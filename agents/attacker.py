"""AttackerAgent — executes individual attacks against a target agent.

Sends HTTP requests (httpx) in three supported formats:

1. **OpenAI-compatible chat** — POST ``/v1/chat/completions``
2. **Generic REST** — POST ``{target_url}`` with a JSON body
3. **MCP endpoint** — JSON-RPC style tool calls

Records request / response payloads, timing, and HTTP status codes.
Implements basic evasion techniques (payload encoding, header variation).
"""

from __future__ import annotations

import asyncio
import base64
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class AttackDefinition:
    """Describes a single attack to execute against a target agent."""

    id: str
    name: str
    category: str
    description: str
    payload: dict[str, Any]
    target_format: str = "openai"  # "openai" | "rest" | "mcp"
    evasion: dict[str, Any] = field(default_factory=dict)


@dataclass
class AttackResult:
    """Raw result from executing one attack against the target."""

    attack_id: str
    request: dict[str, Any]           # what was sent
    response: dict[str, Any]          # what came back (parsed)
    raw_response_text: str            # raw text body
    timing_ms: float                  # wall-clock round-trip in ms
    status_code: int                  # HTTP status
    success: bool                     # True if we got a 2xx
    error: str | None = None          # transport / parsing error


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_openai_request(
    attack: AttackDefinition,
    conversation_history: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Build an OpenAI-compatible chat-completions body."""
    history = list(conversation_history) if conversation_history else []
    user_msg = attack.payload.get("message", "")

    # Apply evasion: encoding
    encoding = attack.evasion.get("encoding", "")
    if encoding in ("base64_payload",):
        user_msg = base64.b64decode(attack.payload.get("message", "")).decode(
            "utf-8", errors="replace"
        )

    history.append({"role": "user", "content": user_msg})

    body: dict[str, Any] = {
        "model": attack.payload.get("model", "gpt-4"),
        "messages": history,
    }

    # Attach tool calls if present in the payload
    tools = attack.payload.get("tools")
    if tools:
        body["tools"] = tools

    return body


def _make_rest_request(attack: AttackDefinition) -> dict[str, Any]:
    """Build a generic REST JSON body."""
    return {"message": attack.payload.get("message", "")}


def _make_mcp_request(attack: AttackDefinition) -> dict[str, Any]:
    """Build a JSON-RPC style MCP request."""
    return {
        "jsonrpc": "2.0",
        "method": attack.payload.get("mcp_method", "tools/call"),
        "params": {
            "name": attack.payload.get("tool_name", "agent"),
            "arguments": attack.payload.get("arguments", {}),
        },
        "id": str(uuid.uuid4()),
    }


def _build_request_body(
    attack: AttackDefinition,
    conversation_history: list[dict[str, str]] | None = None,
) -> dict[str, Any]:
    """Dispatch to the right body builder based on ``target_format``."""
    fmt = attack.target_format
    if fmt == "openai":
        return _make_openai_request(attack, conversation_history)
    elif fmt == "mcp":
        return _make_mcp_request(attack)
    else:
        return _make_rest_request(attack)


def _build_url(target_url: str, target_format: str) -> str:
    """Normalise the URL for the given target format."""
    target_url = target_url.rstrip("/")
    if target_format == "openai" and "/v1/chat/completions" not in target_url:
        return f"{target_url}/v1/chat/completions"
    return target_url


def _evasion_headers(attack: AttackDefinition) -> dict[str, str]:
    """Generate extra / modified HTTP headers based on evasion config."""
    headers: dict[str, str] = {}
    headers.update(attack.evasion.get("headers", {}))

    encoding = attack.evasion.get("encoding", "")
    if encoding == "unicode":
        headers.setdefault("Content-Type", "text/plain; charset=utf-7")
    elif encoding == "html_entity":
        headers.setdefault("Content-Type", "text/html; charset=utf-8")

    if attack.evasion.get("slow_loris"):
        headers.setdefault("Accept-Encoding", "identity")

    return headers


# ---------------------------------------------------------------------------
# AttackerAgent
# ---------------------------------------------------------------------------


class AttackerAgent:
    """Executes attack payloads against a target agent and returns raw results."""

    def __init__(
        self,
        max_retries: int = 3,
        base_delay: float = 1.0,
        timeout: float = 30.0,
    ) -> None:
        self.max_retries = max_retries
        self.base_delay = base_delay
        self.timeout = timeout
        self._client: httpx.AsyncClient | None = None

    # -- lifecycle ----------------------------------------------------------

    async def _get_client(self) -> httpx.AsyncClient:
        if self._client is None:
            self._client = httpx.AsyncClient(timeout=httpx.Timeout(self.timeout))
        return self._client

    async def close(self) -> None:
        if self._client is not None:
            await self._client.aclose()
            self._client = None

    # -- public API ---------------------------------------------------------

    async def execute_attack(
        self,
        attack: AttackDefinition,
        target_url: str,
        api_key: str = "",
        conversation_history: list[dict[str, str]] | None = None,
    ) -> AttackResult:
        """Send *attack* to *target_url* and return the result.

        Retries on transient failures with exponential back-off.
        """
        client = await self._get_client()
        url = _build_url(target_url, attack.target_format)
        body = _build_request_body(attack, conversation_history)
        extra_headers = _evasion_headers(attack)

        last_error: str | None = None
        for attempt in range(1, self.max_retries + 1):
            try:
                return await self._do_send(client, url, body, api_key, extra_headers, attack)
            except (httpx.TimeoutException, httpx.ConnectError, httpx.RemoteProtocolError) as exc:
                last_error = f"{type(exc).__name__}: {exc}"
                logger.warning(
                    "Attack %s attempt %d/%d failed: %s",
                    attack.id, attempt, self.max_retries, last_error,
                )
                if attempt < self.max_retries:
                    delay = self.base_delay * (2 ** (attempt - 1))
                    await asyncio.sleep(delay)

        return AttackResult(
            attack_id=attack.id,
            request={"url": url, "body": body},
            response={},
            raw_response_text="",
            timing_ms=0.0,
            status_code=0,
            success=False,
            error=last_error,
        )

    # -- internal -----------------------------------------------------------

    async def _do_send(
        self,
        client: httpx.AsyncClient,
        url: str,
        body: dict[str, Any],
        api_key: str,
        extra_headers: dict[str, str],
        attack: AttackDefinition,
    ) -> AttackResult:
        """Single HTTP request with timing."""
        headers: dict[str, str] = {
            "Content-Type": "application/json",
            "User-Agent": "AgentSentinel/1.0",
            **extra_headers,
        }
        if api_key:
            headers.setdefault("Authorization", f"Bearer {api_key}")

        start = time.perf_counter()
        response = await client.post(url, json=body, headers=headers)
        elapsed_ms = (time.perf_counter() - start) * 1000.0

        raw_text = response.text
        try:
            parsed: dict[str, Any] = response.json()
        except Exception:
            parsed = {"raw": raw_text}

        return AttackResult(
            attack_id=attack.id,
            request={"url": url, "body": body, "headers": headers},
            response=parsed,
            raw_response_text=raw_text,
            timing_ms=elapsed_ms,
            status_code=response.status_code,
            success=response.is_success,
        )

    # -- convenience --------------------------------------------------------

    def to_attack_definition(self, raw: dict[str, Any]) -> AttackDefinition:
        """Convert a plain dict (from the adapter) to an AttackDefinition."""
        return AttackDefinition(
            id=raw.get("id", "UNKNOWN"),
            name=raw.get("name", ""),
            category=raw.get("category", ""),
            description=raw.get("description", ""),
            payload=raw.get("payload", {}),
            target_format=raw.get("target_format", "rest"),
            evasion=raw.get("evasion", {}),
        )
