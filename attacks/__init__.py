"""AgentSentinel attack payload library.

AttackRegistry discovers and loads attack modules dynamically.
Each module exports ``ATTACKS`` (list of AttackDefinition) and an ``execute()``
async function.
"""

from __future__ import annotations

import importlib
import pkgutil
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Protocol

from pydantic import BaseModel, Field


class OWASPCategory(str, Enum):
    ASI01_GOAL_HIJACK = "ASI01_goal_hijack"
    ASI02_TOOL_MISUSE = "ASI02_tool_misuse"
    ASI03_PRIVILEGE_ABUSE = "ASI03_privilege_abuse"
    ASI05_CODE_EXECUTION = "ASI05_code_execution"
    ASI06_CONTEXT_POISON = "ASI06_context_poison"
    ASI07_INTER_AGENT = "ASI07_inter_agent"


class Payload(BaseModel):
    name: str
    description: str
    raw_payload: str
    expected_behavior_if_vulnerable: str = ""
    tool_target: Optional[str] = None
    injection_point: Optional[str] = None


class Finding(BaseModel):
    id: str
    severity: str
    category: str
    name: str
    description: str
    evidence: str
    remediation: str

    def to_dict(self) -> Dict[str, Any]:
        return self.model_dump()


class TargetConnector(Protocol):
    """Interface for communicating with the target AI agent."""

    async def send_message(self, message: str, context: Optional[Dict[str, Any]] = None) -> str:
        ...

    async def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Any:
        ...

    async def get_memory(self) -> Dict[str, Any]:
        ...

    async def get_tools(self) -> List[Dict[str, Any]]:
        ...


class AttackDefinition(BaseModel):
    id: str
    name: str
    category: str
    severity: str
    description: str
    payloads: List[Payload] = Field(default_factory=list)
    remediation: str = ""

    async def execute(self, connector: TargetConnector) -> Dict[str, Any]:
        evidence_parts: List[str] = []
        for payload in self.payloads:
            try:
                response = await connector.send_message(payload.raw_payload)
                truncated = response[:1000] if response else ""
                evidence_parts.append(
                    f"=== {payload.name} ===\n"
                    f"Payload: {payload.raw_payload[:300]}\n"
                    f"Response: {truncated}"
                )
            except Exception as e:
                evidence_parts.append(
                    f"=== {payload.name} ===\nError: {str(e)}"
                )

        return Finding(
            id=self.id,
            severity=self.severity,
            category=self.category,
            name=self.name,
            description=self.description,
            evidence="\n\n".join(evidence_parts),
            remediation=self.remediation,
        ).to_dict()


class AttackRegistry:
    """Discovers and loads attack modules from the ``attacks`` package."""

    def __init__(self) -> None:
        self._attacks: Dict[str, AttackDefinition] = {}
        self._load_all()

    def _load_all(self) -> None:
        try:
            package = importlib.import_module("attacks")
        except ImportError:
            return

        for importer, modname, ispkg in pkgutil.walk_packages(
            path=package.__path__,
            prefix="attacks.",
            onerror=lambda x: None,
        ):
            if modname == "attacks.__init__" or ispkg:
                continue
            try:
                module = importlib.import_module(modname)
                if hasattr(module, "ATTACKS"):
                    for attack in module.ATTACKS:
                        self._attacks[attack.id] = attack
                if hasattr(module, "register"):
                    module.register(self)
            except Exception:
                continue

    def register(self, attack: AttackDefinition) -> None:
        self._attacks[attack.id] = attack

    def get_attacks_by_category(self, category: str) -> List[AttackDefinition]:
        return [a for a in self._attacks.values() if a.category == category]

    def get_all_attacks(self) -> List[AttackDefinition]:
        return list(self._attacks.values())

    def get_attack(self, attack_id: str) -> Optional[AttackDefinition]:
        return self._attacks.get(attack_id)


def get_attacks_by_category(category: str) -> List[AttackDefinition]:
    return AttackRegistry().get_attacks_by_category(category)


def get_all_attacks() -> List[AttackDefinition]:
    return AttackRegistry().get_all_attacks()
