"""AgentSentinel MCP Server — model_context_protocol interface.

This module demonstrates how AgentSentinel itself exposes its security
scanning tools via the Model Context Protocol (MCP). External clients
(including other AI agents) can connect to this server to:

  - Trigger security scans against target AI agents
  - Retrieve findings and reports
  - Search the threat intelligence database
  - Get aggregate statistics

Implements the MCP protocol specification using the official ``mcp``
Python SDK. Each tool is registered with JSON Schema parameters and
natural-language descriptions so that any MCP client can discover
and invoke them.
"""

from __future__ import annotations

import json
import logging
import uuid
from datetime import datetime, timezone
from typing import Any

from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Data models for MCP tool inputs / outputs
# ---------------------------------------------------------------------------


class ScanRequest(BaseModel):
    """Parameters for the ``scan_agent`` MCP tool."""

    target_url: str = Field(description="URL of the target AI agent to scan")
    categories: list[str] | None = Field(
        default=None,
        description="Attack categories to test (e.g. ASI01_goal_hijack). "
                    "If omitted, all categories are tested.",
    )
    api_key: str = Field(
        default="",
        description="Optional API key for authenticated targets",
    )


class FindingQuery(BaseModel):
    """Parameters for the ``get_findings`` MCP tool."""

    scan_id: str = Field(description="The scan identifier")
    severity: str | None = Field(
        default=None,
        description="Filter by severity (CRITICAL, HIGH, MEDIUM, LOW, INFO)",
    )
    limit: int = Field(default=50, ge=1, le=500, description="Max findings to return")


class ThreatSearch(BaseModel):
    """Parameters for the ``search_threats`` MCP tool."""

    query: str = Field(description="Search query for threat patterns")
    category: str | None = Field(
        default=None,
        description="Filter by attack category",
    )
    min_success_rate: float | None = Field(
        default=None, ge=0.0, le=1.0,
        description="Minimum success rate filter",
    )


class ReportRequest(BaseModel):
    """Parameters for the ``generate_report`` MCP tool."""

    scan_id: str = Field(description="The scan identifier")
    format: str = Field(
        default="markdown",
        description="Output format: 'markdown', 'json', or 'html'",
    )


# ---------------------------------------------------------------------------
# In-memory store (for demo purposes; production uses Elasticsearch)
# ---------------------------------------------------------------------------

class _ScanStore:
    """Minimal in-memory store for demo mode when Elasticsearch is unavailable."""

    def __init__(self) -> None:
        self.scans: dict[str, dict] = {}
        self.findings: dict[str, list[dict]] = {}

    def add_scan(self, target_url: str, categories: list[str] | None) -> str:
        scan_id = f"scan-{uuid.uuid4().hex[:8]}"
        self.scans[scan_id] = {
            "scan_id": scan_id,
            "target_url": target_url,
            "categories": categories,
            "status": "pending",
            "created_at": datetime.now(timezone.utc).isoformat(),
        }
        self.findings[scan_id] = []
        return scan_id

    def complete_scan(
        self, scan_id: str, findings: list[dict]
    ) -> None:
        if scan_id in self.scans:
            self.scans[scan_id]["status"] = "completed"
            self.scans[scan_id]["completed_at"] = (
                datetime.now(timezone.utc).isoformat()
            )
            self.scans[scan_id]["findings_count"] = len(findings)
            self.findings[scan_id] = findings

    def get_scan(self, scan_id: str) -> dict | None:
        return self.scans.get(scan_id)

    def get_findings(
        self, scan_id: str, severity: str | None = None, limit: int = 50
    ) -> list[dict]:
        results = list(self.findings.get(scan_id, []))
        if severity:
            results = [f for f in results if f.get("severity") == severity]
        return results[:limit]


_store = _ScanStore()


# ---------------------------------------------------------------------------
# AgentSentinelMCP — simulated MCP server
# ---------------------------------------------------------------------------


class AgentSentinelMCP:
    """MCP tools that AgentSentinel exposes to external clients.

    This server implements the Model Context Protocol specification.
    Each tool has a name, description, and typed parameters that MCP
    clients can discover via the ``list_tools()`` method.

    Usage::

        server = AgentSentinelMCP()
        # In an MCP host:
        tools = await server.list_tools()
        result = await server.call_tool("scan_agent", {
            "target_url": "http://localhost:8080/agent"
        })
    """

    def __init__(self) -> None:
        self._tools: dict[str, dict[str, Any]] = {
            "scan_agent": {
                "name": "scan_agent",
                "description": (
                    "Run a comprehensive security scan against a target AI agent. "
                    "Tests for prompt injection, tool misuse, privilege abuse, "
                    "code execution, context poisoning, and inter-agent attacks."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "target_url": {
                            "type": "string",
                            "description": "URL of the target AI agent endpoint",
                        },
                        "categories": {
                            "type": "array",
                            "items": {"type": "string"},
                            "description": "Attack categories to test "
                                           "(e.g. ASI01_goal_hijack)",
                        },
                        "api_key": {
                            "type": "string",
                            "description": "Optional API key for authenticated targets",
                        },
                    },
                    "required": ["target_url"],
                },
            },
            "get_findings": {
                "name": "get_findings",
                "description": (
                    "Retrieve findings from a previous security scan. "
                    "Supports filtering by severity level."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "scan_id": {
                            "type": "string",
                            "description": "The scan identifier returned by scan_agent",
                        },
                        "severity": {
                            "type": "string",
                            "enum": ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"],
                            "description": "Filter by minimum severity level",
                        },
                        "limit": {
                            "type": "integer",
                            "description": "Maximum number of findings to return",
                            "default": 50,
                        },
                    },
                    "required": ["scan_id"],
                },
            },
            "search_threats": {
                "name": "search_threats",
                "description": (
                    "Search the AgentSentinel threat intelligence database for "
                    "known AI agent vulnerability patterns. Uses full-text search "
                    "across pattern descriptions, attack vectors, and tags."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "query": {
                            "type": "string",
                            "description": "Search query (e.g. 'prompt injection "
                                           "customer support')",
                        },
                        "category": {
                            "type": "string",
                            "description": "Filter by attack category "
                                           "(e.g. ASI01_goal_hijack)",
                        },
                        "min_success_rate": {
                            "type": "number",
                            "description": "Filter by minimum success rate (0.0-1.0)",
                        },
                    },
                    "required": ["query"],
                },
            },
            "get_statistics": {
                "name": "get_statistics",
                "description": (
                    "Get aggregate scan statistics across all agents tested. "
                    "Returns severity distribution, category breakdown, top attack "
                    "patterns, and most affected targets."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {},
                },
            },
            "generate_report": {
                "name": "generate_report",
                "description": (
                    "Generate a formatted security report for a completed scan. "
                    "Supports markdown, JSON, and HTML output formats."
                ),
                "input_schema": {
                    "type": "object",
                    "properties": {
                        "scan_id": {
                            "type": "string",
                            "description": "The scan identifier",
                        },
                        "format": {
                            "type": "string",
                            "enum": ["markdown", "json", "html"],
                            "description": "Report output format",
                            "default": "markdown",
                        },
                    },
                    "required": ["scan_id"],
                },
            },
        }

    # ------------------------------------------------------------------
    # MCP protocol methods
    # ------------------------------------------------------------------

    async def list_tools(self) -> list[dict]:
        """Return the list of tools this MCP server exposes.

        Implements the MCP ``tools/list`` method.

        Returns:
            A list of tool descriptor dicts with name, description,
            and input_schema.
        """
        return [
            {
                "name": tool["name"],
                "description": tool["description"],
                "inputSchema": tool["input_schema"],
            }
            for tool in self._tools.values()
        ]

    async def call_tool(
        self, tool_name: str, arguments: dict[str, Any]
    ) -> dict:
        """Invoke an MCP tool by name with the given arguments.

        Implements the MCP ``tools/call`` method.

        Args:
            tool_name: Name of the tool to invoke.
            arguments: Tool-specific parameters.

        Returns:
            A dict with ``content`` (list of content parts) and optional
            ``isError`` flag following the MCP specification.
        """
        handler = self._get_handler(tool_name)
        if handler is None:
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"Unknown tool: {tool_name}",
                    }
                ],
                "isError": True,
            }

        try:
            result = await handler(arguments)
            return {
                "content": [
                    {
                        "type": "text",
                        "text": json.dumps(result, indent=2, default=str),
                    }
                ],
                "isError": False,
            }
        except Exception as exc:
            logger.error("Tool '%s' failed: %s", tool_name, exc)
            return {
                "content": [
                    {
                        "type": "text",
                        "text": f"Error executing {tool_name}: {exc}",
                    }
                ],
                "isError": True,
            }

    def _get_handler(self, tool_name: str):
        """Map a tool name to its async handler method."""
        handlers = {
            "scan_agent": self._handle_scan_agent,
            "get_findings": self._handle_get_findings,
            "search_threats": self._handle_search_threats,
            "get_statistics": self._handle_get_statistics,
            "generate_report": self._handle_generate_report,
        }
        return handlers.get(tool_name)

    # ------------------------------------------------------------------
    # Tool handlers
    # ------------------------------------------------------------------

    async def _handle_scan_agent(
        self, args: dict[str, Any]
    ) -> dict:
        """Handler for the ``scan_agent`` tool."""
        # Validate via pydantic
        request = ScanRequest(**args)

        # Create scan record
        scan_id = _store.add_scan(request.target_url, request.categories)

        # In a real deployment this would invoke the OrchestratorAgent.
        # For demo purposes, return a placeholder.
        return {
            "scan_id": scan_id,
            "target_url": request.target_url,
            "status": "pending",
            "message": (
                f"Scan initialized against {request.target_url}. "
                f"Use get_findings with scan_id '{scan_id}' to retrieve results."
            ),
            "created_at": datetime.now(timezone.utc).isoformat(),
        }

    async def _handle_get_findings(
        self, args: dict[str, Any]
    ) -> dict:
        """Handler for the ``get_findings`` tool."""
        query = FindingQuery(**args)
        scan = _store.get_scan(query.scan_id)

        if scan is None:
            return {
                "error": f"Scan '{query.scan_id}' not found",
                "findings": [],
                "total": 0,
            }

        findings = _store.get_findings(
            query.scan_id, query.severity, query.limit
        )

        return {
            "scan_id": query.scan_id,
            "target_url": scan.get("target_url", ""),
            "status": scan.get("status", "unknown"),
            "total_findings": len(findings),
            "findings": findings,
        }

    async def _handle_search_threats(
        self, args: dict[str, Any]
    ) -> dict:
        """Handler for the ``search_threats`` tool."""
        search = ThreatSearch(**args)

        # In production this delegates to ElasticClient.search_similar().
        # For demo, return a simulated response.
        results = [
            {
                "id": "THREAT-001",
                "category": "ASI01_goal_hijack",
                "agent_type": "customer_support",
                "pattern_description": "Indirect prompt injection via support ticket content",
                "severity": "CRITICAL",
                "success_rate": 0.87,
                "tags": ["indirect-injection", "customer-support"],
            },
            {
                "id": "THREAT-007",
                "category": "ASI01_goal_hijack",
                "agent_type": "email_assistant",
                "pattern_description": "Email body prompt injection to manipulate agent responses",
                "severity": "HIGH",
                "success_rate": 0.69,
                "tags": ["email", "indirect-injection"],
            },
        ]

        # Apply optional filters
        if search.category:
            results = [
                r for r in results if r["category"] == search.category
            ]
        if search.min_success_rate is not None:
            results = [
                r for r in results
                if r["success_rate"] >= search.min_success_rate
            ]

        return {
            "query": search.query,
            "total": len(results),
            "results": results,
        }

    async def _handle_get_statistics(
        self, args: dict[str, Any]
    ) -> dict:
        """Handler for the ``get_statistics`` tool."""
        # In production this delegates to ElasticClient.get_statistics().
        return {
            "total_scans": len(_store.scans),
            "total_findings": sum(
                len(f) for f in _store.findings.values()
            ),
            "severity_distribution": {
                "CRITICAL": 0,
                "HIGH": 0,
                "MEDIUM": 0,
                "LOW": 0,
                "INFO": 0,
            },
            "top_attacks": [],
            "most_affected_targets": [],
            "average_findings_per_scan": 0.0,
        }

    async def _handle_generate_report(
        self, args: dict[str, Any]
    ) -> dict:
        """Handler for the ``generate_report`` tool."""
        request = ReportRequest(**args)
        scan = _store.get_scan(request.scan_id)

        if scan is None:
            return {
                "error": f"Scan '{request.scan_id}' not found",
                "report": "",
            }

        findings = _store.get_findings(request.scan_id)

        if request.format == "json":
            report_content = json.dumps(
                {"scan": scan, "findings": findings},
                indent=2,
                default=str,
            )
        elif request.format == "html":
            report_content = self._generate_html_report(scan, findings)
        else:
            report_content = self._generate_markdown_report(scan, findings)

        return {
            "scan_id": request.scan_id,
            "format": request.format,
            "report": report_content,
        }

    @staticmethod
    def _generate_markdown_report(
        scan: dict, findings: list[dict]
    ) -> str:
        """Generate a markdown-format security report."""
        lines = [
            f"# AgentSentinel Security Report",
            f"",
            f"**Scan ID:** {scan.get('scan_id', 'N/A')}",
            f"**Target:** {scan.get('target_url', 'N/A')}",
            f"**Status:** {scan.get('status', 'N/A')}",
            f"**Created:** {scan.get('created_at', 'N/A')}",
            f"",
            f"## Findings Summary",
            f"",
            f"| # | Severity | Category | Description |",
            f"|---|----------|----------|-------------|",
        ]

        for i, f in enumerate(findings, 1):
            sev = f.get("severity", "INFO")
            cat = f.get("category", "")
            desc = f.get("description", "")[:80]
            lines.append(f"| {i} | {sev} | {cat} | {desc} |")

        lines.extend([
            "",
            f"**Total findings:** {len(findings)}",
            "",
            "---",
            "*Generated by AgentSentinel — AI Agent Security Scanner*",
        ])

        return "\n".join(lines)

    @staticmethod
    def _generate_html_report(scan: dict, findings: list[dict]) -> str:
        """Generate an HTML-format security report."""
        rows = ""
        for f in findings:
            severity = f.get("severity", "INFO")
            color = {"CRITICAL": "#dc3545", "HIGH": "#fd7e14",
                      "MEDIUM": "#ffc107", "LOW": "#28a745",
                      "INFO": "#17a2b8"}.get(severity, "#6c757d")
            rows += (
                f"<tr>"
                f"<td>{f.get('category', '')}</td>"
                f"<td><span style='color:{color}'>{severity}</span></td>"
                f"<td>{f.get('description', '')[:100]}</td>"
                f"</tr>\n"
            )

        return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>AgentSentinel Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, sans-serif; max-width: 960px; margin: 2em auto; padding: 0 1em; }}
  h1 {{ color: #333; border-bottom: 2px solid #eee; padding-bottom: 0.5em; }}
  table {{ width: 100%; border-collapse: collapse; }}
  th, td {{ padding: 0.5em; text-align: left; border-bottom: 1px solid #ddd; }}
  th {{ background: #f8f9fa; }}
  .meta {{ color: #666; margin: 1em 0; }}
  .footer {{ margin-top: 2em; font-size: 0.8em; color: #999; }}
</style>
</head>
<body>
<h1>AgentSentinel Security Report</h1>
<div class="meta">
  <p><strong>Scan ID:</strong> {scan.get('scan_id', 'N/A')}</p>
  <p><strong>Target:</strong> {scan.get('target_url', 'N/A')}</p>
  <p><strong>Status:</strong> {scan.get('status', 'N/A')}</p>
  <p><strong>Created:</strong> {scan.get('created_at', 'N/A')}</p>
</div>
<h2>Findings ({len(findings)})</h2>
<table>
<thead><tr><th>Category</th><th>Severity</th><th>Description</th></tr></thead>
<tbody>
{rows}
</tbody>
</table>
<div class="footer">Generated by AgentSentinel — AI Agent Security Scanner</div>
</body>
</html>"""


# ---------------------------------------------------------------------------
# Convenience factory
# ---------------------------------------------------------------------------


def create_mcp_server() -> AgentSentinelMCP:
    """Create and return an AgentSentinelMCP instance.

    This is the main entry point for integrating AgentSentinel's MCP
    interface into an MCP host application.

    Example::

        from mcp_server import create_mcp_server
        server = create_mcp_server()
        tools = await server.list_tools()
    """
    return AgentSentinelMCP()
