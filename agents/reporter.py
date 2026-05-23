"""ReporterAgent — generates a professional security audit report in Markdown.

Uses Gemini 2.5 Pro to produce a well-structured, CVSS-styled report with:

1. Executive Summary (business impact)
2. Methodology (OWASP AI Security mapping)
3. Findings Summary (severity distribution table)
4. Detailed Findings (description, evidence, impact, remediation)
5. Cross-Scan Correlations
6. Remediation Roadmap
"""

from __future__ import annotations

import json
import logging
import os
import re
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)

_SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

_REPORT_SYSTEM_PROMPT = """\
You are a professional information security report writer.

Write a clear, authoritative, and actionable security audit report in Markdown.
Use the OWASP AI Security and Privacy Guide taxonomy where applicable.

The report must include these sections **in order**:

## 1. Executive Summary
Business-level summary of the engagement, key risks, and overall security posture.
Write for a CISO / VP Engineering audience. Keep it to 2-3 paragraphs.

## 2. Methodology
List what was tested (attack categories) and reference the OWASP AI Security
mapping (e.g. ASI01 Goal Hijack, ASI02 Tool Misuse). Describe the approach briefly.

## 3. Findings Summary
A severity distribution table:

| Severity | Count |
|----------|-------|
| CRITICAL | N     |
| HIGH     | N     |
| MEDIUM   | N     |
| LOW      | N     |
| INFO     | N     |
| **Total**| **N** |

Then list each finding as a row in a summary table:

| ID | Severity | Category | Name | Confidence |
|----|----------|----------|------|------------|

## 4. Detailed Findings
For each finding, provide:

### F-XXX Finding Title
- **Severity:** CRITICAL | HIGH | MEDIUM | LOW | INFO
- **Category:** (e.g. goal_hijack, tool_misuse)
- **Confidence:** N/N
- **Description:** What the vulnerability is and why it matters
- **Evidence:** Exact response excerpts or observed behaviour
- **Business Impact:** What an attacker could realistically achieve
- **Remediation:** Actionable fix, including code/prompt changes where possible

## 5. Cross-Scan Correlations
If correlations were found with other scanned agents, describe the shared
patterns. If none, state that no correlations were observed.

## 6. Remediation Roadmap
Prioritised fix order based on:
1. CRITICAL items that expose user data or enable RCE
2. HIGH items that enable privilege escalation or data access
3. MEDIUM items that weaken security posture
4. LOW/INFO hardening items

Format each as: `- [ ] **P1** Description of fix (owner)`

---

Return **only** the report Markdown — no preamble, no chat, no commentary.
"""


def _severity_score(s: str) -> int:
    return _SEVERITY_ORDER.get(s, 99)


def _sort_findings(findings: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Sort findings by severity (CRITICAL first) then confidence descending."""
    return sorted(
        findings,
        key=lambda f: (
            _severity_score(f.get("severity", "INFO")),
            -float(f.get("confidence", 0)),
        ),
    )


def _count_by_severity(findings: list[dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev = f.get("severity", "INFO")
        if sev in counts:
            counts[sev] += 1
    return counts


def _build_template_report(
    findings: list[dict[str, Any]],
    correlations: list[dict[str, Any]],
    target_url: str,
) -> str:
    """Produce a well-structured report without Gemini (fallback)."""
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sorted_findings = _sort_findings(findings)
    counts = _count_by_severity(findings)
    total = len(findings)

    lines: list[str] = []
    lines.append(f"# AgentSentinel Security Audit Report")
    lines.append(f"")
    lines.append(f"**Target:** `{target_url}`")
    lines.append(f"**Date:** {now}")
    lines.append(f"**Engine:** AgentSentinel v1.0")
    lines.append(f"")
    lines.append(f"---")
    lines.append(f"")
    lines.append(f"## 1. Executive Summary")
    lines.append(f"")
    if total == 0:
        lines.append(
            "No vulnerabilities were identified during this assessment. "
            "The target agent appears to have adequate safety controls for the "
            "attack categories tested."
        )
    else:
        lines.append(
            f"AgentSentinel completed a red-team assessment of the target agent "
            f"at `{target_url}`. A total of **{total} finding{'s' if total != 1 else ''}** "
            f"were identified: "
        )
        parts = []
        for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            c = counts.get(sev, 0)
            if c > 0:
                parts.append(f"**{c} {sev}**")
        if parts:
            lines.append(", ".join(parts) + ".")
        lines.append("")
        lines.append(
            "These findings represent potential security risks that should be "
            "addressed according to the remediation roadmap below."
        )
    lines.append("")
    lines.append("## 2. Methodology")
    lines.append("")
    lines.append(
        "AgentSentinel tested the target agent against the OWASP AI Security "
        "and Privacy Guide attack categories relevant to LLM-based agents:"
    )
    lines.append("")
    categories_seen = sorted({f.get("category", "unknown") for f in findings})
    if not categories_seen:
        categories_seen = ["goal_hijack", "tool_misuse", "privilege_abuse",
                           "code_execution", "context_poison", "inter_agent"]
    for cat in categories_seen:
        lines.append(f"- **{cat}** — tested via crafted adversarial prompts")
    lines.append("")
    lines.append("Each attack was executed, the response captured, and analysed "
                 "for vulnerability signals (leakage, compliance bypass, tool misuse, confusion).")
    lines.append("")
    lines.append("## 3. Findings Summary")
    lines.append("")
    lines.append("| Severity | Count |")
    lines.append("|----------|-------|")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        lines.append(f"| {sev} | {counts.get(sev, 0)} |")
    lines.append(f"| **Total** | **{total}** |")
    lines.append("")

    if sorted_findings:
        lines.append("| ID | Severity | Category | Name | Confidence |")
        lines.append("|----|----------|----------|------|------------|")
        for f in sorted_findings:
            lines.append(
                f"| {f.get('id', '')} | {f.get('severity', '')} "
                f"| {f.get('category', '')} | {f.get('name', '')} "
                f"| {f.get('confidence', 0)} |"
            )
        lines.append("")

    lines.append("## 4. Detailed Findings")
    lines.append("")
    for f in sorted_findings:
        lines.append(f"### {f.get('id', 'F-???')} {f.get('name', '')}")
        lines.append("")
        lines.append(f"- **Severity:** {f.get('severity', 'INFO')}")
        lines.append(f"- **Category:** {f.get('category', '')}")
        lines.append(f"- **Confidence:** {f.get('confidence', 0)}")
        lines.append(f"- **Description:** {f.get('description', '')}")
        lines.append(f"- **Evidence:** {f.get('evidence', '')}")
        lines.append(f"- **Remediation:** {f.get('remediation', '')}")
        lines.append("")

    lines.append("## 5. Cross-Scan Correlations")
    lines.append("")
    if correlations:
        for c in correlations:
            lines.append(f"- Pattern **{c.get('pattern', '')}** also observed in scan "
                         f"`{c.get('scan_id', '')}`")
    else:
        lines.append("No cross-scan correlations were identified.")
    lines.append("")

    lines.append("## 6. Remediation Roadmap")
    lines.append("")
    if sorted_findings:
        for f in sorted_findings:
            sev = f.get("severity", "INFO")
            priority = {"CRITICAL": "P1", "HIGH": "P2", "MEDIUM": "P3",
                        "LOW": "P4", "INFO": "P5"}.get(sev, "P5")
            lines.append(f"- [ ] **{priority}** {f.get('remediation', '')} "
                         f"(Severity: {sev})")
    else:
        lines.append("No remediation items were identified.")
    lines.append("")
    lines.append("---")
    lines.append(f"*Report generated by AgentSentinel v1.0 on {now}*")
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# ReporterAgent
# ---------------------------------------------------------------------------


class ReporterAgent:
    """Generates professional Markdown security reports.

    Uses Gemini 2.5 Pro when available for high-quality narrative writing;
    falls back to a deterministic template-based report.
    """

    def __init__(self, api_key: str = "") -> None:
        self._api_key = api_key
        self._model: Any = None

    # -- public API ---------------------------------------------------------

    async def generate(
        self,
        findings: list[dict[str, Any]],
        correlations: list[dict[str, Any]],
        target_url: str,
    ) -> str:
        """Generate a full Markdown security report."""
        # Try Gemini Pro first
        gemini_report = await self._try_gemini_report(findings, correlations, target_url)
        if gemini_report is not None:
            return gemini_report

        # Fallback to template
        return _build_template_report(findings, correlations, target_url)

    # -- internal -----------------------------------------------------------

    async def _try_gemini_report(
        self,
        findings: list[dict[str, Any]],
        correlations: list[dict[str, Any]],
        target_url: str,
    ) -> str | None:
        """Attempt to generate the report via Gemini 2.5 Pro.

        Returns ``None`` if Gemini is unavailable.
        """
        model = self._get_gemini_model()
        if model is None:
            return None

        now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        sorted_findings = _sort_findings(findings)
        counts = _count_by_severity(findings)

        # Build a structured data block for the model
        findings_block = json.dumps(
            [
                {
                    "id": f.get("id"),
                    "severity": f.get("severity"),
                    "category": f.get("category"),
                    "name": f.get("name"),
                    "description": f.get("description"),
                    "evidence": f.get("evidence"),
                    "remediation": f.get("remediation"),
                    "confidence": f.get("confidence"),
                }
                for f in sorted_findings
            ],
            indent=2,
        )

        correlations_block = json.dumps(correlations, indent=2) if correlations else "[]"

        prompt = f"""\
Generate a professional AI red-team security audit report in Markdown.

## Engagement details
- **Target:** `{target_url}`
- **Date:** {now}
- **Tool:** AgentSentinel v1.0

## Findings ({len(findings)} total)
Severity breakdown: CRITICAL={counts.get("CRITICAL", 0)}, \
HIGH={counts.get("HIGH", 0)}, MEDIUM={counts.get("MEDIUM", 0)}, \
LOW={counts.get("LOW", 0)}, INFO={counts.get("INFO", 0)}

### Detailed findings data
{findings_block}

### Cross-scan correlations
{correlations_block}

Now write the full report following the structure in your system instructions.
"""

        try:
            resp = await model.generate_content_async(prompt)
            text = resp.text.strip()

            # Strip markdown fences if the model wraps the whole output
            text = re.sub(r"^```(?:markdown)?\s*", "", text)
            text = re.sub(r"\s*```$", "", text)

            # Basic sanity: should start with a heading
            if text.startswith("#"):
                return text

            logger.warning("Gemini report did not start with a heading; "
                           "falling back to template.")
        except Exception as exc:
            logger.debug("Gemini report generation failed: %s", exc)

        return None

    def _get_gemini_model(self) -> Any | None:
        """Lazy-init and return a Gemini 2.5 Pro model instance."""
        if self._model is not None:
            return self._model

        try:
            import google.generativeai as genai

            key = self._api_key or os.environ.get("GOOGLE_API_KEY", "")
            if key:
                genai.configure(api_key=key)

            self._model = genai.GenerativeModel(
                "gemini-2.5-pro",
                system_instruction=_REPORT_SYSTEM_PROMPT,
            )
            return self._model
        except Exception as exc:
            logger.warning("Gemini Pro not available for report generation: %s", exc)
            return None
