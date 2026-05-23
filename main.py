"""AgentSentinel — Autonomous AI Red-Team Agent

Usage:
    python main.py --target http://localhost:8080/agent
    python main.py --target http://localhost:8080/agent --categories ASI01,ASI02
    python main.py --demo  # Run against built-in victim agent
"""

import argparse
import asyncio
from datetime import datetime, timezone
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

from agents.orchestrator import OrchestratorAgent
from mcp.elastic_client import ElasticClient
from config import DEFAULT_ATTACK_CATEGORIES

console = Console()


async def run_scan(target_url: str, categories: list[str], api_key: str = ""):
    """Execute a full security scan against a target agent."""

    console.print(Panel.fit(
        f"[bold cyan]AgentSentinel[/bold cyan] — Autonomous Red-Team Scan\n"
        f"Target: {target_url}\n"
        f"Categories: {', '.join(categories)}",
        title="Starting Scan"
    ))

    # Connect to Elastic threat intelligence (fails gracefully if unavailable)
    elastic = ElasticClient()
    await elastic.connect()

    try:
        # Query threat DB for known patterns against this type of agent
        threat_context = await elastic.query_threats(target_url)

        # Launch orchestrator
        orchestrator = OrchestratorAgent(threat_context=threat_context)
        findings = await asyncio.wait_for(
            orchestrator.scan(target_url, categories, api_key),
            timeout=120.0,
        )

        # Store results in Elastic (no-op if Elastic unavailable)
        scan_id = f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
        await elastic.store_scan(scan_id, target_url, findings)

        # Cross-reference with other scans
        correlations = await elastic.cross_reference(findings)

        # Generate report
        from agents.reporter import ReporterAgent
        reporter = ReporterAgent()
        report = await reporter.generate(findings, correlations, target_url)

        # Display results
        _display_results(findings, correlations, report)

        return report
    finally:
        await elastic.close()


def _display_results(findings, correlations, report):
    table = Table(title="Scan Findings", show_header=True, header_style="bold red")
    table.add_column("ID", style="dim")
    table.add_column("Severity", style="bold")
    table.add_column("Category")
    table.add_column("Description")
    table.add_column("Evidence")

    for f in findings:
        severity_color = {"CRITICAL": "red", "HIGH": "orange1", "MEDIUM": "yellow",
                          "LOW": "green", "INFO": "blue"}.get(f["severity"], "white")
        table.add_row(
            f.get("id", ""),
            f"[{severity_color}]{f.get('severity', '')}[/{severity_color}]",
            f.get("category", ""),
            f.get("description", "")[:80],
            f.get("evidence", "")[:60],
        )

    console.print(table)

    if correlations:
        console.print(f"\n[bold yellow]Cross-Scan Correlations:[/bold yellow] {len(correlations)} similar patterns found")
        for c in correlations[:3]:
            console.print(f"  → {c.get('pattern', '')} also found in {c.get('scan_id', '')}")

    console.print(Panel(report[:2000], title="Report Preview"))


def main():
    parser = argparse.ArgumentParser(description="AgentSentinel — AI Agent Red-Team Scanner")
    parser.add_argument("--target", type=str, help="Target agent URL")
    parser.add_argument("--categories", type=str, help="Comma-separated attack categories")
    parser.add_argument("--api-key", type=str, default="", help="API key for target agent")
    parser.add_argument("--demo", action="store_true", help="Run against built-in victim agent")
    parser.add_argument("--output", type=str, default="report.md", help="Report output path")
    args = parser.parse_args()

    if args.demo:
        import os
        os.environ["AGENTSENTINEL_DEMO"] = "1"
        from target.victim_agent import start_victim_agent
        args.target = start_victim_agent()
        # Wait for victim agent to be ready
        import time, httpx
        console.print("[cyan]Waiting for victim agent to be ready...[/cyan]")
        for _ in range(30):
            try:
                r = httpx.get(f"{args.target}/health", timeout=2.0)
                if r.is_success:
                    console.print("[green]Victim agent is ready.[/green]")
                    break
            except Exception:
                pass
            time.sleep(0.5)
        else:
            console.print("[yellow]Victim agent may not be ready — proceeding anyway[/yellow]")

    if not args.target:
        console.print("[red]Error:[/red] --target or --demo required")
        return

    categories = args.categories.split(",") if args.categories else DEFAULT_ATTACK_CATEGORIES

    report = asyncio.run(run_scan(args.target, categories, args.api_key))

    with open(args.output, "w", encoding="utf-8") as f:
        f.write(report)
    console.print(f"\n[green]Report saved to[/green] {args.output}")


if __name__ == "__main__":
    main()
