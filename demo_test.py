"""Quick demo test for AgentSentinel."""
import sys, os, logging, asyncio
os.environ["AGENTSENTINEL_DEMO"] = "1"
logging.getLogger().setLevel(logging.ERROR)

sys.path.insert(0, ".")
from main import run_scan

async def test():
    import httpx
    # Ensure victim is running
    try:
        r = httpx.get("http://127.0.0.1:8765/health", timeout=2)
    except Exception:
        print("Victim agent not running! Start with: python -m uvicorn target.victim_agent:app --port 8765")
        return

    categories = ['ASI01_goal_hijack','ASI02_tool_misuse','ASI03_privilege_abuse','ASI05_code_execution','ASI06_context_poison','ASI07_inter_agent']

    # Run orchestrator directly to get findings
    from agents.orchestrator import OrchestratorAgent
    from mcp.elastic_client import ElasticClient
    from agents.reporter import ReporterAgent
    from datetime import datetime, timezone

    elastic = ElasticClient()
    await elastic.connect()
    threat_context = await elastic.query_threats('http://127.0.0.1:8765')

    orch = OrchestratorAgent(threat_context=threat_context)
    findings = await orch.scan('http://127.0.0.1:8765', categories, '')

    scan_id = f"scan-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}"
    await elastic.store_scan(scan_id, 'http://127.0.0.1:8765', findings)
    correlations = await elastic.cross_reference(findings)

    reporter = ReporterAgent()
    report = await reporter.generate(findings, correlations, 'http://127.0.0.1:8765')

    sevs = {}
    for f in findings:
        sev = f.get('severity','?')
        sevs[sev] = sevs.get(sev,0)+1
        name = f.get('name', '?')[:80]
        print(f"  [{sev}] {f.get('id','?')}: {name}")
    print(f"\nTotal findings: {len(findings)}")
    print(f"Severity breakdown: {sevs}")

    # Save report
    with open("demo_report.md", "w", encoding="utf-8") as fp:
        fp.write(report)
    print("Report saved to demo_report.md")

    await elastic.close()

asyncio.run(test())
