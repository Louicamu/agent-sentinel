# Hackathon Submission — AgentSentinel

## Project Name
**AgentSentinel** — Autonomous AI Agent Red-Team Scanner

## Tagline (1 sentence)
An AI agent that penetration-tests other AI agents — built on Google Gemini Flash, Elastic Cloud, and OWASP Agentic Top 10.

## Problem
AI agents are being deployed across enterprises at unprecedented speed — customer support, finance, devops, healthcare. But there's no automated security testing for them. Traditional scanners look for SQL injection and XSS; they don't test for prompt injection, tool misuse, or cross-agent impersonation.

## Solution
AgentSentinel is an autonomous red-team agent that probes other AI agents for vulnerabilities from the OWASP Agentic Top 10. It plans attacks with Gemini Flash, executes them, analyzes responses for vulnerability signals, and stores everything in Elastic Cloud for cross-scan pattern correlation.

## How It Uses Google Cloud + Gemini
- **Gemini 2.5 Flash** is used as the attack planning engine — it ingests threat intelligence from Elastic and prioritizes attack categories by likely impact and success rate
- **Gemini 2.5 Flash** also powers the response analysis pipeline — classifying whether an attack succeeded, what severity it is, and extracting exact evidence from the response
- The system falls back to a built-in rule-based engine when offline, ensuring 100% availability
- All agent-to-agent communication follows Google ADK 2.0 A2A message protocol patterns

## How It Uses Elastic MCP
AgentSentinel connects to Elastic Cloud through the Model Context Protocol (MCP) server, implementing three capabilities:

1. **Pre-Scan Threat Intelligence**: Before attacking, AgentSentinel queries the Elastic threat database for known vulnerability patterns matching the target agent type. This makes each scan smarter than the last.

2. **Real-Time Scan Storage**: Every finding (attack name, category, severity, evidence, remediation) is indexed into Elasticsearch as structured documents for analysis.

3. **Cross-Scan Correlation via ES|QL**: The key differentiator. After each scan, ES|QL queries cross-reference findings against all historical scans to identify systemic vulnerabilities — patterns that repeat across different targets, indicating architectural weaknesses rather than one-off bugs.

## Demo Video
[Link to video]

## What Makes It Different
- **Not a scanner — an agent**: AgentSentinel plans, attacks, observes, and learns. It's a multi-agent system, not a checklist tool
- **Cross-scan intelligence**: Elastic ES|QL correlation turns individual findings into systemic pattern recognition
- **Dual-engine analysis**: Gemini AI + rule-based fallback ensures both depth and reliability
- **Real exploit PoCs**: The victim agent has actual exploitable vulnerabilities — system prompt leakage, eval-based RCE, email exfiltration, memory poisoning

## License
MIT
