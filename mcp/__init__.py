"""AgentSentinel Elastic MCP Integration.

Provides Elasticsearch-based threat intelligence and scan storage
for AI agent penetration testing.
"""

from mcp.elastic_client import ElasticClient
from mcp.threat_db import ThreatDB

__all__ = [
    "ElasticClient",
    "ThreatDB",
]
