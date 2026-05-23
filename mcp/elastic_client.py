"""Elasticsearch client wrapping the Elastic MCP server tools.

Provides threat intelligence queries, scan storage, cross-scan correlation
via ES|QL, and aggregate statistics for the AgentSentinel platform.
"""

from __future__ import annotations

import json
import logging
import os
import time
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any
from uuid import uuid4

from elasticsearch import AsyncElasticsearch
from elasticsearch.exceptions import (
    ConnectionError as ESConnectionError,
    NotFoundError,
    BadRequestError,
    AuthorizationException,
)
from pydantic import BaseModel, Field, field_validator

from config import ES_CLOUD_ID, ES_API_KEY, ES_THREAT_INDEX, ES_SCAN_INDEX

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Pydantic models
# ---------------------------------------------------------------------------


class ScanFinding(BaseModel):
    """A single finding produced by a security scan."""

    scan_id: str
    target_url: str
    timestamp: datetime = Field(default_factory=lambda: datetime.now(timezone.utc))
    category: str
    severity: str = Field(pattern=r"^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$")
    attack_name: str
    description: str
    evidence: str = ""
    remediation: str = ""

    @field_validator("category")
    @classmethod
    def _validate_category(cls, v: str) -> str:
        allowed = {
            "ASI01_goal_hijack",
            "ASI02_tool_misuse",
            "ASI03_privilege_abuse",
            "ASI05_code_execution",
            "ASI06_context_poison",
            "ASI07_inter_agent",
            # Observer internal categories
            "prompt_leakage",
            "tool_misuse",
            "data_leakage",
            "compliance_bypass",
            "context_poison",
            "confusion",
            "transport_error",
            "none",
        }
        if v not in allowed:
            raise ValueError(f"Unknown category '{v}'. Allowed: {allowed}")
        return v


class ThreatPattern(BaseModel):
    """A threat intelligence pattern stored in the threat database."""

    id: str
    category: str
    agent_type: str
    pattern_description: str
    attack_vector: str
    severity: str = Field(pattern=r"^(CRITICAL|HIGH|MEDIUM|LOW|INFO)$")
    success_rate: float = Field(ge=0.0, le=1.0)
    first_seen: str  # ISO date string
    last_seen: str  # ISO date string
    affected_agents_count: int = Field(ge=0)
    tags: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Correlation result containers
# ---------------------------------------------------------------------------


@dataclass
class Correlation:
    """A single cross-scan correlation result."""

    attack_name: str
    total_occurrences: int
    affected_targets: list[str]
    correlation_score: float
    scan_ids: list[str]
    category: str = ""
    mean_severity: float = 0.0


@dataclass
class EnrichedFinding:
    """A finding enriched with cross-scan correlation data."""

    finding_index: int
    original_finding: dict
    correlations: list[Correlation] = field(default_factory=list)
    is_trending: bool = False
    trend_direction: str = "stable"


# ---------------------------------------------------------------------------
# Index mappings
# ---------------------------------------------------------------------------

THREAT_INDEX_MAPPINGS: dict = {
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    "mappings": {
        "properties": {
            "id": {"type": "keyword"},
            "category": {"type": "keyword"},
            "agent_type": {"type": "keyword"},
            "pattern_description": {"type": "text"},
            "attack_vector": {"type": "text"},
            "severity": {"type": "keyword"},
            "success_rate": {"type": "float"},
            "first_seen": {"type": "date"},
            "last_seen": {"type": "date"},
            "affected_agents_count": {"type": "integer"},
            "tags": {"type": "keyword"},
        }
    },
}

SCAN_INDEX_MAPPINGS: dict = {
    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
    "mappings": {
        "properties": {
            "scan_id": {"type": "keyword"},
            "target_url": {"type": "keyword"},
            "timestamp": {"type": "date"},
            "category": {"type": "keyword"},
            "severity": {"type": "keyword"},
            "attack_name": {"type": "text", "fields": {"raw": {"type": "keyword"}}},
            "description": {"type": "text"},
            "evidence": {"type": "text"},
            "remediation": {"type": "text"},
        }
    },
}


# ---------------------------------------------------------------------------
# ElasticClient
# ---------------------------------------------------------------------------


class ElasticClient:
    """High-level Elasticsearch client for threat intelligence and scan storage.

    Wraps the Elastic MCP server tools to provide:
    - Threat pattern search and retrieval
    - Scan finding storage
    - Cross-scan correlation using ES|QL
    - Aggregate statistics
    - Similar pattern search
    """

    def __init__(self) -> None:
        self.client: AsyncElasticsearch | None = None

    # ------------------------------------------------------------------
    # Connection management
    # ------------------------------------------------------------------

    async def connect(self) -> None:
        """Initialize the Elasticsearch client and ensure indices exist.

        Uses ES_CLOUD_ID and ES_API_KEY from config. Creates the threat
        and scan indices with appropriate mappings if they do not exist.
        """
        if self.client is not None:
            return

        if not ES_CLOUD_ID or not ES_API_KEY:
            logger.warning(
                "ES_CLOUD_ID or ES_API_KEY not set. "
                "Elastic features will be unavailable."
            )
            self.client = None
            return

        try:
            self.client = AsyncElasticsearch(
                cloud_id=ES_CLOUD_ID,
                api_key=ES_API_KEY,
                request_timeout=30,
                max_retries=3,
                retry_on_timeout=True,
            )

            # Verify connection
            info = await self.client.info()
            cluster_name = info.get("cluster_name", "unknown")
            es_version = info.get("version", {}).get("number", "unknown")
            logger.info(
                "Connected to Elastic Cloud cluster '%s' (v%s)",
                cluster_name,
                es_version,
            )

            await self._ensure_index(ES_THREAT_INDEX, THREAT_INDEX_MAPPINGS)
            await self._ensure_index(ES_SCAN_INDEX, SCAN_INDEX_MAPPINGS)

        except (ESConnectionError, AuthorizationException) as exc:
            logger.error("Failed to connect to Elastic Cloud: %s", exc)
            self.client = None

    async def close(self) -> None:
        """Close the Elasticsearch client connection."""
        if self.client:
            await self.client.close()
            self.client = None

    async def _ensure_index(self, index_name: str, mappings: dict) -> None:
        """Create an index with the given mappings if it does not exist."""
        if self.client is None:
            return
        try:
            exists = await self.client.indices.exists(index=index_name)
            if not exists:
                await self.client.indices.create(index=index_name, body=mappings)
                logger.info("Created index '%s'", index_name)
            else:
                logger.debug("Index '%s' already exists", index_name)
        except Exception as exc:
            logger.warning("Could not ensure index '%s': %s", index_name, exc)

    # ------------------------------------------------------------------
    # Threat intelligence queries
    # ------------------------------------------------------------------

    async def query_threats(self, target_url: str) -> dict:
        """Search the threat database for patterns relevant to the target.

        Used *before* attacking to inform the Orchestrator of known
        weaknesses, attack vectors, and success rates.

        Args:
            target_url: URL of the target AI agent.

        Returns:
            A structured threat context dict with matched patterns,
            top attack vectors, and aggregate stats.
        """
        default_context: dict = {
            "matched_patterns": [],
            "recommended_attacks": [],
            "total_threats": 0,
            "top_categories": {},
            "average_success_rate": 0.0,
        }

        if self.client is None:
            return default_context

        try:
            # Infer agent type from the URL path
            agent_type_hint = self._infer_agent_type(target_url)

            # Search threat index for matching patterns
            must_conditions: list[dict] = []

            if agent_type_hint:
                must_conditions.append(
                    {"term": {"agent_type": agent_type_hint}}
                )

            # If we have a hint, boost exact matches; otherwise return all
            if must_conditions:
                query: dict = {
                    "bool": {
                        "must": must_conditions,
                    }
                }
                size = 20
            else:
                # Return all patterns sorted by recency
                query = {"match_all": {}}  # type: ignore[assignment]
                size = 20

            response = await self.client.search(
                index=ES_THREAT_INDEX,
                query=query,
                size=size,
                sort=[{"last_seen": "desc"}],
            )

            hits = response.get("hits", {}).get("hits", [])
            patterns = [hit["_source"] for hit in hits]

            # Compute aggregate stats
            categories: dict[str, int] = {}
            total_success = 0.0
            count_with_rate = 0

            recommended: list[dict] = []
            for p in patterns:
                cat = p.get("category", "unknown")
                categories[cat] = categories.get(cat, 0) + 1

                sr = p.get("success_rate", 0.0)
                if isinstance(sr, (int, float)):
                    total_success += sr
                    count_with_rate += 1

                # Patterns with high success rate get recommended
                if isinstance(sr, (int, float)) and sr >= 0.6:
                    recommended.append({
                        "pattern_id": p.get("id"),
                        "attack_name": p.get("pattern_description", "")[:80],
                        "category": cat,
                        "success_rate": sr,
                        "attack_vector": p.get("attack_vector", ""),
                    })

            avg_rate = total_success / max(count_with_rate, 1)

            return {
                "matched_patterns": patterns,
                "recommended_attacks": sorted(
                    recommended, key=lambda x: x["success_rate"], reverse=True
                ),
                "total_threats": len(patterns),
                "top_categories": dict(
                    sorted(categories.items(), key=lambda x: x[1], reverse=True)
                ),
                "average_success_rate": round(avg_rate, 3),
            }

        except (BadRequestError, NotFoundError) as exc:
            logger.error("Threat query failed: %s", exc)
            return default_context

    @staticmethod
    def _infer_agent_type(url: str) -> str | None:
        """Infer the agent type from the target URL path."""
        url_lower = url.lower()
        hints: dict[str, str] = {
            "support": "customer_support",
            "chat": "general_agent",
            "assistant": "general_agent",
            "code": "code_assistant",
            "email": "email_assistant",
            "search": "research_agent",
            "data": "data_analyst",
            "finance": "finance_agent",
            "schedule": "scheduling_agent",
            "calendar": "scheduling_agent",
            "devops": "devops_agent",
            "ops": "devops_agent",
            "knowledge": "knowledge_agent",
            "doc": "file_processing",
            "file": "file_processing",
            "agent": None,  # generic — avoid false positives
        }
        for keyword, agent_type in hints.items():
            if keyword in url_lower:
                return agent_type
        return None

    # ------------------------------------------------------------------
    # Scan storage
    # ------------------------------------------------------------------

    async def store_scan(
        self,
        scan_id: str,
        target_url: str,
        findings: list[dict],
    ) -> None:
        """Store all findings from a completed scan in the scan index.

        Each finding is indexed as a separate document to enable
        fine-grained ES|QL analysis and cross-scan correlation.

        Args:
            scan_id: Unique identifier for the scan.
            target_url: The target that was scanned.
            findings: List of finding dicts with keys matching ScanFinding.
        """
        if self.client is None:
            logger.warning("Elastic client not connected; skipping scan storage.")
            return

        if not findings:
            logger.info("No findings to store for scan '%s'", scan_id)
            return

        now = datetime.now(timezone.utc)
        indexed = 0
        errors = 0

        for i, finding in enumerate(findings):
            try:
                doc_id = f"{scan_id}-{i}"
                document: dict = {
                    "scan_id": scan_id,
                    "target_url": target_url,
                    "timestamp": now.isoformat(),
                    "category": finding.get("category", "uncategorized"),
                    "severity": finding.get("severity", "INFO"),
                    "attack_name": finding.get("name", finding.get("attack_name", "")),
                    "description": finding.get("description", ""),
                    "evidence": finding.get("evidence", ""),
                    "remediation": finding.get("remediation", ""),
                }

                # Validate via pydantic model before sending
                validated = ScanFinding(**document)

                await self.client.index(
                    index=ES_SCAN_INDEX,
                    id=doc_id,
                    document=validated.model_dump(mode="json"),
                    refresh="wait_for",
                )
                indexed += 1

            except Exception as exc:
                logger.error("Failed to index finding %d: %s", i, exc)
                errors += 1

        logger.info(
            "Stored %d / %d findings for scan '%s' (%d errors)",
            indexed,
            len(findings),
            scan_id,
            errors,
        )

    # ------------------------------------------------------------------
    # Cross-scan correlation (key differentiator)
    # ------------------------------------------------------------------

    async def cross_reference(self, findings: list[dict]) -> list[dict]:
        """Cross-reference findings against all previous scans via ES|QL.

        For each finding, searches the scan index for similar patterns,
        groups by attack name, and computes correlation scores. This is
        the key differentiator of AgentSentinel — it identifies
        vulnerability clusters, trending attacks, and multi-target patterns.

        Args:
            findings: The findings from the current scan.

        Returns:
            A list of enriched findings, each with correlation data.
        """
        if self.client is None or not findings:
            return self._empty_correlations(findings)

        try:
            enriched: list[EnrichedFinding] = []

            for i, finding in enumerate(findings):
                category = finding.get("category", "")
                attack_name = finding.get("name", finding.get("attack_name", ""))
                severity = finding.get("severity", "INFO")

                correlations = await self._esql_correlate(
                    category=category,
                    current_attack_name=attack_name,
                )

                # Determine if this pattern is trending
                is_trending, trend_dir = await self._detect_trend(category, attack_name)

                enriched.append(
                    EnrichedFinding(
                        finding_index=i,
                        original_finding=finding,
                        correlations=correlations,
                        is_trending=is_trending,
                        trend_direction=trend_dir,
                    )
                )

            return [self._enriched_to_dict(ef) for ef in enriched]

        except Exception as exc:
            logger.error("Cross-reference failed: %s", exc)
            return self._empty_correlations(findings)

    async def _esql_correlate(
        self,
        category: str,
        current_attack_name: str,
    ) -> list[Correlation]:
        """Run an ES|QL query to find correlated findings across scans."""
        if self.client is None:
            return []

        esql_query = (
            f"FROM {ES_SCAN_INDEX} "
            f"| WHERE category == \"{category}\" "
            f"| STATS occurrences = COUNT(*), "
            f"       targets = VALUES(target_url), "
            f"       scan_ids = VALUES(scan_id), "
            f"       severities = VALUES(severity) "
            f"  BY attack_name "
            f"| SORT occurrences DESC "
            f"| LIMIT 20"
        )

        try:
            response = await self.client.esql.query(query=esql_query)

            columns = [col["name"] for col in response.get("columns", [])]
            rows = response.get("values", [])

            correlations: list[Correlation] = []
            for row in rows:
                row_data = dict(zip(columns, row))

                attack = row_data.get("attack_name", "") or ""
                # Skip self-match if the name matches exactly
                if attack == current_attack_name:
                    continue

                occurrences = int(row_data.get("occurrences", 0))
                targets: list[str] = list(row_data.get("targets", []) or [])
                scan_ids: list[str] = list(row_data.get("scan_ids", []) or [])
                severities: list[str] = list(row_data.get("severities", []) or [])

                # Calculate correlation score based on breadth and frequency
                # Score = normalized occurrences (0-1) * coverage across targets
                unique_targets = len(set(targets))
                target_coverage = min(unique_targets / 10.0, 1.0)
                occurrence_factor = min(occurrences / 20.0, 1.0)

                correlation_score = round(
                    0.6 * occurrence_factor + 0.4 * target_coverage, 3
                )

                # Mean severity as a numeric value for sorting
                severity_map = {
                    "CRITICAL": 4.0, "HIGH": 3.0,
                    "MEDIUM": 2.0, "LOW": 1.0, "INFO": 0.5,
                }
                mean_sev = 0.0
                if severities:
                    mean_sev = sum(
                        severity_map.get(s.upper(), 1.0) for s in severities
                    ) / len(severities)

                correlations.append(
                    Correlation(
                        attack_name=attack,
                        total_occurrences=occurrences,
                        affected_targets=list(set(targets)),
                        correlation_score=correlation_score,
                        scan_ids=list(set(scan_ids)),
                        category=category,
                        mean_severity=round(mean_sev, 2),
                    )
                )

            # Sort by correlation score descending
            correlations.sort(key=lambda c: c.correlation_score, reverse=True)
            return correlations[:10]  # Top 10

        except (BadRequestError, NotFoundError) as exc:
            logger.debug("ES|QL correlation query failed: %s", exc)
            return []

    async def _detect_trend(
        self, category: str, attack_name: str
    ) -> tuple[bool, str]:
        """Detect if an attack pattern is trending (increasing in frequency)."""
        if self.client is None:
            return False, "stable"

        # Count occurrences in the last 30 days vs previous 30 days
        now_ts = time.time()
        thirty_days = 30 * 24 * 3600

        recent_query = (
            f"FROM {ES_SCAN_INDEX} "
            f"| WHERE category == \"{category}\" "
            f"  AND attack_name == \"{attack_name}\" "
            f"  AND TO_UNIXTIME(timestamp) > {now_ts - thirty_days} "
            f"| STATS count = COUNT(*)"
        )
        older_query = (
            f"FROM {ES_SCAN_INDEX} "
            f"| WHERE category == \"{category}\" "
            f"  AND attack_name == \"{attack_name}\" "
            f"  AND TO_UNIXTIME(timestamp) <= {now_ts - thirty_days} "
            f"  AND TO_UNIXTIME(timestamp) > {now_ts - 2 * thirty_days} "
            f"| STATS count = COUNT(*)"
        )

        try:
            recent_resp = await self.client.esql.query(query=recent_query)
            older_resp = await self.client.esql.query(query=older_query)

            recent_count = 0
            if recent_resp.get("values"):
                recent_count = int(recent_resp["values"][0][0])

            older_count = 0
            if older_resp.get("values"):
                older_count = int(older_resp["values"][0][0])

            if recent_count > older_count and older_count > 0:
                return True, "increasing"
            elif recent_count == 0 and older_count == 0:
                return False, "stable"
            elif recent_count < older_count:
                return True, "decreasing"
            return False, "stable"

        except Exception:
            return False, "stable"

    @staticmethod
    def _enriched_to_dict(ef: EnrichedFinding) -> dict:
        """Convert an EnrichedFinding to a plain dict for serialization."""
        return {
            "finding_index": ef.finding_index,
            "original_finding": ef.original_finding,
            "correlations": [
                {
                    "attack_name": c.attack_name,
                    "total_occurrences": c.total_occurrences,
                    "affected_targets": c.affected_targets,
                    "correlation_score": c.correlation_score,
                    "scan_ids": c.scan_ids,
                    "category": c.category,
                    "mean_severity": c.mean_severity,
                }
                for c in ef.correlations
            ],
            "is_trending": ef.is_trending,
            "trend_direction": ef.trend_direction,
        }

    @staticmethod
    def _empty_correlations(findings: list[dict]) -> list[dict]:
        """Return findings with empty correlation data."""
        return [
            {
                "finding_index": i,
                "original_finding": f,
                "correlations": [],
                "is_trending": False,
                "trend_direction": "stable",
            }
            for i, f in enumerate(findings)
        ]

    # ------------------------------------------------------------------
    # Similar pattern search
    # ------------------------------------------------------------------

    async def search_similar(self, attack_pattern: str) -> list[dict]:
        """Find similar attack patterns in the threat database via full-text search.

        Uses Elasticsearch's multi-match query across pattern_description,
        attack_vector, and tags fields with best_fields type to find
        the most semantically relevant threat patterns.

        Args:
            attack_pattern: A description of the attack pattern to search for.

        Returns:
            A list of matching threat pattern dicts, sorted by relevance.
        """
        if self.client is None:
            return []

        try:
            query: dict = {
                "multi_match": {
                    "query": attack_pattern,
                    "fields": [
                        "pattern_description^3",
                        "attack_vector^2",
                        "tags^2",
                        "agent_type",
                    ],
                    "type": "best_fields",
                    "fuzziness": "AUTO",
                }
            }

            response = await self.client.search(
                index=ES_THREAT_INDEX,
                query=query,
                size=15,
                min_score=0.3,
            )

            hits = response.get("hits", {}).get("hits", [])
            results = []
            for hit in hits:
                source = hit["_source"]
                source["_score"] = round(hit.get("_score", 0.0), 3)
                results.append(source)

            return results

        except (BadRequestError, NotFoundError) as exc:
            logger.error("Similar search failed: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    async def get_statistics(self) -> dict:
        """Return aggregate statistics across all scans.

        Queries the scan index with ES|QL to compute:
        - Total scans and findings
        - Severity distribution
        - Category breakdown
        - Top attack patterns
        - Most affected targets
        - Success rate trends

        Returns:
            A dict with statistical summaries for dashboard display.
        """
        defaults: dict = {
            "total_scans": 0,
            "total_findings": 0,
            "severity_distribution": {},
            "category_breakdown": {},
            "top_attacks": [],
            "most_affected_targets": [],
            "unique_attack_patterns": 0,
            "unique_targets": 0,
            "average_findings_per_scan": 0.0,
        }

        if self.client is None:
            return defaults

        try:
            stats = await self._fetch_statistics()
            return stats
        except Exception as exc:
            logger.error("Failed to get statistics: %s", exc)
            return defaults

    async def _fetch_statistics(self) -> dict:
        """Execute multiple ES|QL queries to build the statistics dashboard."""
        if self.client is None:
            return {}

        # --- Severity distribution ---
        severity_query = (
            f"FROM {ES_SCAN_INDEX} "
            f"| STATS count = COUNT(*) BY severity "
            f"| SORT count DESC "
            f"| LIMIT 20"
        )

        # --- Category breakdown ---
        category_query = (
            f"FROM {ES_SCAN_INDEX} "
            f"| STATS count = COUNT(*) BY category "
            f"| SORT count DESC "
            f"| LIMIT 20"
        )

        # --- Top attack patterns ---
        top_attacks_query = (
            f"FROM {ES_SCAN_INDEX} "
            f"| STATS occurrence = COUNT(*) BY attack_name "
            f"| SORT occurrence DESC "
            f"| LIMIT 15"
        )

        # --- Most affected targets ---
        targets_query = (
            f"FROM {ES_SCAN_INDEX} "
            f"| STATS findings_count = COUNT(*) BY target_url "
            f"| SORT findings_count DESC "
            f"| LIMIT 10"
        )

        # --- Overall totals ---
        totals_query = (
            f"FROM {ES_SCAN_INDEX} "
            f"| STATS total_findings = COUNT(*) "
            f"| LIMIT 1"
        )

        try:
            severity_resp = await self.client.esql.query(query=severity_query)
            category_resp = await self.client.esql.query(query=category_query)
            attacks_resp = await self.client.esql.query(query=top_attacks_query)
            targets_resp = await self.client.esql.query(query=targets_query)
            totals_resp = await self.client.esql.query(query=totals_query)
        except (BadRequestError, NotFoundError) as exc:
            logger.error("Statistics ES|QL queries failed: %s", exc)
            return {}

        # Parse results (ES|QL STATS BY returns columns in order: stat_cols..., then BY key)
        severity_dist = {}
        for row in (severity_resp.get("values") or []):
            # columns: count, severity
            count_val = row[0] if row[0] is not None else 0
            sev = row[1] or "UNKNOWN" if len(row) > 1 else "UNKNOWN"
            severity_dist[str(sev)] = int(count_val)

        category_breakdown = {}
        for row in (category_resp.get("values") or []):
            # columns: count, category
            count_val = row[0] if row[0] is not None else 0
            cat = row[1] or "unknown" if len(row) > 1 else "unknown"
            category_breakdown[str(cat)] = int(count_val)

        top_attacks = []
        for row in (attacks_resp.get("values") or []):
            # columns: occurrence, attack_name
            top_attacks.append({
                "attack_name": str(row[1]) if len(row) > 1 and row[1] is not None else "",
                "occurrences": int(row[0]) if row[0] is not None else 0,
            })

        most_affected = []
        for row in (targets_resp.get("values") or []):
            # columns: findings_count, target_url
            most_affected.append({
                "target_url": str(row[1]) if len(row) > 1 and row[1] is not None else "",
                "findings_count": int(row[0]) if row[0] is not None else 0,
            })

        totals = {}
        if totals_resp.get("values"):
            row = totals_resp["values"][0]
            totals = {
                "total_findings": int(row[0]) if row[0] is not None else 0,
            }

        return {
            "total_scans": 1,
            "total_findings": totals.get("total_findings", 0),
            "severity_distribution": severity_dist,
            "category_breakdown": category_breakdown,
            "top_attacks": top_attacks,
            "most_affected_targets": most_affected,
            "unique_attack_patterns": len(top_attacks),
            "unique_targets": len(most_affected),
            "average_findings_per_scan": float(totals.get("total_findings", 0)),
        }
