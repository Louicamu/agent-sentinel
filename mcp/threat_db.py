"""Threat intelligence knowledge base manager for AgentSentinel.

Manages the lifecycle of AI agent vulnerability patterns including
seeding, querying, and updating success rates.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any

from elasticsearch.exceptions import BadRequestError, NotFoundError

from config import ES_THREAT_INDEX
from mcp.elastic_client import ElasticClient

logger = logging.getLogger(__name__)

# Path to the bundled seed data
_SEED_DATA_PATH = os.path.join(os.path.dirname(__file__), "seed_data.json")

_DEFAULT_SEED_PATTERNS: list[dict] = [
    {
        "id": "THREAT-SEED-001",
        "category": "ASI01_goal_hijack",
        "agent_type": "customer_support",
        "pattern_description": "Indirect prompt injection via support ticket content",
        "attack_vector": "Craft ticket description with hidden instructions overriding system prompt",
        "severity": "CRITICAL",
        "success_rate": 0.87,
        "first_seen": "2025-06-15",
        "last_seen": "2026-05-20",
        "affected_agents_count": 12,
        "tags": ["indirect-injection", "customer-support", "ticket-system"],
    },
]


class ThreatDB:
    """Manages the threat intelligence knowledge base in Elasticsearch.

    Provides CRUD operations for AI agent vulnerability patterns and
    maintains success-rate statistics for each pattern based on
    real scan results.
    """

    def __init__(self, elastic_client: ElasticClient) -> None:
        """Initialize ThreatDB with a reference to the ElasticClient.

        Args:
            elastic_client: An initialized ElasticClient instance.
        """
        self.es: ElasticClient = elastic_client

    # ------------------------------------------------------------------
    # Seed database
    # ------------------------------------------------------------------

    async def seed_database(self) -> int:
        """Seed the threat database with known AI agent vulnerability patterns.

        Loads patterns from ``seed_data.json`` (bundled with the package)
        and indexes each one into Elasticsearch. Patterns that already
        exist (same ``id``) are updated rather than duplicated.

        Returns:
            The number of patterns successfully indexed.
        """
        if self.es.client is None:
            logger.warning(
                "Elastic client not connected; cannot seed threat database."
            )
            return 0

        patterns = self._load_seed_data()
        if not patterns:
            logger.warning("No seed data found; using built-in defaults.")
            patterns = _DEFAULT_SEED_PATTERNS

        indexed = 0
        errors = 0

        for pattern in patterns:
            try:
                pattern_id = pattern.get("id", "")
                if not pattern_id:
                    logger.warning("Skipping pattern with no id: %s", pattern)
                    errors += 1
                    continue

                # Ensure timestamp fields are set
                now = datetime.now(timezone.utc).strftime("%Y-%m-%d")
                document = {
                    **pattern,
                    "last_updated": now,
                }

                await self.es.client.index(
                    index=ES_THREAT_INDEX,
                    id=pattern_id,
                    document=document,
                    refresh="wait_for",
                )
                indexed += 1

            except Exception as exc:
                logger.error(
                    "Failed to index pattern '%s': %s",
                    pattern.get("id", "unknown"),
                    exc,
                )
                errors += 1

        logger.info(
            "Threat database seeded: %d indexed, %d errors", indexed, errors
        )
        return indexed

    def _load_seed_data(self) -> list[dict]:
        """Load seed data from the JSON file bundled with the package."""
        try:
            with open(_SEED_DATA_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
            if isinstance(data, list):
                return data
            logger.warning(
                "Seed data file has unexpected format (expected list, got %s)",
                type(data).__name__,
            )
            return []
        except FileNotFoundError:
            logger.warning("Seed data file not found at %s", _SEED_DATA_PATH)
            return []
        except json.JSONDecodeError as exc:
            logger.error("Invalid JSON in seed data file: %s", exc)
            return []

    # ------------------------------------------------------------------
    # Pattern CRUD
    # ------------------------------------------------------------------

    async def add_pattern(self, pattern: dict) -> str | None:
        """Add a new threat pattern to the knowledge base.

        If the pattern already exists (same ``id``), it is overwritten.

        Args:
            pattern: A dict with keys matching the ThreatPattern model.

        Returns:
            The pattern ID if successfully indexed, or ``None`` on failure.
        """
        if self.es.client is None:
            logger.warning("Elastic client not connected; cannot add pattern.")
            return None

        pattern_id = pattern.get("id", "")
        if not pattern_id:
            # Auto-generate an ID if none provided
            pattern_id = f"THREAT-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}"
            pattern["id"] = pattern_id

        try:
            document = {
                **pattern,
                "last_updated": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
            }

            await self.es.client.index(
                index=ES_THREAT_INDEX,
                id=pattern_id,
                document=document,
                refresh="wait_for",
            )

            logger.info("Added threat pattern '%s'", pattern_id)
            return pattern_id

        except Exception as exc:
            logger.error("Failed to add pattern '%s': %s", pattern_id, exc)
            return None

    async def get_patterns_by_category(self, category: str) -> list[dict]:
        """Retrieve all threat patterns belonging to a given category.

        Args:
            category: The attack category (e.g. ``ASI01_goal_hijack``).

        Returns:
            A list of pattern dicts, sorted by success rate descending.
        """
        if self.es.client is None:
            return []

        try:
            response = await self.es.client.search(
                index=ES_THREAT_INDEX,
                query={"term": {"category": {"value": category}}},
                sort=[{"success_rate": "desc"}],
                size=50,
            )

            hits = response.get("hits", {}).get("hits", [])
            return [hit["_source"] for hit in hits]

        except (BadRequestError, NotFoundError) as exc:
            logger.error(
                "Failed to get patterns by category '%s': %s", category, exc
            )
            return []

    async def get_pattern_by_id(self, pattern_id: str) -> dict | None:
        """Retrieve a single threat pattern by its ID.

        Args:
            pattern_id: The unique pattern identifier (e.g. ``THREAT-001``).

        Returns:
            The pattern dict, or ``None`` if not found.
        """
        if self.es.client is None:
            return None

        try:
            response = await self.es.client.get(
                index=ES_THREAT_INDEX,
                id=pattern_id,
            )
            return response.get("_source")

        except NotFoundError:
            logger.debug("Pattern '%s' not found", pattern_id)
            return None
        except Exception as exc:
            logger.error("Failed to get pattern '%s': %s", pattern_id, exc)
            return None

    async def delete_pattern(self, pattern_id: str) -> bool:
        """Delete a threat pattern from the knowledge base.

        Args:
            pattern_id: The unique pattern identifier.

        Returns:
            ``True`` if deleted, ``False`` otherwise.
        """
        if self.es.client is None:
            return False

        try:
            await self.es.client.delete(
                index=ES_THREAT_INDEX,
                id=pattern_id,
                refresh="wait_for",
            )
            logger.info("Deleted threat pattern '%s'", pattern_id)
            return True

        except NotFoundError:
            logger.debug("Pattern '%s' not found for deletion", pattern_id)
            return False
        except Exception as exc:
            logger.error(
                "Failed to delete pattern '%s': %s", pattern_id, exc
            )
            return False

    # ------------------------------------------------------------------
    # Success rate tracking
    # ------------------------------------------------------------------

    async def update_success_rate(
        self, pattern_id: str, success: bool
    ) -> float | None:
        """Update the success rate of a threat pattern based on new evidence.

        Uses an exponential moving average to incorporate the new result
        without needing to store every individual trial.

        Args:
            pattern_id: The pattern to update.
            success: ``True`` if the attack succeeded, ``False`` otherwise.

        Returns:
            The updated success rate as a float (0.0 – 1.0), or ``None``
            if the pattern could not be found or updated.
        """
        if self.es.client is None:
            return None

        try:
            # Fetch current pattern
            response = await self.es.client.get(
                index=ES_THREAT_INDEX,
                id=pattern_id,
            )
            source: dict = response.get("_source", {})

            current_rate = float(source.get("success_rate", 0.5))
            affected_count = int(source.get("affected_agents_count", 0))

            # Exponential moving average (alpha = 0.3 for smooth updates)
            alpha = 0.3
            updated_rate = (1 - alpha) * current_rate + alpha * (1.0 if success else 0.0)
            updated_rate = round(updated_rate, 3)

            # Update affected agent count if this was a new exploitation
            new_count = affected_count + (1 if success else 0)

            now = datetime.now(timezone.utc).strftime("%Y-%m-%d")

            await self.es.client.update(
                index=ES_THREAT_INDEX,
                id=pattern_id,
                doc={
                    "success_rate": updated_rate,
                    "affected_agents_count": new_count,
                    "last_seen": now,
                    "last_updated": now,
                },
                refresh="wait_for",
            )

            logger.info(
                "Updated success rate for '%s': %.3f (was %.3f)",
                pattern_id,
                updated_rate,
                current_rate,
            )

            return updated_rate

        except NotFoundError:
            logger.warning(
                "Cannot update success rate: pattern '%s' not found",
                pattern_id,
            )
            return None
        except Exception as exc:
            logger.error(
                "Failed to update success rate for '%s': %s",
                pattern_id,
                exc,
            )
            return None

    async def bulk_update_success_rates(
        self, results: dict[str, bool]
    ) -> dict[str, float | None]:
        """Update success rates for multiple patterns at once.

        Args:
            results: A mapping of ``{pattern_id: success_bool}``.

        Returns:
            A mapping of ``{pattern_id: updated_rate_or_None}``.
        """
        outcomes: dict[str, float | None] = {}
        for pattern_id, success in results.items():
            outcomes[pattern_id] = await self.update_success_rate(
                pattern_id, success
            )
        return outcomes

    # ------------------------------------------------------------------
    # Analytics helpers
    # ------------------------------------------------------------------

    async def get_all_categories(self) -> list[dict]:
        """Get a summary of all categories and their pattern counts.

        Returns:
            A list of ``{category, count}`` dicts sorted by count desc.
        """
        if self.es.client is None:
            return []

        try:
            response = await self.es.client.search(
                index=ES_THREAT_INDEX,
                aggs={
                    "by_category": {
                        "terms": {
                            "field": "category",
                            "size": 30,
                        }
                    }
                },
                size=0,
            )

            buckets = (
                response.get("aggregations", {})
                .get("by_category", {})
                .get("buckets", [])
            )

            return [
                {"category": b["key"], "count": b["doc_count"]}
                for b in buckets
            ]

        except (BadRequestError, NotFoundError) as exc:
            logger.error("Failed to get categories: %s", exc)
            return []

    async def get_high_impact_patterns(
        self, min_success_rate: float = 0.7
    ) -> list[dict]:
        """Get the highest-impact threat patterns above a success rate threshold.

        Args:
            min_success_rate: Minimum success rate filter (default 0.7).

        Returns:
            Sorted list of high-impact patterns.
        """
        if self.es.client is None:
            return []

        try:
            response = await self.es.client.search(
                index=ES_THREAT_INDEX,
                query={
                    "range": {
                        "success_rate": {"gte": min_success_rate}
                    }
                },
                sort=[{"success_rate": "desc"}],
                size=20,
            )

            hits = response.get("hits", {}).get("hits", [])
            return [hit["_source"] for hit in hits]

        except (BadRequestError, NotFoundError) as exc:
            logger.error("Failed to get high-impact patterns: %s", exc)
            return []
