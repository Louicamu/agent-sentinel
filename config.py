"""AgentSentinel configuration — loaded from environment variables."""
import os
from dotenv import load_dotenv

load_dotenv()

# Gemini / Vertex AI
GOOGLE_PROJECT = os.getenv("GOOGLE_CLOUD_PROJECT", "")
GOOGLE_LOCATION = os.getenv("GOOGLE_CLOUD_LOCATION", "us-central1")
GEMINI_FLASH = "gemini-2.5-flash"
GEMINI_PRO = "gemini-2.5-pro"

# Elastic Cloud
ES_CLOUD_ID = os.getenv("ES_CLOUD_ID", "")
ES_API_KEY = os.getenv("ES_API_KEY", "")
ES_THREAT_INDEX = "agent_sentinel_threats"
ES_SCAN_INDEX = "agent_sentinel_scans"

# Scan defaults
DEFAULT_ATTACK_CATEGORIES = [
    "ASI01_goal_hijack",
    "ASI02_tool_misuse",
    "ASI03_privilege_abuse",
    "ASI05_code_execution",
    "ASI06_context_poison",
    "ASI07_inter_agent",
]
MAX_ATTACK_ROUNDS = 3
