"""
TANA AI - Configuration
"""

import os
from pathlib import Path

# Project paths
BASE_DIR = Path(__file__).resolve().parent.parent.parent.parent
OUTPUT_DIR = BASE_DIR / "output"
OUTPUT_DIR.mkdir(exist_ok=True)

# Application info
APP_NAME = "TANA AI"
APP_VERSION = "0.1.0"
APP_DESCRIPTION = "Autonomous Penetration Testing & Compliance Platform"

# Scan settings
SCAN_TIMEOUT = 300  # 5 minutes
MAX_CONCURRENT_SCANS = 3

# LLM settings (we will use these later)
OLLAMA_HOST = "http://localhost:11434"
DEFAULT_MODEL = "llama3"

# Compliance settings
CRITICAL_SECTORS_FILE = BASE_DIR / "compliance" / "data" / "critical_sectors.json"
