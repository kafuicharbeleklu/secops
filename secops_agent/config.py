"""
Configuration management for the SecOps Agent.
"""

from __future__ import annotations

import os
from pathlib import Path
from dotenv import load_dotenv

# Load env variables from .env if present
load_dotenv()

class Config:
    GEMINI_API_KEY: str = os.getenv("GEMINI_API_KEY", "")
    MODEL_NAME: str = os.getenv("MODEL_NAME") or os.getenv("GEMINI_MODEL", "gemini-2.5-flash")
    MODEL_TEMPERATURE: float = float(os.getenv("MODEL_TEMPERATURE", "0.7"))
    MODEL_MAX_TOKENS: int = int(os.getenv("MODEL_MAX_TOKENS", "8192"))
    GOOGLE_SEARCH_GROUNDING: str = os.getenv("GOOGLE_SEARCH_GROUNDING", "auto").strip().casefold()
    # Gate the one local-answer that requires outbound egress: the public-IP
    # lookup ("what's my public IP"). Set to off/0/false/no to disable it in
    # sensitive engagements. Enabled by default.
    PUBLIC_IP_LOOKUP: str = os.getenv("SECOPS_PUBLIC_IP_LOOKUP", "auto").strip().casefold()
    AGENT_NAME: str = os.getenv("AGENT_NAME", "SecOps Agent")
    MAX_TOOL_RETRIES: int = int(os.getenv("MAX_TOOL_RETRIES", "3"))
    TOOL_TIMEOUT: int = int(os.getenv("TOOL_TIMEOUT", "120"))
    TRACE_FILE: str = os.getenv("SECOPS_TRACE_FILE", "").strip()
    LOG_LEVEL: str = os.getenv("LOG_LEVEL", "INFO")
    LOG_FILE: str = os.getenv("LOG_FILE", "secops_agent.log")
    
    @property
    def sessions_dir(self) -> Path:
        try:
            path = Path.home() / ".secops_agent" / "sessions"
            path.mkdir(parents=True, exist_ok=True)
            return path
        except OSError:
            # Fallback to local workspace folder
            path = Path("./.secops_sessions")
            path.mkdir(parents=True, exist_ok=True)
            return path

settings = Config()
