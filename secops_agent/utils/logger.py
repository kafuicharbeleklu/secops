"""
Structured logging configuration using Rich handlers.
"""

from __future__ import annotations

import logging
from rich.logging import RichHandler

from secops_agent.config import settings

def setup_logger():
    # Silence verbose third party libraries in CLI
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("urllib3").setLevel(logging.WARNING)
    logging.getLogger("google").setLevel(logging.WARNING)
    logging.getLogger("google.genai").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)

    # Setup base configuration (only capture WARNING and above for console by default)
    logging.basicConfig(
        level=logging.WARNING,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[
            RichHandler(
                rich_tracebacks=True,
                markup=True,
                show_path=False
            )
        ]
    )
    
    # Create logger instance for our application
    logger = logging.getLogger("secops_agent")
    logger.setLevel(logging.INFO)
    logger.propagate = False
    
    # Also add a file handler for history/debugging logs silently. The CLI must
    # still start in read-only homes, CI sandboxes, or restricted SSH sessions.
    if not logger.handlers:
        try:
            log_file = settings.sessions_dir.parent / settings.LOG_FILE
            file_handler = logging.FileHandler(log_file, encoding="utf-8")
            file_handler.setFormatter(logging.Formatter(
                "%(asctime)s - %(name)s - %(levelname)s - %(message)s"
            ))
            logger.addHandler(file_handler)
        except OSError:
            logger.addHandler(logging.NullHandler())
    
    return logger

logger = setup_logger()
