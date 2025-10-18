"""Logging helpers for consistent production-friendly output."""

from __future__ import annotations

import logging
import os
from typing import Optional

DEFAULT_LOG_LEVEL = "INFO"
LOG_LEVEL_ENV = "NSHS_LOG_LEVEL"


def setup_logging(level: Optional[str] = None) -> None:
    """Configure global logging if not already configured."""
    if logging.getLogger().handlers:
        return

    level_name = level or os.getenv(LOG_LEVEL_ENV, DEFAULT_LOG_LEVEL)
    logging.basicConfig(
        level=level_name,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )
