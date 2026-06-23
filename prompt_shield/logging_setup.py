"""
logging_setup.py — Centralised logging configuration for Prompt Shield.

Call ``setup_logging()`` once at application startup (before any other
prompt_shield imports) to configure all handlers.
"""

from __future__ import annotations

import logging
import sys
from pathlib import Path

from prompt_shield.config import LOG_FORMAT, LOG_DATE_FORMAT, LOG_FILE, LOG_LEVEL


def setup_logging(
    level: int = LOG_LEVEL,
    log_file: Path | None = LOG_FILE,
) -> None:
    """
    Configure the root logger with a StreamHandler and, optionally, a
    FileHandler.

    Parameters
    ----------
    level:
        Python logging level (e.g. ``logging.INFO``).
    log_file:
        If provided, attach a ``FileHandler`` that writes to this path.
    """
    handlers: list[logging.Handler] = [
        _build_stream_handler(level),
    ]
    if log_file is not None:
        handlers.append(_build_file_handler(log_file, level))

    logging.basicConfig(
        level=level,
        format=LOG_FORMAT,
        datefmt=LOG_DATE_FORMAT,
        handlers=handlers,
        force=True,  # reset any previously configured handlers
    )
    logging.getLogger(__name__).debug("Logging initialised at level %s.", level)


# ---------------------------------------------------------------------------
# Private helpers
# ---------------------------------------------------------------------------


def _build_stream_handler(level: int) -> logging.StreamHandler:
    handler = logging.StreamHandler(sys.stderr)
    handler.setLevel(level)
    handler.setFormatter(
        logging.Formatter(fmt=LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
    )
    return handler


def _build_file_handler(path: Path, level: int) -> logging.FileHandler:
    handler = logging.FileHandler(path, encoding="utf-8")
    handler.setLevel(level)
    handler.setFormatter(
        logging.Formatter(fmt=LOG_FORMAT, datefmt=LOG_DATE_FORMAT)
    )
    return handler
