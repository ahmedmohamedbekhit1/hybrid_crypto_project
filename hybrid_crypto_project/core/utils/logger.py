"""Structured logging configuration used across the project."""
from __future__ import annotations

import logging
import sys


def get_logger(name: str) -> logging.Logger:
    """Create and return a configured logger.

    Uses ISO timestamps and INFO level by default.
    """
    logger = logging.getLogger(name)
    if logger.handlers:
        return logger
    handler = logging.StreamHandler(sys.stdout)
    fmt = logging.Formatter(
        fmt="%(asctime)s %(levelname)s [%(name)s] %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )
    handler.setFormatter(fmt)
    logger.addHandler(handler)
    logger.setLevel(logging.INFO)
    return logger
