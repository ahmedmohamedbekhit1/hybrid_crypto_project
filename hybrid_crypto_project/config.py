"""Configuration constants for the packaged project.

This mirrors the top-level config but uses package-relative resolution where
appropriate. Runtime code should prefer filesystem-relative paths when
interacting with application data.
"""
from __future__ import annotations

from pathlib import Path

# When running from source the repo root is two levels up from this file.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
KEY_DIR = PROJECT_ROOT / "keys"
