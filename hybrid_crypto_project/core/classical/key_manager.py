"""Key storage helpers for RSA keys.

This module provides secure filesystem operations for key material.
"""
from __future__ import annotations

from typing import Optional
import os
import stat

from pathlib import Path


def save_private_key(path: str, data: bytes, mode: int = 0o600) -> None:
    """Atomically write private key bytes to disk with restrictive permissions.

    Args:
        path: Destination path.
        data: PEM bytes.
        mode: File mode (POSIX). Windows uses default ACLs.
    """
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(".tmp")
    with tmp.open("wb") as f:
        f.write(data)
    try:
        tmp.replace(p)
    except Exception:
        tmp.rename(p)
    try:
        os.chmod(p, mode)
    except Exception:
        # On Windows os.chmod semantics differ; best-effort only
        pass


def load_bytes(path: str) -> bytes:
    """Read a file and return bytes.

    Raises FileNotFoundError if missing.
    """
    p = Path(path)
    with p.open("rb") as f:
        return f.read()


def safe_path(path: str, base_dir: Optional[str] = None) -> str:
    """Validate and return an absolute path within base_dir if provided.

    Prevents path traversal when base_dir is set.
    """
    p = Path(path).resolve()
    if base_dir is not None:
        base = Path(base_dir).resolve()
        if not str(p).startswith(str(base)):
            raise ValueError("Path escapes allowed base directory")
    return str(p)
