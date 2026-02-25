"""File handling utilities with safe path validation and atomic writes."""
from __future__ import annotations

from pathlib import Path


def safe_path(path: str, base_dir: str | None = None) -> str:
    """Return an absolute, resolved path and optionally ensure it's inside base_dir."""
    p = Path(path).resolve()
    if base_dir is not None:
        base = Path(base_dir).resolve()
        if not str(p).startswith(str(base)):
            raise ValueError("Path escapes allowed base directory")
    return str(p)

def atomic_write(path: str, data: bytes) -> None:
    """Atomically write bytes to a file by writing to a .tmp and renaming."""
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    with tmp.open("wb") as f:
        f.write(data)
    try:
        tmp.replace(p)
    except Exception:
        tmp.rename(p)
