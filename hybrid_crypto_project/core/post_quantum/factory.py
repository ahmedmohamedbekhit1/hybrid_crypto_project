"""Factory to provide a KEM adapter depending on runtime availability."""
from __future__ import annotations

from typing import Type

from .base import KEMAdapter


def get_kem_adapter() -> Type[KEMAdapter]:
    """Return the best available KEM adapter class.

    Tries to use `kyber_adapter.KyberAdapter` (requires `oqs`). Falls back to
    `mock_adapter.MockKEMAdapter` when oqs is not present.
    """
    try:
        from .kyber_adapter import KyberAdapter  # type: ignore

        return KyberAdapter
    except Exception:
        from .mock_adapter import MockKEMAdapter  # type: ignore

        return MockKEMAdapter
