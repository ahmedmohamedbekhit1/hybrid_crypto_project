"""Factory returning the mandatory real post-quantum KEM adapter."""
from __future__ import annotations

from .base import KEMAdapter
from .kyber_adapter import Kyber768Adapter, PQUnavailableError


def get_mandatory_kem_adapter() -> KEMAdapter:
    """Return Kyber768 adapter or fail hard if unavailable."""
    adapter = Kyber768Adapter()
    try:
        _ = adapter.algorithm
    except Exception as exc:
        raise PQUnavailableError("Post-quantum KEM initialization failed") from exc
    return adapter
