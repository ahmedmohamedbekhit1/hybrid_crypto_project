"""Adapter for Kyber KEM via liboqs (oqs) if available.

This module does a conditional import of `oqs` and provides an adapter
that implements the `KEMAdapter` interface. If `oqs` is missing, importing
this module will raise ImportError.
"""
from __future__ import annotations

from typing import Tuple
from .base import KEMAdapter

try:
    import oqs  # type: ignore
except Exception as exc:  # pragma: no cover - optional dependency
    raise ImportError("oqs library is not available") from exc


class KyberAdapter(KEMAdapter):
    """Kyber adapter using liboqs Python bindings.

    This expects the caller to securely store the private key bytes.
    """

    ALGORITHM = "Kyber512"

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        with oqs.KeyEncapsulation(self.ALGORITHM) as kem:
            public_key = kem.generate_keypair()
            private_key = kem.export_secret_key()
        return public_key, private_key

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        with oqs.KeyEncapsulation(self.ALGORITHM) as kem:
            ct, ss = kem.encapsulate(public_key)
        return ct, ss

    def decapsulate(self, ciphertext: bytes, private_key: bytes) -> bytes:
        with oqs.KeyEncapsulation(self.ALGORITHM) as kem:
            kem.import_secret_key(private_key)
            ss = kem.decapsulate(ciphertext)
        return ss
