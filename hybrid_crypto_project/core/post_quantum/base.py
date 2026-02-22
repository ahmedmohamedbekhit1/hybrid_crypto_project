"""Base classes and interfaces for post-quantum KEM adapters."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Tuple


class KEMAdapter(ABC):
    """Abstract interface for a KEM adapter.

    Implementations MUST not expose raw private key bytes and MUST provide
    deterministic serialization for public keys.
    """

    @abstractmethod
    def generate_keypair(self) -> Tuple[bytes, bytes]:
        """Generate (public_key, private_key) bytes. Private key kept by caller."""

    @abstractmethod
    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        """Encapsulate to a recipient public key.

        Returns (ciphertext, shared_secret).
        """

    @abstractmethod
    def decapsulate(self, ciphertext: bytes, private_key: bytes) -> bytes:
        """Recover shared secret from ciphertext and recipient private key."""
