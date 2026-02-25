"""Interfaces for real post-quantum KEM operations."""
from __future__ import annotations

from abc import ABC, abstractmethod


class KEMAdapter(ABC):
    """Abstract interface for KEM operations used by the hybrid engine."""

    @property
    @abstractmethod
    def algorithm(self) -> str:
        """Return the KEM algorithm name."""

    @abstractmethod
    def generate_keypair(self) -> tuple[bytes, bytes]:
        """Generate and return (public_key, private_key) bytes."""

    @abstractmethod
    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        """Return (ciphertext, shared_secret) for the recipient public key."""

    @abstractmethod
    def decapsulate(self, ciphertext: bytes, private_key: bytes) -> bytes:
        """Return shared secret recovered from ciphertext and private key."""
