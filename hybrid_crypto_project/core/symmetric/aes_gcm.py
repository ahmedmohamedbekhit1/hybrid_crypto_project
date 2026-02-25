"""AES-256-GCM helper primitives."""
from __future__ import annotations

import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class AESGCMCipher:
    """AES-256-GCM operations with explicit IV and tag handling."""

    KEY_SIZE = 32
    IV_SIZE = 12
    TAG_SIZE = 16

    @classmethod
    def generate_key(cls) -> bytes:
        return secrets.token_bytes(cls.KEY_SIZE)

    @classmethod
    def generate_iv(cls) -> bytes:
        return secrets.token_bytes(cls.IV_SIZE)

    @classmethod
    def encrypt(
        cls,
        key: bytes,
        iv: bytes,
        plaintext: bytes,
        aad: bytes | None = None,
    ) -> tuple[bytes, bytes]:
        if len(key) != cls.KEY_SIZE:
            raise ValueError("AES-256 key must be 32 bytes")
        if len(iv) != cls.IV_SIZE:
            raise ValueError("AES-GCM IV must be 12 bytes")
        combined = AESGCM(key).encrypt(iv, plaintext, aad)
        return combined[:-cls.TAG_SIZE], combined[-cls.TAG_SIZE:]

    @classmethod
    def decrypt(
        cls,
        key: bytes,
        iv: bytes,
        ciphertext: bytes,
        tag: bytes,
        aad: bytes | None = None,
    ) -> bytes:
        if len(key) != cls.KEY_SIZE:
            raise ValueError("AES-256 key must be 32 bytes")
        if len(iv) != cls.IV_SIZE:
            raise ValueError("AES-GCM IV must be 12 bytes")
        if len(tag) != cls.TAG_SIZE:
            raise ValueError("AES-GCM tag must be 16 bytes")
        try:
            return AESGCM(key).decrypt(iv, ciphertext + tag, aad)
        except InvalidTag as exc:
            raise ValueError("AES-GCM authentication failed") from exc
