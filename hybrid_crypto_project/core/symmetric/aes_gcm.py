"""AES-256-GCM symmetric encryption wrapper.

Uses pyca/cryptography's AESGCM for authenticated encryption.
"""
from __future__ import annotations

from typing import Tuple
import secrets
import base64

from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class AESGCMCipher:
    """Convenience wrapper for AES-256-GCM operations.

    The AES key is 32 bytes (256 bits). Nonce/IV is 12 bytes recommended for GCM.
    """

    KEY_SIZE = 32
    IV_SIZE = 12

    @staticmethod
    def generate_key() -> bytes:
        """Generate a cryptographically secure 32-byte key."""
        return secrets.token_bytes(AESGCMCipher.KEY_SIZE)

    @staticmethod
    def encrypt(key: bytes, plaintext: bytes, associated_data: bytes | None = None) -> Tuple[bytes, bytes]:
        """Encrypt plaintext and return (nonce, ciphertext).

        The ciphertext returned contains the authentication tag appended (AESGCM default).
        """
        if len(key) != AESGCMCipher.KEY_SIZE:
            raise ValueError("Invalid AES key size")
        aesgcm = AESGCM(key)
        nonce = secrets.token_bytes(AESGCMCipher.IV_SIZE)
        ct = aesgcm.encrypt(nonce, plaintext, associated_data)
        return nonce, ct

    @staticmethod
    def decrypt(key: bytes, nonce: bytes, ciphertext: bytes, associated_data: bytes | None = None) -> bytes:
        """Decrypt and validate tag. Raises exceptions on failure."""
        if len(key) != AESGCMCipher.KEY_SIZE:
            raise ValueError("Invalid AES key size")
        if len(nonce) != AESGCMCipher.IV_SIZE:
            raise ValueError("Invalid nonce size")
        aesgcm = AESGCM(key)
        return aesgcm.decrypt(nonce, ciphertext, associated_data)
