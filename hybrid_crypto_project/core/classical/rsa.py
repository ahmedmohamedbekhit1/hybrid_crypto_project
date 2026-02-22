"""RSA utilities using pyca/cryptography with OAEP-SHA256 padding."""
from __future__ import annotations

from typing import Tuple
import os
import base64

from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.backends import default_backend


class RSAKeyManager:
    """Manage RSA key generation, serialization and encryption operations.

    All private key material MUST be handled securely and never printed.
    """

    def __init__(self, private_key: rsa.RSAPrivateKey | None = None) -> None:
        self._private_key = private_key

    @staticmethod
    def generate(key_size: int = 2048) -> "RSAKeyManager":
        """Generate a fresh RSA private key.

        Args:
            key_size: Size in bits (minimum 2048).
        Returns:
            RSAKeyManager wrapping the new private key.
        """
        if key_size < 2048:
            raise ValueError("RSA key size must be at least 2048 bits")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=key_size, backend=default_backend())
        return RSAKeyManager(private_key)

    def public_key_bytes(self) -> bytes:
        """Return PEM-encoded public key bytes."""
        pub = self._private_key.public_key()
        return pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )

    def private_key_bytes(self, password: bytes | None = None) -> bytes:
        """Return PEM-encoded private key bytes, optionally encrypted with a password."""
        enc = (
            serialization.BestAvailableEncryption(password) if password else serialization.NoEncryption()
        )
        return self._private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=enc,
        )

    @staticmethod
    def load_private(pem_data: bytes, password: bytes | None = None) -> "RSAKeyManager":
        """Load a private key from PEM bytes."""
        private_key = serialization.load_pem_private_key(pem_data, password=password, backend=default_backend())
        return RSAKeyManager(private_key)

    @staticmethod
    def load_public(pem_data: bytes) -> rsa.RSAPublicKey:
        """Load a public key from PEM bytes."""
        return serialization.load_pem_public_key(pem_data, backend=default_backend())

    def encrypt(self, plaintext: bytes, public_key: rsa.RSAPublicKey) -> bytes:
        """Encrypt using RSA-OAEP(SHA-256)."""
        ciphertext = public_key.encrypt(
            plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> bytes:
        """Decrypt ciphertext using the managed private key and OAEP-SHA256."""
        if self._private_key is None:
            raise ValueError("Private key not set for decryption")
        plaintext = self._private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )
        return plaintext
