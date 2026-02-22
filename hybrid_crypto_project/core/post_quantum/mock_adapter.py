"""Secure mock KEM adapter used when PQ backend is unavailable.

This adapter implements an X25519-based authenticated KEM using HKDF-SHA256.
It is NOT a post-quantum primitive and is intended only as a safe fallback
for demonstration and testing when liboqs is not installed.
"""
from __future__ import annotations

from typing import Tuple
import secrets

from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes, serialization

from .base import KEMAdapter


class MockKEMAdapter(KEMAdapter):
    """Fallback KEM using X25519 + HKDF-SHA256.

    Produces 32-byte shared secrets suitable for symmetric key derivation.
    """

    def generate_keypair(self) -> Tuple[bytes, bytes]:
        priv = X25519PrivateKey.generate()
        pub = priv.public_key()
        pub_b = pub.public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        priv_b = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        return pub_b, priv_b

    def encapsulate(self, public_key: bytes) -> Tuple[bytes, bytes]:
        # Interpret public_key as raw X25519 public bytes
        recipient_pub = X25519PublicKey.from_public_bytes(public_key)
        eph_priv = X25519PrivateKey.generate()
        shared = eph_priv.exchange(recipient_pub)
        # Derive a 32-byte key from shared secret
        ss = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"mock-kem").derive(shared)
        # ciphertext is ephemeral public bytes
        ct = eph_priv.public_key().public_bytes(encoding=serialization.Encoding.Raw, format=serialization.PublicFormat.Raw)
        return ct, ss

    def decapsulate(self, ciphertext: bytes, private_key: bytes) -> bytes:
        # ciphertext is ephemeral public bytes
        eph_pub = X25519PublicKey.from_public_bytes(ciphertext)
        priv = X25519PrivateKey.from_private_bytes(private_key)
        shared = priv.exchange(eph_pub)
        ss = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"mock-kem").derive(shared)
        return ss
