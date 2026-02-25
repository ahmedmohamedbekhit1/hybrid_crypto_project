from __future__ import annotations

import hashlib
import secrets

import pytest

from hybrid_crypto_project.core.classical.rsa import generate_rsa_keypair
from hybrid_crypto_project.core.hybrid.hybrid_engine import HybridCryptoEngine
from hybrid_crypto_project.core.hybrid.payload import HybridPayload
from hybrid_crypto_project.core.post_quantum.base import KEMAdapter


class TestKEM(KEMAdapter):
    @property
    def algorithm(self) -> str:
        return "TEST-KEM"

    def generate_keypair(self) -> tuple[bytes, bytes]:
        secret = secrets.token_bytes(32)
        return secret, secret

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        ciphertext = secrets.token_bytes(32)
        shared_secret = hashlib.sha256(public_key + ciphertext).digest()
        return ciphertext, shared_secret

    def decapsulate(self, ciphertext: bytes, private_key: bytes) -> bytes:
        return hashlib.sha256(private_key + ciphertext).digest()


def _flip_first_byte(data: bytes) -> bytes:
    return bytes([data[0] ^ 0x01]) + data[1:]


def test_hybrid_round_trip() -> None:
    rsa_private, rsa_public = generate_rsa_keypair()
    pq_public, pq_private = TestKEM().generate_keypair()
    engine = HybridCryptoEngine(TestKEM())

    plaintext = b"hybrid message"
    payload = engine.encrypt_bytes(plaintext, rsa_public, pq_public)
    recovered = engine.decrypt_bytes(payload, rsa_private, pq_private)

    assert recovered == plaintext


def test_corrupted_ciphertext_fails() -> None:
    rsa_private, rsa_public = generate_rsa_keypair()
    pq_public, pq_private = TestKEM().generate_keypair()
    engine = HybridCryptoEngine(TestKEM())

    payload = engine.encrypt_bytes(b"hello", rsa_public, pq_public)
    tampered = HybridPayload(
        version=payload.version,
        iv=payload.iv,
        ciphertext=_flip_first_byte(payload.ciphertext),
        tag=payload.tag,
        rsa_wrapped_key=payload.rsa_wrapped_key,
        pq_ciphertext=payload.pq_ciphertext,
    )
    with pytest.raises(ValueError):
        _ = engine.decrypt_bytes(tampered, rsa_private, pq_private)


def test_wrong_key_fails() -> None:
    rsa_private, rsa_public = generate_rsa_keypair()
    wrong_rsa_private, _ = generate_rsa_keypair()
    pq_public, pq_private = TestKEM().generate_keypair()
    engine = HybridCryptoEngine(TestKEM())

    payload = engine.encrypt_bytes(b"hello", rsa_public, pq_public)

    with pytest.raises(ValueError):
        _ = engine.decrypt_bytes(payload, wrong_rsa_private, pq_private)

    assert rsa_private != wrong_rsa_private


def test_invalid_tag_fails() -> None:
    rsa_private, rsa_public = generate_rsa_keypair()
    pq_public, pq_private = TestKEM().generate_keypair()
    engine = HybridCryptoEngine(TestKEM())

    payload = engine.encrypt_bytes(b"hello", rsa_public, pq_public)
    tampered = HybridPayload(
        version=payload.version,
        iv=payload.iv,
        ciphertext=payload.ciphertext,
        tag=_flip_first_byte(payload.tag),
        rsa_wrapped_key=payload.rsa_wrapped_key,
        pq_ciphertext=payload.pq_ciphertext,
    )
    with pytest.raises(ValueError):
        _ = engine.decrypt_bytes(tampered, rsa_private, pq_private)
