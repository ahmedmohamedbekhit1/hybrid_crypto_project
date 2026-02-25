from __future__ import annotations

import secrets

import pytest

from hybrid_crypto_project.core.symmetric.aes_gcm import AESGCMCipher


def test_aes_encrypt_decrypt_round_trip() -> None:
    key = AESGCMCipher.generate_key()
    iv = AESGCMCipher.generate_iv()
    plaintext = secrets.token_bytes(1024)

    ciphertext, tag = AESGCMCipher.encrypt(key, iv, plaintext)
    recovered = AESGCMCipher.decrypt(key, iv, ciphertext, tag)

    assert recovered == plaintext


def test_aes_invalid_tag_fails() -> None:
    key = AESGCMCipher.generate_key()
    iv = AESGCMCipher.generate_iv()
    ciphertext, tag = AESGCMCipher.encrypt(key, iv, b"message")
    bad_tag = bytes([tag[0] ^ 0x01]) + tag[1:]

    with pytest.raises(ValueError, match="authentication"):
        AESGCMCipher.decrypt(key, iv, ciphertext, bad_tag)
