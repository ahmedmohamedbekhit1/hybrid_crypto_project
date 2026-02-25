from __future__ import annotations

import pytest

from hybrid_crypto_project.core.classical.rsa import (
    generate_rsa_keypair,
    rsa_unwrap_key,
    rsa_wrap_key,
)


def test_rsa_wrap_unwrap_round_trip() -> None:
    private_pem, public_pem = generate_rsa_keypair()
    key = b"k" * 32
    wrapped = rsa_wrap_key(public_pem, key)
    unwrapped = rsa_unwrap_key(private_pem, wrapped)
    assert unwrapped == key


def test_rsa_wrong_private_key_fails() -> None:
    private_pem, public_pem = generate_rsa_keypair()
    other_private, _ = generate_rsa_keypair()
    wrapped = rsa_wrap_key(public_pem, b"z" * 32)

    with pytest.raises(ValueError):
        _ = rsa_unwrap_key(other_private, wrapped)

    assert private_pem != other_private
