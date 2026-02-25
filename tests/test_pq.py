from __future__ import annotations

import pytest

from hybrid_crypto_project.core.post_quantum.factory import get_mandatory_kem_adapter
from hybrid_crypto_project.core.post_quantum.kyber_adapter import PQUnavailableError


def test_pq_round_trip_if_available() -> None:
    try:
        kem = get_mandatory_kem_adapter()
        public_key, private_key = kem.generate_keypair()
    except PQUnavailableError:
        pytest.skip("liboqs not available in test environment")

    ciphertext, shared_secret_1 = kem.encapsulate(public_key)
    shared_secret_2 = kem.decapsulate(ciphertext, private_key)

    assert shared_secret_1 == shared_secret_2
