from __future__ import annotations

import json

import pytest

from hybrid_crypto_project.core.hybrid.payload import HQF_MAGIC, HybridPayload


def test_hqf_container_prefix_and_round_trip() -> None:
    payload = HybridPayload(
        version="1.0",
        iv=b"\x00" * 12,
        ciphertext=b"ciphertext",
        tag=b"\x11" * 16,
        rsa_wrapped_key=b"rsa",
        pq_ciphertext=b"pq",
    )

    blob = payload.to_json_bytes()
    assert blob.startswith(HQF_MAGIC)

    parsed = HybridPayload.from_json_bytes(blob)
    assert parsed == payload


def test_rejects_wrong_hqf_format_field() -> None:
    payload = HybridPayload(
        version="1.0",
        iv=b"\x00" * 12,
        ciphertext=b"ciphertext",
        tag=b"\x11" * 16,
        rsa_wrapped_key=b"rsa",
        pq_ciphertext=b"pq",
    )

    blob = payload.to_json_bytes()
    raw = json.loads(blob[len(HQF_MAGIC) :].decode("utf-8"))
    raw["format"] = "other.project"
    tampered = HQF_MAGIC + json.dumps(raw, separators=(",", ":")).encode("utf-8")

    with pytest.raises(ValueError, match="Invalid HQF container format"):
        HybridPayload.from_json_bytes(tampered)
