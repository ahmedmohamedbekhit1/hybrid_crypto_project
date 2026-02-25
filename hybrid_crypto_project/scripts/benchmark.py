"""Benchmark utilities for the hybrid cryptography engine."""
from __future__ import annotations

import secrets
import statistics
import time

from hybrid_crypto_project.core.hybrid.hybrid_engine import HybridCryptoEngine
from hybrid_crypto_project.core.post_quantum.factory import get_mandatory_kem_adapter


def run_benchmark(
    iterations: int,
    plaintext_size_kb: int,
    rsa_public_pem: bytes,
    rsa_private_pem: bytes,
    pq_public_key: bytes,
    pq_private_key: bytes,
) -> str:
    """Run benchmark and return formatted report."""
    if iterations <= 0:
        raise ValueError("iterations must be greater than zero")
    if plaintext_size_kb <= 0:
        raise ValueError("plaintext_size_kb must be greater than zero")

    engine = HybridCryptoEngine(get_mandatory_kem_adapter())
    plaintext = secrets.token_bytes(plaintext_size_kb * 1024)

    enc_times_ms: list[float] = []
    dec_times_ms: list[float] = []

    for _ in range(iterations):
        start_enc = time.perf_counter()
        payload = engine.encrypt_bytes(plaintext, rsa_public_pem, pq_public_key)
        end_enc = time.perf_counter()

        start_dec = time.perf_counter()
        recovered = engine.decrypt_bytes(payload, rsa_private_pem, pq_private_key)
        end_dec = time.perf_counter()

        if recovered != plaintext:
            raise ValueError("benchmark integrity check failed")

        enc_times_ms.append((end_enc - start_enc) * 1000)
        dec_times_ms.append((end_dec - start_dec) * 1000)

    enc_p95 = (
        max(enc_times_ms)
        if len(enc_times_ms) < 2
        else statistics.quantiles(enc_times_ms, n=20)[18]
    )
    dec_p95 = (
        max(dec_times_ms)
        if len(dec_times_ms) < 2
        else statistics.quantiles(dec_times_ms, n=20)[18]
    )

    return (
        "Hybrid Benchmark Report\n"
        f"Iterations: {iterations}\n"
        f"Payload size: {plaintext_size_kb} KB\n"
        f"Encrypt mean (ms): {statistics.mean(enc_times_ms):.3f}\n"
        f"Encrypt p95 (ms): {enc_p95:.3f}\n"
        f"Decrypt mean (ms): {statistics.mean(dec_times_ms):.3f}\n"
        f"Decrypt p95 (ms): {dec_p95:.3f}"
    )
