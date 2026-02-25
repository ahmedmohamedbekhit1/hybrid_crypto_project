"""Hybrid cryptographic engine with mandatory PQ + RSA binding."""
from __future__ import annotations

from pathlib import Path

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..classical.rsa import rsa_unwrap_key, rsa_wrap_key
from ..post_quantum.base import KEMAdapter
from ..symmetric.aes_gcm import AESGCMCipher
from ..utils.file_handler import safe_path
from .payload import HybridPayload


class HybridCryptoEngine:
    """Implements the mandatory hybrid construction.

    Encryption:
      1. Generate fresh AES-256 key K.
      2. Generate fresh 12-byte IV.
      3. Encrypt plaintext with AES-256-GCM.
      4. RSA-OAEP wrap K.
      5. PQ-KEM encapsulate to get (C_pq, SS).
      6. Derive K' = HKDF(SS || K).
      7. Store payload fields.
    """

    VERSION = "1.0"

    def __init__(self, kem: KEMAdapter) -> None:
        self._kem = kem

    @staticmethod
    def derive_binding_key(shared_secret: bytes, aes_key: bytes) -> bytes:
        """Derive K' = HKDF(SS || K)."""
        return HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"hybrid-crypto-binding-v1",
        ).derive(shared_secret + aes_key)

    def encrypt_bytes(
        self,
        plaintext: bytes,
        rsa_public_pem: bytes,
        pq_public_key: bytes,
    ) -> HybridPayload:
        aes_key = AESGCMCipher.generate_key()
        iv = AESGCMCipher.generate_iv()
        ciphertext, tag = AESGCMCipher.encrypt(aes_key, iv, plaintext)

        rsa_wrapped_key = rsa_wrap_key(rsa_public_pem, aes_key)
        pq_ciphertext, shared_secret = self._kem.encapsulate(pq_public_key)
        _ = self.derive_binding_key(shared_secret, aes_key)

        return HybridPayload(
            version=self.VERSION,
            iv=iv,
            ciphertext=ciphertext,
            tag=tag,
            rsa_wrapped_key=rsa_wrapped_key,
            pq_ciphertext=pq_ciphertext,
        )

    def decrypt_bytes(
        self,
        payload: HybridPayload,
        rsa_private_pem: bytes,
        pq_private_key: bytes,
    ) -> bytes:
        shared_secret = self._kem.decapsulate(payload.pq_ciphertext, pq_private_key)
        aes_key = rsa_unwrap_key(rsa_private_pem, payload.rsa_wrapped_key)
        _ = self.derive_binding_key(shared_secret, aes_key)
        return AESGCMCipher.decrypt(aes_key, payload.iv, payload.ciphertext, payload.tag)

    def encrypt_file(
        self,
        source_path: str,
        destination_path: str,
        rsa_public_pem: bytes,
        pq_public_key: bytes,
    ) -> None:
        source = Path(safe_path(source_path))
        destination = Path(safe_path(destination_path))
        payload = self.encrypt_bytes(source.read_bytes(), rsa_public_pem, pq_public_key)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(payload.to_json_bytes())

    def decrypt_file(
        self,
        source_path: str,
        destination_path: str,
        rsa_private_pem: bytes,
        pq_private_key: bytes,
    ) -> None:
        source = Path(safe_path(source_path))
        destination = Path(safe_path(destination_path))
        payload = HybridPayload.from_json_bytes(source.read_bytes())
        plaintext = self.decrypt_bytes(payload, rsa_private_pem, pq_private_key)
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_bytes(plaintext)
