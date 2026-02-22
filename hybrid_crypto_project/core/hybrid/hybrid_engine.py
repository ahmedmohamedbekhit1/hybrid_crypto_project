"""Hybrid encryption engine combining RSA, PQ-KEM and AES-GCM.

This module implements the high-level flows for encrypting and decrypting files
with multiple key-wrapping backends (RSA and a pluggable PQ KEM).
"""
from __future__ import annotations

from typing import Dict, Any, Optional, Tuple
import json
import base64
from pathlib import Path

from ..symmetric.aes_gcm import AESGCMCipher
from ..classical.rsa import RSAKeyManager
from ..post_quantum.factory import get_kem_adapter
from ..utils.file_handler import safe_path
from ..utils.logger import get_logger

logger = get_logger(__name__)


class HybridEngine:
    """Perform hybrid encryption and decryption on files.

    Encrypted payload format (JSON):
    {
      "version": 1,
      "iv": base64,
      "ciphertext": base64,
      "wrappings": {
          "rsa": base64,     # RSA-encrypted AES key
          "pq": base64       # KEM encapsulation ciphertext
      }
    }
    """

    VERSION = 1

    def __init__(
        self,
        rsa_pub_pem: bytes | None = None,
        rsa_key_manager: RSAKeyManager | None = None,
        pq_pub: bytes | None = None,
    ) -> None:
        self.rsa_pub_pem = rsa_pub_pem
        self.rsa_key_manager = rsa_key_manager
        self.pq_pub = pq_pub
        self._KEM = get_kem_adapter()()

    def encrypt_file(self, src: str, dst: str) -> None:
        src_path = safe_path(src)
        dst_path = safe_path(dst)
        data = Path(src_path).read_bytes()

        # 1) generate AES key and encrypt file
        aes_key = AESGCMCipher.generate_key()
        iv, ciphertext = AESGCMCipher.encrypt(aes_key, data)

        # 2) RSA wrap AES key if public key provided
        wrappings: Dict[str, str] = {}
        if self.rsa_pub_pem:
            pub = RSAKeyManager.load_public(self.rsa_pub_pem)
            rsa_ct = RSAKeyManager().encrypt(aes_key, pub)
            wrappings["rsa"] = base64.b64encode(rsa_ct).decode("ascii")
        # 3) PQ KEM wrap (PQ public key is mandatory)
        if self.pq_pub is None:
            raise ValueError("PQ public key is required for encryption")
        ct, ss = self._KEM.encapsulate(self.pq_pub)
        # Use KEM shared secret to encrypt the AES key (XOR or KDF advised); here we use HKDF to derive a key
        # For simplicity derive 32 bytes and XOR -- secure KDF use should be implemented by caller for production.
        # We'll derive using HKDF to produce a 32-byte mask
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes

        mask = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"hybrid-aes-mask").derive(ss)
        wrapped = bytes(a ^ b for a, b in zip(aes_key, mask))
        wrappings["pq"] = base64.b64encode(ct + wrapped).decode("ascii")

        payload: Dict[str, Any] = {
            "version": self.VERSION,
            "iv": base64.b64encode(iv).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "wrappings": wrappings,
        }

        Path(dst_path).write_bytes(json.dumps(payload).encode("utf-8"))
        logger.info(
            "File encrypted: %s -> %s; pq_present=%s; rsa_included=%s",
            src_path,
            dst_path,
            self.pq_pub is not None,
            self.rsa_pub_pem is not None,
        )

    def decrypt_file(self, src: str, dst: str, pq_private: bytes) -> None:
        src_path = safe_path(src)
        dst_path = safe_path(dst)
        raw = Path(src_path).read_bytes()
        payload = json.loads(raw.decode("utf-8"))

        iv = base64.b64decode(payload["iv"])
        ciphertext = base64.b64decode(payload["ciphertext"])

        # PQ decapsulation is mandatory. Do not allow RSA-only fallback.
        if "pq" not in payload.get("wrappings", {}):
            raise ValueError("PQ wrapping missing from payload; cannot decrypt without PQ")

        if pq_private is None:
            raise ValueError("pq_private is required to decapsulate PQ wrapping")

        raw_wr = base64.b64decode(payload["wrappings"]["pq"])
        # Split ciphertext and wrapped key: wrapped key length == AES key size
        ct_len = len(raw_wr) - AESGCMCipher.KEY_SIZE
        if ct_len <= 0:
            raise ValueError("Invalid PQ wrapping format")
        ct = raw_wr[:ct_len]
        wrapped = raw_wr[ct_len:]

        ss = self._KEM.decapsulate(ct, pq_private)
        from cryptography.hazmat.primitives.kdf.hkdf import HKDF
        from cryptography.hazmat.primitives import hashes

        mask = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"hybrid-aes-mask").derive(ss)
        aes_key = bytes(a ^ b for a, b in zip(wrapped, mask))

        plaintext = AESGCMCipher.decrypt(aes_key, iv, ciphertext)
        Path(dst_path).write_bytes(plaintext)
        logger.info("File decrypted: %s -> %s; pq_used=True; rsa_present=%s", src_path, dst_path, self.rsa_key_manager is not None)
