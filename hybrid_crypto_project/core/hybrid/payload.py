"""Payload model for hybrid encrypted bundles."""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass


def _b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("ascii"), validate=True)


HQF_MAGIC = b"HQF1\n"
HQF_FORMAT = "hybrid_crypto_project.hqf"


@dataclass(frozen=True)
class HybridPayload:
    """Structured payload for encrypted content."""

    version: str
    iv: bytes
    ciphertext: bytes
    tag: bytes
    rsa_wrapped_key: bytes
    pq_ciphertext: bytes

    def to_json_bytes(self) -> bytes:
        data = {
            "format": HQF_FORMAT,
            "version": self.version,
            "iv": _b64e(self.iv),
            "ciphertext": _b64e(self.ciphertext),
            "tag": _b64e(self.tag),
            "rsa_wrapped_key": _b64e(self.rsa_wrapped_key),
            "pq_ciphertext": _b64e(self.pq_ciphertext),
        }
        return HQF_MAGIC + json.dumps(data, separators=(",", ":")).encode("utf-8")

    @classmethod
    def from_json_bytes(cls, blob: bytes) -> HybridPayload:
        payload_blob = blob
        if blob.startswith(HQF_MAGIC):
            payload_blob = blob[len(HQF_MAGIC) :]

        raw = json.loads(payload_blob.decode("utf-8"))
        if not isinstance(raw, dict):
            raise ValueError("Invalid payload object")
        if "format" in raw and str(raw["format"]) != HQF_FORMAT:
            raise ValueError("Invalid HQF container format")
        return cls(
            version=str(raw["version"]),
            iv=_b64d(str(raw["iv"])),
            ciphertext=_b64d(str(raw["ciphertext"])),
            tag=_b64d(str(raw["tag"])),
            rsa_wrapped_key=_b64d(str(raw["rsa_wrapped_key"])),
            pq_ciphertext=_b64d(str(raw["pq_ciphertext"])),
        )