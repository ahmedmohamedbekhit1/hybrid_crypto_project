"""Kyber768 KEM adapter backed by liboqs."""
from __future__ import annotations

import contextlib
import importlib
import io
import logging
import os
import sys
from pathlib import Path
from typing import Protocol, cast

from .base import KEMAdapter


class PQUnavailableError(RuntimeError):
    """Raised when liboqs is unavailable or unsupported."""


class _KEMContext(Protocol):
    def __enter__(self) -> _KEMContext: ...

    def __exit__(self, exc_type: object, exc: object, tb: object) -> None: ...

    def generate_keypair(self) -> bytes: ...

    def export_secret_key(self) -> bytes: ...

    def encap_secret(self, public_key: bytes) -> tuple[bytes, bytes]: ...

    def import_secret_key(self, private_key: bytes) -> None: ...

    def decap_secret(self, ciphertext: bytes) -> bytes: ...


class _OQSModule(Protocol):
    def get_enabled_kem_mechanisms(self) -> list[str]: ...

    def KeyEncapsulation(  # noqa: N802
        self,
        algorithm: str,
        secret_key: bytes | None = None,
    ) -> _KEMContext: ...


class Kyber768Adapter(KEMAdapter):
    """Real post-quantum KEM adapter using Kyber768 via liboqs."""

    _ALGORITHM = "Kyber768"

    def __init__(self) -> None:
        oqs_module = self._import_oqs()
        self._ensure_supported(oqs_module)

    @property
    def algorithm(self) -> str:
        return self._ALGORITHM

    @staticmethod
    def _candidate_local_paths() -> list[Path]:
        repo_root = Path(__file__).resolve().parents[3]
        return [
            repo_root / "liboqs-python",
            repo_root / "liboqs" / "python",
            repo_root / "liboqs" / "bindings" / "python",
            repo_root / "liboqs",
        ]

    @staticmethod
    def _quiet_import_oqs_module() -> object:
        previous_disable_level = logging.root.manager.disable
        logging.disable(logging.CRITICAL)
        try:
            with contextlib.redirect_stdout(io.StringIO()):
                with contextlib.redirect_stderr(io.StringIO()):
                    return importlib.import_module("oqs")
        finally:
            logging.disable(previous_disable_level)

    @classmethod
    def _import_oqs(cls) -> _OQSModule:
        repo_root = Path(__file__).resolve().parents[3]
        oqs_install_path = repo_root / "_oqs_install"
        os.environ.setdefault("OQS_INSTALL_PATH", str(oqs_install_path))

        path_entries = os.environ.get("PATH", "")
        venv_scripts = str(repo_root / ".venv" / "Scripts")
        oqs_bin = str(oqs_install_path / "bin")
        for entry in [venv_scripts, oqs_bin]:
            if entry and entry not in path_entries:
                path_entries = f"{entry};{path_entries}"
        os.environ["PATH"] = path_entries

        try:
            oqs_module = cls._quiet_import_oqs_module()
        except Exception:
            for path in cls._candidate_local_paths():
                if path.exists():
                    as_str = str(path)
                    if as_str not in sys.path:
                        sys.path.insert(0, as_str)
            try:
                oqs_module = cls._quiet_import_oqs_module()
            except Exception as retry_exc:
                message = (
                    "liboqs/python-oqs is not installed or failed to load. "
                    "Local liboqs source was detected, but Python bindings module `oqs` "
                    "is unavailable. The `liboqs` C source folder alone is not enough; "
                    "install local liboqs-python bindings into the venv."
                )
                raise PQUnavailableError(message) from retry_exc
        return cast(_OQSModule, oqs_module)

    def _ensure_supported(self, oqs_module: _OQSModule) -> None:
        enabled = oqs_module.get_enabled_kem_mechanisms
        mechanisms = enabled()
        if self._ALGORITHM not in mechanisms:
            raise PQUnavailableError(
                f"Required KEM algorithm {self._ALGORITHM} is not enabled in liboqs"
            )

    def generate_keypair(self) -> tuple[bytes, bytes]:
        oqs_module = self._import_oqs()
        self._ensure_supported(oqs_module)
        key_encapsulation = oqs_module.KeyEncapsulation
        with key_encapsulation(self._ALGORITHM) as kem:
            public_key = kem.generate_keypair()
            private_key = kem.export_secret_key()
        return public_key, private_key

    def encapsulate(self, public_key: bytes) -> tuple[bytes, bytes]:
        oqs_module = self._import_oqs()
        self._ensure_supported(oqs_module)
        key_encapsulation = oqs_module.KeyEncapsulation
        with key_encapsulation(self._ALGORITHM) as kem:
            ciphertext, shared_secret = kem.encap_secret(public_key)
        return ciphertext, shared_secret

    def decapsulate(self, ciphertext: bytes, private_key: bytes) -> bytes:
        oqs_module = self._import_oqs()
        self._ensure_supported(oqs_module)
        key_encapsulation = oqs_module.KeyEncapsulation
        with key_encapsulation(self._ALGORITHM, private_key) as kem:
            shared_secret = kem.decap_secret(ciphertext)
        return shared_secret
