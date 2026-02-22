"""Command-line interface for hybrid_crypto_project."""
from __future__ import annotations

import argparse
from typing import Optional
from pathlib import Path

from .core.classical.rsa import RSAKeyManager
from .core.hybrid.hybrid_engine import HybridEngine
from .core.post_quantum.factory import get_kem_adapter
from .core.utils.logger import get_logger

logger = get_logger("cli")


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(prog="hybrid-crypto")
    sub = parser.add_subparsers(dest="cmd", required=True)

    sub.add_parser("--generate-keys", help="Generate RSA keys and PQ keys")

    enc = sub.add_parser("--encrypt", help="Encrypt a file")
    enc.add_argument("file", help="Path to plaintext file")
    enc.add_argument("--out", help="Output path for encrypted bundle", required=True)

    dec = sub.add_parser("--decrypt", help="Decrypt a file")
    dec.add_argument("file", help="Path to encrypted bundle")
    dec.add_argument("--out", help="Output path for plaintext file", required=True)
    dec.add_argument("--pq-priv", help="Path to PQ private key for decapsulation", required=True)

    sub.add_parser("--backend-info", help="Show available backends")

    return parser.parse_args()
def cmd_generate_keys() -> None:
    rsa_mgr = RSAKeyManager.generate()
    priv = rsa_mgr.private_key_bytes()
    pub = rsa_mgr.public_key_bytes()
    Path("keys").mkdir(exist_ok=True)
    Path("keys/rsa_private.pem").write_bytes(priv)
    Path("keys/rsa_public.pem").write_bytes(pub)
    logger.info("RSA keypair generated in 'keys' folder")

    Adapter = get_kem_adapter()
    adapter = Adapter()
    pubk, privk = adapter.generate_keypair()
    Path("keys/pq_public.bin").write_bytes(pubk)
    Path("keys/pq_private.bin").write_bytes(privk)
    logger.info("PQ keypair generated via %s", Adapter.__name__)

def cmd_encrypt(file: str, out: str) -> None:
    # Load mandatory PQ public key and optional RSA public key
    pq_pub = Path("keys/pq_public.bin").read_bytes()
    rsa_pub = None
    try:
        rsa_pub = Path("keys/rsa_public.pem").read_bytes()
    except Exception:
        rsa_pub = None

    engine = HybridEngine(rsa_pub_pem=rsa_pub, pq_pub=pq_pub)
    engine.encrypt_file(file, out)


def cmd_decrypt(file: str, out: str, pq_priv: Optional[str] = None, pq_priv_path: Optional[str] = None) -> None:
    # Accept either `pq_priv` (Makefile) or `pq_priv_path` (CLI); PQ private key is required
    pq_arg = pq_priv if pq_priv is not None else pq_priv_path
    if not pq_arg:
        raise ValueError("--pq-priv is required for decryption when PQ is mandatory")

    pq_priv = Path(pq_arg).read_bytes()

    # RSA private key is optional but not used as a fallback
    rsa_mgr = None
    try:
        rsa_priv = Path("keys/rsa_private.pem").read_bytes()
        rsa_mgr = RSAKeyManager.load_private(rsa_priv)
    except Exception:
        rsa_mgr = None

    engine = HybridEngine(rsa_key_manager=rsa_mgr, pq_pub=None)
    engine.decrypt_file(file, out, pq_private=pq_priv)


def cmd_backend_info() -> None:
    try:
        Adapter = get_kem_adapter()
        print(f"KEM Adapter: {Adapter.__name__}")
    except Exception as e:
        print("KEM Adapter: unavailable")
    print("RSA: available via cryptography")


def main() -> None:
    args = parse_args()
    if args.cmd == "--generate-keys":
        cmd_generate_keys()
    elif args.cmd == "--encrypt":
        cmd_encrypt(args.file, args.out)
    elif args.cmd == "--decrypt":
        cmd_decrypt(args.file, args.out, args.pq_priv)
    elif args.cmd == "--backend-info":
        cmd_backend_info()


if __name__ == "__main__":
    main()
