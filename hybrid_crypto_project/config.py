"""Runtime configuration values for the hybrid cryptosystem."""
from __future__ import annotations

import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
KEYS_DIR = Path(os.getenv("HYBRID_KEYS_DIR", PROJECT_ROOT / "keys"))

RSA_PRIVATE_KEY_PATH = KEYS_DIR / "rsa_private.pem"
RSA_PUBLIC_KEY_PATH = KEYS_DIR / "rsa_public.pem"
PQ_PRIVATE_KEY_PATH = KEYS_DIR / "pq_private.bin"
PQ_PUBLIC_KEY_PATH = KEYS_DIR / "pq_public.bin"

AWS_REGION = os.getenv("AWS_REGION")
AWS_S3_BUCKET = os.getenv("HYBRID_S3_BUCKET")
AWS_S3_PREFIX = os.getenv("HYBRID_S3_PREFIX", "")
AWS_KMS_KEY_ID = os.getenv("HYBRID_AWS_KMS_KEY_ID")
