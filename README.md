# Hybrid Cryptography Project

## Overview

This repository provides a Hybrid Cryptography command-line tool that combines
classical RSA, AES-256-GCM for authenticated encryption, and a pluggable
post-quantum KEM adapter. A secure mock adapter is available for development
when a native PQ backend is not installed.

## Architecture Overview

- `core/` — All cryptographic primitives and core logic.
- `cli.py` and `main.py` — Command-line entry points.
- `manage.py` — Project controller for developer tasks and automation.
- Packaging via `pyproject.toml` and editable install support.

The design intentionally separates cryptographic concerns (core) from the CLI
and operational tooling (manage.py) to support audits and secure reviews.

## Hybrid Encryption Design

Encryption flow:

1. Generate a 256-bit AES session key using a CSPRNG.
2. Encrypt payloads with AES-256-GCM to provide confidentiality and authenticity.
3. Protect the AES key with multiple key-wrapping mechanisms:
   - RSA-2048 with OAEP (SHA-256)
   - Post-quantum KEM (Kyber) via a pluggable adapter; if unavailable a secure
     X25519+HKDF mock adapter is used for testing.
4. Store a JSON bundle containing ciphertext, IV, and wrapped-key versions.

Decryption reverses the process: recover AES key from one of the wrappers and
use AES-GCM to recover plaintext, validating authentication tags.

## Post-Quantum Migration Strategy

- A pluggable KEM interface (`core.post_quantum.base.KEMAdapter`) isolates
  PQ logic.
- `core.post_quantum.factory.get_kem_adapter()` selects the Kyber adapter when
  `oqs` is available; otherwise it returns a secure mock adapter.
- Real-world migration: generate and retain both classical and PQ key-wrappings
  for a period of overlap. Rotate keys and verify decryption using both
  classical and PQ channels before retiring classical keys.

## Installation

Prerequisites: Python 3.11+ and `pip`.

Install runtime dependencies:

```bash
python -m pip install -r requirements.txt
```

Install editable package (recommended):

```bash
pip install -e .
```

Post-quantum backend (recommended and required for post-quantum security):

```bash
# Install the PQ extras to enable Kyber/liboqs support (required for PQ security):
pip install ".[pq]"
```

## Virtual Environment Setup

Create and activate a virtual environment, then install runtime dependencies and the package in editable mode:

```bash

##  Commands

- `make generate` — generate RSA (and PQ if available) keypairs into `keys/`.
- `make encrypt file=<path> [out=<path>]` — encrypt a file (default `out` is `<file>.enc`).
- `make decrypt file=<path> out=<path> [pq_priv=<path>]` — decrypt a file; `out` is required.
- `make generate` — generate RSA and PQ keypairs into `keys/` (PQ adapter must be available or the secure mock will be used for development).
- `make encrypt file=<path> [out=<path>]` — encrypt a file (default `out` is `<file>.enc`). PQ public key (`keys/pq_public.bin`) is required.
- `make decrypt file=<path> out=<path> pq_priv=<path>` — decrypt a file; `out` and `pq_priv` (path to PQ private key) are required.



CLI Usage Examples

CLI Usage

Quick start (create keys, encrypt, decrypt):

```bash
# 1) Generate keys (creates keys/ directory)
make generate

# 2) Encrypt a file (default out is <file>.enc when omitted)
make encrypt file=plaintext.txt
# or specify output name
make encrypt file=plaintext.txt out=encrypted.bundle

# 3) Decrypt (out is required)
# 3) Decrypt (out and PQ private key are required)
make decrypt file=encrypted.bundle out=recovered.txt pq_priv=keys/pq_private.bin
```

Notes:
- `make encrypt` will default `out` to `file`.enc when `out` is not provided.
- `make decrypt` requires an explicit `out` path. If you need PQ decapsulation
  and have the PQ private key file, pass `pq_priv` to the make target:

```bash
make decrypt file=encrypted.bundle out=recovered.txt pq_priv=keys/pq_private.bin
```
Notes:
- `make encrypt` will default `out` to `file`.enc when `out` is not provided. PQ public key must exist in `keys/pq_public.bin`.
- `make decrypt` requires an explicit `out` path and the PQ private key file. Pass `pq_priv` to the make target:

```bash
make decrypt file=encrypted.bundle out=recovered.txt pq_priv=keys/pq_private.bin
```

Direct module entrypoint usage

You can also run the packaged CLI directly via Python's `-m` entrypoint:

```bash
python -m hybrid_crypto_project.main --generate-keys
python -m hybrid_crypto_project.main --encrypt plaintext.txt --out encrypted.bundle
python -m hybrid_crypto_project.main --decrypt encrypted.bundle --out recovered.txt
python -m hybrid_crypto_project.main --backend-info
```

Verification

After decrypting, verify the recovered file matches the original. Example using Python:

```bash
python - <<'PY'
from pathlib import Path
orig = Path('plaintext.txt').read_bytes()
rec = Path('recovered.txt').read_bytes()
print('match' if orig==rec else 'mismatch')
PY
```

## Security Considerations

- Uses `secrets` for CSPRNG and pyca/cryptography for primitives.
- RSA uses 2048-bit keys with OAEP(SHA-256) padding.
- Symmetric encryption is AES-256-GCM with 12-byte nonces.
- PQ adapter is required for true post-quantum security; install the `.[pq]` extras to enable Kyber/liboqs support.
- Private keys are saved with restrictive permissions where supported.
- Sensitive material is never printed to logs.

## Limitations

- The provided mock PQ adapter is NOT post-quantum secure; it exists for
  development and testing only. For production use and real post-quantum
  security you must install and enable the Kyber/liboqs adapter (see
  the Installation section and install `.[pq]`).
- The simple wrapped-key format in the JSON bundle is for demonstration. A
  production system should use a canonical binary format, versioning, and
  signed metadata.

## Future Work

- Add authenticated metadata and signatures for bundle integrity.
- Implement key rotation tools, secure key storage/HSM integration.
- Add end-to-end tests and CI pipeline with fuzzing for malformed inputs.

## License

This project is released under the MIT License.
