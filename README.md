# Hybrid Crypto Project

Production-ready hybrid encryption CLI that combines:

- AES-256-GCM for authenticated data encryption
- RSA-OAEP (SHA-256) for classical key wrapping
- Kyber768 (via liboqs/python-oqs) for post-quantum KEM

Decryption requires both RSA and PQ material. Classical-only fallback is intentionally disabled.

## Security Model

For each encryption:

1. Generate fresh AES key and IV
2. Encrypt plaintext with AES-256-GCM
3. Wrap AES key with RSA-OAEP
4. Encapsulate with Kyber768 to obtain PQ ciphertext and shared secret
5. Serialize everything into HQF payload format

During decryption, plaintext is returned only after successful Kyber decapsulation and RSA unwrapping.

## Project Layout

```text
hybrid_crypto_project/
  cli.py
  config.py
  main.py
  core/
    classical/
    hybrid/
    post_quantum/
    storage/
    symmetric/
  scripts/
tests/
```

## Prerequisites

- Python 3.12+
- Windows with Visual Studio 2022 Build Tools (for local liboqs build)

## Quick Start

```bash
make install
make run
```

`make install` creates `.venv`, installs dependencies, installs local `liboqs-python`, and builds local `liboqs` runtime into `_oqs_install`.

## CLI Commands

- `generate-keys` : generate RSA + Kyber keys in `keys/`
- `encrypt <source>` : produce `<source>.hqf`
- `decrypt <source.hqf>` : recover plaintext output
- `upload-s3 <local_file> <bucket> <object_key>`
- `download-s3 <bucket> <object_key> <local_file>`
- `benchmark [--iterations N] [--size-kb N]`

Run interactive mode with:

```bash
make run
```

## HQF Payload Format

Encrypted output is stored as `.hqf`:

- Magic prefix: `HQF1\n`
- JSON payload with:
  - `format = "hybrid_crypto_project.hqf"`
  - `version`
  - `iv`, `ciphertext`, `tag`
  - `rsa_wrapped_key`
  - `pq_ciphertext`

## AWS S3 Configuration

Environment variables:

```bash
set AWS_ACCESS_KEY_ID=...
set AWS_SECRET_ACCESS_KEY=...
set AWS_DEFAULT_REGION=eu-central-1
set HYBRID_AWS_KMS_KEY_ID=arn:aws:kms:...   # optional
```

If `HYBRID_AWS_KMS_KEY_ID` is set, uploads use KMS server-side encryption.

## Development Commands

- `make check` : mypy + ruff
- `make test` : pytest suite
- `make benchmark` : local performance benchmark
- `make clean` : remove venv and cache artifacts

## Notes

- This implementation enforces mandatory post-quantum participation.
- Local `liboqs` source alone is not enough; Python bindings (`oqs`) must be installed in the virtual environment.
