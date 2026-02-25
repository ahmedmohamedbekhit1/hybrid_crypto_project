"""Typer CLI for the production hybrid cryptography system."""
from __future__ import annotations

import os
import subprocess
import sys
import time
from collections.abc import Callable
from functools import partial
from pathlib import Path

import typer
from rich.console import Console

from . import config
from .core.classical.rsa import generate_rsa_keypair
from .core.hybrid.hybrid_engine import HybridCryptoEngine
from .core.post_quantum.factory import get_mandatory_kem_adapter
from .core.post_quantum.kyber_adapter import PQUnavailableError
from .core.storage.s3_client import S3OperationError, S3StorageClient

app = typer.Typer(add_completion=False, no_args_is_help=False)
console = Console()


def _ensure_local_oqs_runtime() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    install_prefix = repo_root / "_oqs_install"
    oqs_dll = install_prefix / "bin" / "oqs.dll"
    if oqs_dll.exists():
        return

    cmake_exe = repo_root / ".venv" / "Scripts" / "cmake.exe"
    liboqs_source = repo_root / "liboqs"
    build_dir = repo_root / "_liboqs_build"

    if not liboqs_source.exists():
        raise PQUnavailableError("Local liboqs source folder not found. Expected: ./liboqs")
    if not cmake_exe.exists():
        raise PQUnavailableError("cmake is missing in .venv. Run `make install` first.")

    env = os.environ.copy()
    env["PATH"] = str(repo_root / ".venv" / "Scripts") + ";" + env.get("PATH", "")

    typer.secho("Building local liboqs runtime (step 1/3: configure)...", fg=typer.colors.YELLOW)
    try:
        subprocess.check_call(
            [
                str(cmake_exe),
                "-S",
                str(liboqs_source),
                "-B",
                str(build_dir),
                "-G",
                "Visual Studio 17 2022",
                "-A",
                "x64",
                "-DBUILD_SHARED_LIBS=ON",
                "-DOQS_BUILD_ONLY_LIB=ON",
                f"-DCMAKE_INSTALL_PREFIX={install_prefix}",
            ],
            env=env,
        )

        typer.secho("Building local liboqs runtime (step 2/3: build)...", fg=typer.colors.YELLOW)
        subprocess.check_call(
            [str(cmake_exe), "--build", str(build_dir), "--config", "Release"],
            env=env,
        )

        typer.secho("Building local liboqs runtime (step 3/3: install)...", fg=typer.colors.YELLOW)
        subprocess.check_call(
            [str(cmake_exe), "--install", str(build_dir), "--config", "Release"],
            env=env,
        )
    except subprocess.CalledProcessError as exc:
        raise PQUnavailableError(
            "Local liboqs build failed. Run `make build-liboqs-local`."
        ) from exc

    if not oqs_dll.exists():
        raise PQUnavailableError("Local liboqs build completed but oqs.dll was not found.")

    typer.secho("Local liboqs runtime ready.", fg=typer.colors.GREEN)


def _run_with_loader(label: str, action: Callable[[], None]) -> None:
    succeeded = False
    try:
        with console.status(f"[cyan]{label}...[/cyan]", spinner="dots"):
            action()
        succeeded = True
    finally:
        status = "done" if succeeded else "failed"
        color = typer.colors.GREEN if succeeded else typer.colors.RED
        typer.secho(f"{label} {status}.", fg=color)


def _generate_pq_keys_with_progress() -> None:
    repo_root = Path(__file__).resolve().parent.parent
    env = os.environ.copy()
    env["PATH"] = (
        str(repo_root / ".venv" / "Scripts")
        + ";"
        + str(repo_root / "_oqs_install" / "bin")
        + ";"
        + env.get("PATH", "")
    )
    env.setdefault("OQS_INSTALL_PATH", str(repo_root / "_oqs_install"))

    script = (
        "from hybrid_crypto_project import config; "
        "from hybrid_crypto_project.core.post_quantum.factory import get_mandatory_kem_adapter; "
        "kem=get_mandatory_kem_adapter(); "
        "pub,priv=kem.generate_keypair(); "
        "config.PQ_PUBLIC_KEY_PATH.write_bytes(pub); "
        "config.PQ_PRIVATE_KEY_PATH.write_bytes(priv); "
        "print('Kyber keypair generated.')"
    )

    typer.secho("Loading Kyber adapter and generating keypair...", fg=typer.colors.YELLOW)
    process = subprocess.Popen(
        [sys.executable, "-c", script],
        cwd=str(repo_root),
        env=env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )

    while process.poll() is None:
        typer.echo("[progress] still working...")
        time.sleep(3)

    stdout, stderr = process.communicate()
    if stdout.strip():
        typer.echo(stdout.strip())

    if process.returncode != 0:
        detail = stderr.strip() or stdout.strip() or "Unknown error"
        raise PQUnavailableError(f"Kyber key generation failed: {detail}")


def _print_banner() -> None:
    typer.secho("", fg=typer.colors.CYAN)
    typer.secho("╔════════════════════════════════════════════════════╗", fg=typer.colors.CYAN)
    typer.secho("║         Hybrid Crypto Console (PQ Mandatory)      ║", fg=typer.colors.CYAN)
    typer.secho("╚════════════════════════════════════════════════════╝", fg=typer.colors.CYAN)
    typer.secho("Type help to view commands, or q to quit.", fg=typer.colors.BRIGHT_BLACK)


def _interactive_help() -> None:
    typer.secho("", fg=typer.colors.CYAN)
    typer.secho("Commands", fg=typer.colors.CYAN, bold=True)
    typer.secho("  help, h              Show this help", fg=typer.colors.BLUE)
    typer.secho("  generate-keys, gen   Generate RSA + Kyber768 keys", fg=typer.colors.BLUE)
    typer.secho("  encrypt, enc         Encrypt a local file", fg=typer.colors.BLUE)
    typer.secho("  decrypt, dec         Decrypt a local file", fg=typer.colors.BLUE)
    typer.secho("  upload-s3, up        Upload encrypted file to S3", fg=typer.colors.BLUE)
    typer.secho("  download-s3, down    Download encrypted file from S3", fg=typer.colors.BLUE)
    typer.secho("  benchmark, bench     Run local benchmark", fg=typer.colors.BLUE)
    typer.secho("  exit, quit, q        Exit interactive mode", fg=typer.colors.BLUE)


def _interactive_shell() -> None:
    commands = {
        "help",
        "h",
        "generate-keys",
        "gen",
        "encrypt",
        "enc",
        "decrypt",
        "dec",
        "upload-s3",
        "up",
        "download-s3",
        "down",
        "benchmark",
        "bench",
        "exit",
        "quit",
        "q",
    }

    _print_banner()
    while True:
        choice = typer.prompt("Command").strip().lower()
        if choice not in commands:
            typer.secho(
                f"Unknown command: {choice}. Type help to see available commands.",
                fg=typer.colors.RED,
                err=True,
            )
            continue

        if choice in {"exit", "quit", "q"}:
            typer.secho("Bye.", fg=typer.colors.GREEN)
            return

        try:
            if choice in {"help", "h"}:
                _interactive_help()
                continue

            if choice in {"generate-keys", "gen"}:
                generate_keys()
                continue

            if choice in {"encrypt", "enc"}:
                source = Path(typer.prompt("Source file"))
                _run_with_loader(
                    "Encrypting file",
                    partial(encrypt, source=source),
                )
                continue

            if choice in {"decrypt", "dec"}:
                source = Path(typer.prompt("Encrypted file"))
                _run_with_loader(
                    "Decrypting file",
                    partial(decrypt, source=source),
                )
                continue

            if choice in {"upload-s3", "up"}:
                local_file = Path(typer.prompt("Local file path"))
                bucket = typer.prompt("S3 bucket")
                object_key = typer.prompt("S3 object key")
                _run_with_loader(
                    "Uploading to S3",
                    partial(upload_s3, local_file=local_file, bucket=bucket, object_key=object_key),
                )
                continue

            if choice in {"download-s3", "down"}:
                bucket = typer.prompt("S3 bucket")
                object_key = typer.prompt("S3 object key")
                local_file = Path(typer.prompt("Local output file path"))
                _run_with_loader(
                    "Downloading from S3",
                    partial(
                        download_s3,
                        bucket=bucket,
                        object_key=object_key,
                        local_file=local_file,
                    ),
                )
                continue

            if choice in {"benchmark", "bench"}:
                iterations = int(typer.prompt("Iterations", default="10"))
                size_kb = int(typer.prompt("Payload size KB", default="64"))
                _run_with_loader(
                    "Running benchmark",
                    partial(benchmark, iterations=iterations, size_kb=size_kb),
                )
                continue
        except (PQUnavailableError, S3OperationError, typer.BadParameter, ValueError) as exc:
            typer.secho(f"Error: {exc}", fg=typer.colors.RED, err=True)
            continue
        except Exception as exc:
            typer.secho(f"Unexpected error: {exc}", fg=typer.colors.RED, err=True)
            continue


def _keys_ready() -> None:
    required = [
        config.RSA_PRIVATE_KEY_PATH,
        config.RSA_PUBLIC_KEY_PATH,
        config.PQ_PRIVATE_KEY_PATH,
        config.PQ_PUBLIC_KEY_PATH,
    ]
    missing = [str(path) for path in required if not path.exists()]
    if missing:
        message = f"Missing key files: {', '.join(missing)}. Run generate-keys first."
        raise typer.BadParameter(message)


def _default_encrypted_output(source: Path) -> Path:
    if source.suffix:
        return source.with_suffix(f"{source.suffix}.hqf")
    return Path(f"{source}.hqf")


def _default_decrypted_output(source: Path) -> Path:
    if source.suffix == ".hqf":
        return source.with_suffix("")
    if source.suffix:
        return source.with_suffix(f"{source.suffix}.dec")
    return Path(f"{source}.dec")


@app.callback(invoke_without_command=True)
def root(ctx: typer.Context) -> None:
    if ctx.invoked_subcommand is not None:
        return
    _interactive_shell()


@app.command("generate-keys")
def generate_keys() -> None:
    """Generate RSA and Kyber768 keypairs."""
    config.KEYS_DIR.mkdir(parents=True, exist_ok=True)
    private_pem, public_pem = generate_rsa_keypair()
    config.RSA_PRIVATE_KEY_PATH.write_bytes(private_pem)
    config.RSA_PUBLIC_KEY_PATH.write_bytes(public_pem)
    typer.secho("RSA keys generated.", fg=typer.colors.GREEN)

    typer.secho(
        "Initializing Kyber backend (first run may take several minutes)...",
        fg=typer.colors.YELLOW,
    )

    _ensure_local_oqs_runtime()

    _generate_pq_keys_with_progress()
    typer.secho("Keys generated successfully.", fg=typer.colors.GREEN)


@app.command("encrypt")
def encrypt(source: Path) -> None:
    """Encrypt local file using mandatory PQ + RSA hybrid mode."""
    _keys_ready()
    destination = _default_encrypted_output(source)
    engine = HybridCryptoEngine(get_mandatory_kem_adapter())
    engine.encrypt_file(
        str(source),
        str(destination),
        config.RSA_PUBLIC_KEY_PATH.read_bytes(),
        config.PQ_PUBLIC_KEY_PATH.read_bytes(),
    )
    typer.secho(f"Encrypted: {source} -> {destination}", fg=typer.colors.GREEN)


@app.command("decrypt")
def decrypt(source: Path) -> None:
    """Decrypt local file; PQ decapsulation is mandatory."""
    _keys_ready()
    if source.suffix != ".hqf":
        raise typer.BadParameter("Decrypt input must be a .hqf file.")
    destination = _default_decrypted_output(source)
    engine = HybridCryptoEngine(get_mandatory_kem_adapter())
    engine.decrypt_file(
        str(source),
        str(destination),
        config.RSA_PRIVATE_KEY_PATH.read_bytes(),
        config.PQ_PRIVATE_KEY_PATH.read_bytes(),
    )
    typer.secho(f"Decrypted: {source} -> {destination}", fg=typer.colors.GREEN)


@app.command("upload-s3")
def upload_s3(local_file: Path, bucket: str, object_key: str) -> None:
    """Upload an encrypted file to S3."""
    s3 = S3StorageClient(region_name=config.AWS_REGION)
    s3.upload_file(
        str(local_file),
        bucket,
        object_key,
        kms_key_id=config.AWS_KMS_KEY_ID,
    )
    typer.secho(f"Uploaded to s3://{bucket}/{object_key}", fg=typer.colors.GREEN)


@app.command("download-s3")
def download_s3(bucket: str, object_key: str, local_file: Path) -> None:
    """Download an encrypted file from S3."""
    s3 = S3StorageClient(region_name=config.AWS_REGION)
    s3.download_file(bucket, object_key, str(local_file))
    typer.secho(
        f"Downloaded: s3://{bucket}/{object_key} -> {local_file}",
        fg=typer.colors.GREEN,
    )


@app.command("benchmark")
def benchmark(iterations: int = 10, size_kb: int = 64) -> None:
    """Run local benchmark for hybrid encryption/decryption."""
    from .scripts.benchmark import run_benchmark

    _keys_ready()
    report = run_benchmark(
        iterations=iterations,
        plaintext_size_kb=size_kb,
        rsa_public_pem=config.RSA_PUBLIC_KEY_PATH.read_bytes(),
        rsa_private_pem=config.RSA_PRIVATE_KEY_PATH.read_bytes(),
        pq_public_key=config.PQ_PUBLIC_KEY_PATH.read_bytes(),
        pq_private_key=config.PQ_PRIVATE_KEY_PATH.read_bytes(),
    )
    typer.secho(report, fg=typer.colors.CYAN)


def main() -> int:
    try:
        app()
    except typer.Exit as exc:
        return int(exc.exit_code)
    except PQUnavailableError as exc:
        typer.echo(f"PQ error: {exc}", err=True)
        return 2
    except S3OperationError as exc:
        typer.echo(f"S3 error: {exc}", err=True)
        return 3
    except ValueError as exc:
        typer.echo(f"Error: {exc}", err=True)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
