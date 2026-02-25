"""CLI entrypoint module for hybrid_crypto_project (packaged).

When executed as a module (`python -m hybrid_crypto_project.main`) this
module will call `cli.main()` from the packaged CLI implementation.
"""
from __future__ import annotations


def _run() -> int:
    try:
        from .cli import main
    except ModuleNotFoundError as exc:
        if exc.name == "typer":
            print(
                "Missing dependency: typer. "
                "Run `make install` or `.venv/Scripts/pip install typer`."
            )
            return 1
        raise

    return main()


if __name__ == "__main__":
    raise SystemExit(_run())
