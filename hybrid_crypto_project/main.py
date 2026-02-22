"""CLI entrypoint module for hybrid_crypto_project (packaged).

When executed as a module (`python -m hybrid_crypto_project.main`) this
module will call `cli.main()` from the packaged CLI implementation.
"""
from __future__ import annotations

from .cli import main


if __name__ == "__main__":
    main()
