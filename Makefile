# Makefile - professional version

.PHONY: generate encrypt decrypt  help

# Generate RSA (and PQ if available) keypairs
generate:
	python -c "from hybrid_crypto_project import cli; cli.cmd_generate_keys()"

# Encrypt: requires `file` and `out` variables
encrypt:
ifndef file
	$(error file variable is required. Usage: make encrypt file=<path> [out=<path>])
endif
ifeq ($(strip $(out)),)
	$(eval out=$(file).enc)
endif
	python -c "from hybrid_crypto_project import cli; cli.cmd_encrypt('$(file)', '$(out)')"

# Decrypt: requires `file`, `out`, and `pq_priv` (PQ private key path required).
decrypt:
ifndef file
	$(error file variable is required. Usage: make decrypt file=<path> out=<path> [pq_priv=<path>])
endif
ifndef out
	$(error out variable is required. Usage: make decrypt file=<path> out=<path> [pq_priv=<path>])
endif

ifndef pq_priv
	$(error pq_priv variable is required. Usage: make decrypt file=<path> out=<path> pq_priv=<path>)
endif
	python -c "from hybrid_crypto_project import cli; cli.cmd_decrypt('$(file)', '$(out)', pq_priv='$(pq_priv)')"


# Friendly help menu
help:
	@echo "Hybrid Crypto CLI - Makefile Commands"
	@echo ""
	@echo "  make generate                         # Generate RSA and PQ keypairs (writes to keys/)"
	@echo "  make encrypt file=<path> [out=<path>]    # Encrypt a file; default out is <file>.enc"
	@echo "  make decrypt file=<path> out=<path> pq_priv=<path>    # Decrypt a file (PQ private key required)"
	@echo "  make help                             # Show this help menu"