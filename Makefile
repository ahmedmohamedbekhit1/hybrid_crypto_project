PYTHON := .venv\Scripts\python.exe
OQS_PY_PATH ?= liboqs-python

.PHONY: install install-oqs-local check run test benchmark clean help
.PHONY: build-liboqs-local

install:
	python -m venv .venv
	$(PYTHON) -m pip install --upgrade pip
	$(PYTHON) -m pip install -r requirements.txt
	$(PYTHON) -m pip install -r requirements-dev.txt
	$(PYTHON) -m pip install cmake ninja
	$(PYTHON) -m pip install -e .
	$(MAKE) install-oqs-local OQS_PY_PATH=$(OQS_PY_PATH)
	$(MAKE) build-liboqs-local

install-oqs-local:
	@$(PYTHON) -c "from pathlib import Path; import subprocess, sys; target = Path('$(OQS_PY_PATH)').resolve(); pip = Path('.venv/Scripts/pip.exe').resolve(); ok = target.exists() and ((target/'pyproject.toml').exists() or (target/'setup.py').exists()); ok or sys.exit('Local oqs bindings path invalid. Use: make install-oqs-local OQS_PY_PATH=PATH'); subprocess.check_call([str(pip), 'install', str(target)])"

build-liboqs-local:
	@$(PYTHON) -c "import os, subprocess, pathlib; root = pathlib.Path('.').resolve(); install_prefix = root / '_oqs_install'; dll = install_prefix / 'bin' / 'oqs.dll'; dll.exists() and print('liboqs already built; skipping rebuild.') or (lambda: (subprocess.check_call([str(root / '.venv' / 'Scripts' / 'cmake.exe'), '-S', str(root / 'liboqs'), '-B', str(root / '_liboqs_build'), '-G', 'Visual Studio 17 2022', '-A', 'x64', '-DBUILD_SHARED_LIBS=ON', '-DOQS_BUILD_ONLY_LIB=ON', f'-DCMAKE_INSTALL_PREFIX={install_prefix}'], env={**os.environ, 'PATH': str(root / '.venv' / 'Scripts') + ';' + os.environ.get('PATH', '')}), subprocess.check_call([str(root / '.venv' / 'Scripts' / 'cmake.exe'), '--build', str(root / '_liboqs_build'), '--config', 'Release'], env={**os.environ, 'PATH': str(root / '.venv' / 'Scripts') + ';' + os.environ.get('PATH', '')}), subprocess.check_call([str(root / '.venv' / 'Scripts' / 'cmake.exe'), '--install', str(root / '_liboqs_build'), '--config', 'Release'], env={**os.environ, 'PATH': str(root / '.venv' / 'Scripts') + ';' + os.environ.get('PATH', '')}), print('liboqs build/install completed.')))()"

check:
	$(PYTHON) -m mypy --config-file mypy.ini hybrid_crypto_project tests benchmark.py
	$(PYTHON) -m ruff check hybrid_crypto_project tests benchmark.py

run:
	@python -c "from pathlib import Path; import subprocess, sys; py = Path('.venv/Scripts/python.exe'); pip = Path('.venv/Scripts/pip.exe'); py.exists() or subprocess.check_call([sys.executable, '-m', 'venv', '.venv']); subprocess.call([str(py), '-c', 'import typer']) == 0 or subprocess.check_call([str(pip), 'install', 'typer>=0.15.1'])"
	@$(PYTHON) -c "import os, runpy; root = os.getcwd(); os.environ['PATH'] = os.path.join(root, '.venv', 'Scripts') + ';' + os.path.join(root, '_oqs_install', 'bin') + ';' + os.environ.get('PATH', ''); os.environ.setdefault('OQS_INSTALL_PATH', os.path.join(root, '_oqs_install')); runpy.run_module('hybrid_crypto_project.main', run_name='__main__')"

test:
	$(PYTHON) -m pytest -q

benchmark:
	$(PYTHON) -m hybrid_crypto_project.main benchmark --iterations 10 --size-kb 64

clean:
	-$(PYTHON) -c "import pathlib, shutil; root = pathlib.Path('.'); shutil.rmtree('.venv', ignore_errors=True); [shutil.rmtree(p, ignore_errors=True) for p in root.rglob('__pycache__')]; [p.unlink() for p in root.rglob('*.pyc') if p.exists()]"

help:
	@echo Available commands:
	@echo   make install    - Full setup: venv, dependencies, oqs bindings, local liboqs build
	@echo   make check      - Run strict mypy and ruff lint checks
	@echo   make run        - Launch interactive Typer CLI
	@echo   make test       - Run pytest suite
	@echo   make benchmark  - Run benchmark command
	@echo   make clean      - Remove .venv and caches
	@echo   make help       - Show this help text