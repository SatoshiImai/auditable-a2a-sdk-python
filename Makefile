PYTHON_VER			:= 3.14.7
VENV				:= $(PYTHON_VER)-aa2a
ACTIVATE			:= . ~/.pyenv/versions/$(VENV)/bin/activate

.DEFAULT_GOAL := help
.PHONY: help env/init env/destroy env/sync env/freeze test test/target walk lint format spec/sync spec/check clean __require_target__

help:
	@echo 'auditable-a2a-sdk (Python) — development commands'
	@echo ''
	@echo '  make env/init      Create the pyenv virtualenv ($(VENV)) and install the project + extras + dev deps'
	@echo '  make env/destroy   Remove the pyenv virtualenv'
	@echo '  make env/sync      Reinstall the project + extras + dev deps into the virtualenv'
	@echo '  make env/freeze    Show installed packages'
	@echo ''
	@echo '  make test          Run the test suite (unit + conformance vectors)'
	@echo '  make test/target   Run a specific test (TARGET=tests/test_audit_host.py)'
	@echo '  make lint          ruff check + ruff format --check + mypy (strict, from pyproject)'
	@echo '  make format        ruff format + ruff check --fix'
	@echo ''
	@echo '  make spec/check    Fail if the vendored spec/ drifted from its source'
	@echo '  make walk          Run the cross-language walk (CASE=<name> narrows it)'
	@echo '  make spec/sync     Re-vendor spec/ from ../auditable-a2a/spec'
	@echo ''
	@echo '  make clean         Remove caches and build artifacts'

# Environment: pyenv owns isolation, uv is the installer.
env/init:
	$(eval ret := $(shell pyenv versions | grep $(PYTHON_VER)))
	@if [ -n "$(ret)" ]; then \
		echo '$(PYTHON_VER) exists'; \
	else \
		(pyenv install -s $(PYTHON_VER)); \
	fi
	$(eval ret := $(shell pyenv versions | grep -P "\s$(VENV)(?=\s|$$)"))
	@if [ -n "$(ret)" ]; then \
		echo '$(VENV) exists'; \
	else \
		(pyenv virtualenv -f $(PYTHON_VER) $(VENV)); \
	fi
	@$(MAKE) env/sync
	@echo '✅ Environment ready: $(VENV)'

env/destroy:
	(pyenv uninstall -f $(VENV))

env/sync:
	( \
		$(ACTIVATE) && \
		python -m pip install --upgrade pip uv && \
		uv pip install -e '.[http,a2a]' --group dev 2>&1 \
	)

env/freeze:
	( \
		$(ACTIVATE) && \
		pip freeze \
	)

test:
	( \
		$(ACTIVATE) && \
		pytest -q 2>&1 \
	)

test/target: __require_target__
	( \
		$(ACTIVATE) && \
		pytest -v $(TARGET) 2>&1 \
	)

# A Client, its audit host, and a Server Agent as separate processes over HTTPS, with each of the audit host and
# the Server Agent this SDK's or the TypeScript SDK's (../auditable-a2a-sdk-ts). CASE narrows it by name.
walk:
	( \
		$(ACTIVATE) && \
		python -m walk.run $(CASE) 2>&1 \
	)

lint:
	( \
		$(ACTIVATE) && \
		ruff check . && \
		ruff format --check . && \
		mypy 2>&1 \
	)

format:
	( \
		$(ACTIVATE) && \
		ruff format . && \
		ruff check --fix . \
	)

# Vendored spec integrity: the conformance vectors must reproduce byte-for-byte (spec §12).
spec/check:
	( \
		$(ACTIVATE) && \
		python scripts/sync_spec.py --check 2>&1 \
	)

spec/sync:
	( \
		$(ACTIVATE) && \
		python scripts/sync_spec.py 2>&1 \
	)

clean:
	find . -type d -name '__pycache__' -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name '.pytest_cache' -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name '.mypy_cache' -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name '.ruff_cache' -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name '*.pyc' -delete
	rm -rf dist/ build/ *.egg-info

__require_target__:
	@[ -n "$(TARGET)" ] || (echo "[ERROR] Parameter [TARGET] is required" 1>&2 && echo "(e.g) make test/target TARGET=tests/test_audit_host.py" 1>&2 && exit 1)
