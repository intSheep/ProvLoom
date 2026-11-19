.PHONY: install fmt lint typecheck test test-acceptance db-up db-down db-migrate api-dev web-install web-dev web-check

BIN := $(shell [ -d .venv/bin ] && echo .venv/bin/ || echo "")
PYTHON ?= $(BIN)python3

install:
	@command -v uv >/dev/null 2>&1 && uv sync --all-extras || $(PYTHON) -m pip install -e ".[dev]"

fmt:
	$(BIN)ruff format src tests
	$(BIN)ruff check --fix src tests

lint:
	$(BIN)ruff check src tests
	$(BIN)ruff format --check src tests

typecheck:
	$(BIN)mypy src
	@if [ -d web/node_modules ]; then npm --prefix web run typecheck; fi

test:
	$(BIN)pytest -m "not acceptance"

test-acceptance:
	$(BIN)pytest -m acceptance

db-up:
	docker compose up -d postgres

db-down:
	docker compose down

db-migrate:
	$(BIN)alembic upgrade head

api-dev:
	$(BIN)uvicorn provloom.api.app:create_app --factory --reload --host 127.0.0.1 --port 8000

web-install:
	npm --prefix web install

web-dev:
	npm --prefix web run dev

web-check:
	npm --prefix web run typecheck
