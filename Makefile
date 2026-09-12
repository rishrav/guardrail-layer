.PHONY: help setup models up down migrate test lint bench bench-all bench-record demo

help:  ## Show targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk -F':.*## ' '{printf "  %-14s %s\n", $$1, $$2}'

setup:  ## Install deps and git hooks
	uv sync
	uv run pre-commit install

models:  ## Download the ONNX classifier and pull the Ollama judge/guardian models
	./scripts/pull_models.sh

up:  ## Start postgres, redis, migrations and the gateway
	docker compose up -d --build --wait gateway

down:  ## Stop the stack
	docker compose down

migrate:  ## Apply database migrations from the host
	cd gateway && uv run alembic upgrade head

lint:  ## Ruff lint + format check
	uv run ruff check .
	uv run ruff format --check .

test:  ## Unit + integration tests (needs `make up`)
	uv run pytest tests -q

bench:  ## Benchmark core configs A-D on the held-out split (cassette replay)
	uv run pytest benchmarks --split test

bench-all:  ## Benchmark core configs + ablations on the held-out split
	uv run pytest benchmarks --split test --config all

bench-record:  ## Record missing model responses from live local models (slow)
	uv run pytest benchmarks --split all --config all --record

demo:  ## Run the scripted end-to-end demo against the running gateway
	uv run python -m agent_demo.demo
