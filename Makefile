.PHONY: init install lint format mypy test check architecture architecture-site

init:
	git config core.hooksPath .githooks
	chmod +x .githooks/pre-push

install:
	pip install -e '.[dev]'
	npm ci

format:
	ruff format --check memory_router tests

lint:
	ruff check memory_router tests

mypy:
	mypy memory_router

test:
	coverage run -m pytest
	coverage report

check: format lint mypy test
	npm run check

architecture:
	./scripts/architecture.sh svg

architecture-site:
	./scripts/architecture.sh site
