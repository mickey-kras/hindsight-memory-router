.PHONY: init install lint format mypy test check architecture architecture-site

init:
	git config core.hooksPath .githooks
	chmod +x .githooks/pre-push

install:
	pip install -e '.[dev]'
	npm ci

format:
	python -m ruff format --check memory_router tests .github/scripts/sync-sonar-findings.py

lint:
	python -m ruff check memory_router tests .github/scripts/sync-sonar-findings.py

mypy:
	python -m mypy memory_router

test:
	python -m coverage run -m pytest
	python -m coverage report

check: format lint mypy test
	npm run check

architecture:
	./scripts/architecture.sh svg

architecture-site:
	./scripts/architecture.sh site
