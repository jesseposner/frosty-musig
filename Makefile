.PHONY: format lint type-check check test all install-dev

install-dev:
	pip install -r requirements-dev.txt

format:
	ruff format .

lint:
	ruff check . --fix

type-check:
	mypy .

test:
	python tests/test_integration.py

check: lint type-check

all: format check test