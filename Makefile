.PHONY: format lint type-check check all install-dev

install-dev:
	pip install -r requirements-dev.txt

format:
	ruff format .

lint:
	ruff check . --fix

type-check:
	mypy .

check: lint type-check

all: format check