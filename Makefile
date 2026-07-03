# Developer convenience targets. See CONTRIBUTING.md.
.PHONY: install test lint typecheck fmt scan-example docker clean

install:
	pip install -e ".[dev]"

test:
	pytest -q

lint:
	ruff check .

typecheck:
	mypy

fmt:
	ruff check . --fix

# Run a full scan on the bundled vulnerable example with all features on.
scan-example:
	argus scan examples/vulnerable-app --attack-sim --patches

docker:
	docker build -t argus:local .

clean:
	rm -rf .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage \
		dist build src/*.egg-info examples/reports
	find . -type d -name __pycache__ -prune -exec rm -rf {} +
