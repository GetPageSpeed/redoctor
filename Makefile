.PHONY: tests test coverage lint clean install dev-install

# Run all tests with coverage (parallel for speed)
tests:
	pytest tests/ -n auto --timeout=60 -q

# Alias for tests
test: tests

# Run tests with verbose output
test-verbose:
	pytest -v --tb=long tests/

# Generate coverage report (slower, runs sequentially)
coverage:
	pytest --cov=src/redoctor --cov-report=term-missing --cov-report=html tests/ --timeout=30
	@echo "Coverage report generated in htmlcov/"

# Lint with ruff
lint:
	ruff check src/redoctor tests/
	ruff format --check src/redoctor tests/

# Format code with ruff
format:
	ruff format src/redoctor tests/
	ruff check --fix src/redoctor tests/

# Clean up build artifacts
clean:
	rm -rf __pycache__ .pytest_cache .coverage htmlcov build dist *.egg-info
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

# Install package in development mode
dev-install:
	pip install -e ".[dev]"

# Install package
install:
	pip install .

# Run a quick test (no coverage)
quick:
	pytest tests/ -x --tb=short -n auto --timeout=60

# Run tests matching a pattern
test-match:
	pytest tests/ -k "$(PATTERN)" -v

# Run pre-commit hooks
pre-commit:
	pre-commit run --all-files
