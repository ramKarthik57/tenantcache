# TenantCache Makefile
.PHONY: help install test test-full test-nginx doctor benchmark ablation reproducibility lint clean package

PYTHON ?= python
PYTEST ?= pytest

help:
	@echo "TenantCache Engineering Commands:"
	@echo "  make install         Install package and dev dependencies"
	@echo "  make doctor          Run environment health check"
	@echo "  make test            Run core test suite (37 tests, fast offline)"
	@echo "  make test-full       Run full test suite (39 tests including Hypothesis)"
	@echo "  make test-nginx      Run native Nginx integration suite (8 archetypes)"
	@echo "  make benchmark       Run comprehensive 66-scenario benchmark"
	@echo "  make ablation        Run component ablation study"
	@echo "  make reproducibility Run 5-seed reproducibility validation"
	@echo "  make clean           Remove caches, bytecode, and temporary files"
	@echo "  make package         Build canonical release archive and sidecars"

install:
	$(PYTHON) -m pip install --upgrade pip setuptools wheel
	$(PYTHON) -m pip install -r constraints.txt
	$(PYTHON) -m pip install -e ".[dev]"

doctor:
	$(PYTHON) -m tenantcache.cli doctor

test:
	$(PYTEST) tests/ -v --ignore=tests/unit/test_property_hypothesis.py

test-full:
	$(PYTEST) tests/ -v

test-nginx:
	$(PYTEST) tests/integration/test_real_nginx.py -v

benchmark:
	$(PYTHON) -m tenantcache.cli benchmark --version v1.1 --profile comprehensive

ablation:
	$(PYTHON) -m tenantcache.cli ablation --version v1.1

reproducibility:
	$(PYTHON) -m tenantcache.cli reproducibility --version v1.1

clean:
	find . -type d -name "__pycache__" -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.py[cod]" -delete 2>/dev/null || true
	find . -type d -name ".pytest_cache" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name ".hypothesis" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "*.egg-info" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "build" -exec rm -rf {} + 2>/dev/null || true
	find . -type d -name "dist" -exec rm -rf {} + 2>/dev/null || true

package:
	$(PYTHON) scripts/build_release_zip.py
