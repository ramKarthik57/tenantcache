#!/usr/bin/env bash
set -e

echo "======================================================"
echo "     TenantCache Automated Experiment Runner          "
echo "======================================================"

python3 -m pytest -v
python3 -m src.tenantcache.cli benchmark --profile comprehensive --output-dir benchmarks/results
python3 -m src.tenantcache.cli report --results-path benchmarks/results/benchmark_report.md
echo "Experiments finished successfully."
