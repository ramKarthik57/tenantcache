#!/usr/bin/env bash
set -e

echo "======================================================"
echo "      TenantCache Research Framework Setup            "
echo "======================================================"

python3 --version
python3 -m pip install -r requirements.txt -c constraints.txt
python3 -m pip install -e .
python3 -m tenantcache.cli doctor
echo "Setup completed successfully."
