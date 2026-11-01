#!/usr/bin/env bash
set -e

echo "======================================================"
echo "      TenantCache Research Framework Setup            "
echo "======================================================"

python3 --version
python3 -m pip install -r requirements.txt
python3 -m src.tenantcache.cli doctor
echo "Setup completed successfully."
