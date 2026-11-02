# TenantCache Environment Setup Script (Windows PowerShell)
$ErrorActionPreference = "Stop"

Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "      TenantCache Research Framework Setup            " -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan

# 1. Verify Python
$pythonVersion = python --version 2>&1
if ($LASTEXITCODE -ne 0) {
    Write-Error "Python is not installed or not in PATH."
    exit 1
}
Write-Host "[+] Detected: $pythonVersion" -ForegroundColor Green

# 2. Install dependencies with constraints
Write-Host "[*] Installing dependencies with constraints.txt..." -ForegroundColor Yellow
python -m pip install -r requirements.txt -c constraints.txt
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to install dependencies with constraints."
    exit 1
}

# 3. Install TenantCache in editable mode
Write-Host "[*] Installing TenantCache in editable mode..." -ForegroundColor Yellow
python -m pip install -e .
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to install TenantCache package."
    exit 1
}

# 4. Run doctor
Write-Host "[*] Executing TenantCache doctor diagnostic..." -ForegroundColor Yellow
python -m tenantcache.cli doctor
if ($LASTEXITCODE -ne 0) {
    Write-Error "TenantCache doctor failed."
    exit 1
}

Write-Host "`n[+] Setup completed successfully!" -ForegroundColor Green
