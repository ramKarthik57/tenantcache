# TenantCache Environment Setup Script (Windows PowerShell)

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

# 2. Install dependencies
Write-Host "[*] Installing dependencies from requirements.txt..." -ForegroundColor Yellow
python -m pip install -r requirements.txt
if ($LASTEXITCODE -ne 0) {
    Write-Error "Failed to install dependencies."
    exit 1
}

# 3. Run doctor
Write-Host "[*] Executing TenantCache doctor diagnostic..." -ForegroundColor Yellow
python -m src.tenantcache.cli doctor

Write-Host "`n[+] Setup completed successfully!" -ForegroundColor Green
