# TenantCache Lab State Reset Script (Windows PowerShell)

Write-Host "[*] Resetting TenantCache laboratory state..." -ForegroundColor Yellow
python -m src.tenantcache.cli lab reset
Write-Host "[+] Lab state reset complete." -ForegroundColor Green
