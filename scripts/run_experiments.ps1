# TenantCache Automated Benchmark & Experiment Runner (Windows PowerShell)

Write-Host "======================================================" -ForegroundColor Cyan
Write-Host "     TenantCache Automated Experiment Runner          " -ForegroundColor Cyan
Write-Host "======================================================" -ForegroundColor Cyan

# 1. Run unit, integration, and E2E verification
Write-Host "[*] Executing test suite via pytest..." -ForegroundColor Yellow
python -m pytest -v
if ($LASTEXITCODE -ne 0) {
    Write-Error "Test suite verification failed. Aborting experiment run."
    exit 1
}

# 2. Run Comprehensive Benchmark
Write-Host "`n[*] Executing comprehensive research benchmark across all 8 archetypes..." -ForegroundColor Yellow
python -m src.tenantcache.cli benchmark --profile comprehensive --output-dir benchmarks/results

# 3. Print Summary Report
Write-Host "`n[*] Output Summary Report:" -ForegroundColor Cyan
python -m src.tenantcache.cli report --results-path benchmarks/results/benchmark_report.md

Write-Host "`n[+] All experiments concluded successfully. Results saved to benchmarks/results/" -ForegroundColor Green
