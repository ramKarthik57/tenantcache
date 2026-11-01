# Reproducibility Guide: TenantCache

## 1. System Requirements

TenantCache is engineered for zero-budget, 100% reproducible execution on standard developer workstations across Windows, Linux, and macOS.

| Requirement | Specification |
|---|---|
| Python | 3.9+ (Tested on Python 3.11, 3.12, 3.14) |
| Operating System | Windows 10/11, Ubuntu 20.04+, macOS Sonoma+ |
| Shell | Windows PowerShell or POSIX Bash |
| Memory | Minimum 512 MB RAM |
| Disk Space | ~50 MB (Python environment) |
| Container Runtime | Optional (Docker Compose supported for containerized labs; native ASGI mode executes without Docker) |

---

## 2. Quickstart Execution (Windows PowerShell)

### Step 1: Install Dependencies
```powershell
python -m pip install -r requirements.txt
```

### Step 2: Run Environment Diagnostics
```powershell
python -m src.tenantcache.cli doctor
```
Expected output:
```text
Diagnostic Verifications:
  Python Runtime:   PASS
  Lab Application:  PASS
  Tenant Simulator: PASS
  Cache Simulator:  PASS
```

### Step 3: Execute Single Differential Scan
Test Vulnerable Archetype V1 (Missing Tenant Key):
```powershell
python -m src.tenantcache.cli scan --archetype V1_MISSING_TENANT_KEY
```
Test Secure Archetype S1 (Strict Private Cache Bypass):
```powershell
python -m src.tenantcache.cli scan --archetype SECURE_S1_STRICT_PRIVATE
```

### Step 4: Execute Full Research Benchmark
Run the comprehensive benchmark comparing Baseline A, Baseline B, and TenantCache across all 8 configuration archetypes:
```powershell
python -m src.tenantcache.cli benchmark --profile comprehensive
```
The results will be written to:
- `benchmarks/results/benchmark_results.json`
- `benchmarks/results/benchmark_results.csv`
- `benchmarks/results/benchmark_report.md`

### Step 5: Run Automated Verification Tests
```powershell
python -m pytest -v
```
All 19 test cases (unit, integration, hypothesis property, end-to-end) must pass with zero failures.

---

## 3. Dockerized Laboratory Execution (Linux / CI / Docker Desktop)

Where Docker is installed, execute the containerized environment:

```bash
# Build and start the lab containers
docker compose up -d

# Verify container status
docker compose ps

# Run scan against live Nginx reverse proxy
python -m src.tenantcache.cli scan --archetype V1_MISSING_TENANT_KEY

# Teardown
docker compose down
```
