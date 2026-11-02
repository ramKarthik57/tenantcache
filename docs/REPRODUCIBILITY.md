# Reproducibility Guide: TenantCache v1.1.0

## 1. System Requirements & Execution Matrix

TenantCache is engineered for zero-budget, 100% reproducible execution on standard workstations across Windows and Linux.

| Requirement | Specification |
|---|---|
| Python Runtime | Python 3.11+ (Tested on Python 3.11, 3.12, 3.14) |
| Operating Systems | Windows 10/11 (PowerShell), Ubuntu 20.04+ / Debian 11+ (Bash) |
| Shell Environments | PowerShell 5.1+ / 7+, POSIX Bash |
| Reverse Proxy Binary | Nginx 1.26.2 (Windows local runtime in `lab/nginx_runtime/`) or Nginx 1.26.3+ on Linux (`nginx` in `$PATH`) |
| Network Access | **Zero external network or cloud dependencies**; all tests execute offline via localhost loopback |
| Memory & Storage | Minimum 512 MB RAM, ~50 MB disk space |

---

## 2. Clean-Room Installation Workflow

To prevent dependency drift across platforms, always apply the pinned constraints file:

### POSIX (Linux / macOS):
```bash
# 1. Unzip canonical release archive
unzip tenantcache.zip -d tenantcache && cd tenantcache

# 2. Install dependencies with exact tested constraints
python3 -m pip install -r requirements.txt -c constraints.txt

# 3. Install TenantCache package in editable mode
python3 -m pip install -e .

# 4. Verify system health
python3 -m tenantcache.cli doctor
```

### Windows (PowerShell):
```powershell
# 1. Expand archive
Expand-Archive -Path tenantcache.zip -DestinationPath tenantcache
Set-Location tenantcache

# 2. Install dependencies with exact tested constraints
python -m pip install -r requirements.txt -c constraints.txt

# 3. Install TenantCache in editable mode
python -m pip install -e .

# 4. Verify system health
python -m tenantcache.cli doctor
```

Expected diagnostic output:
```text
+-----------------------------------------------+
| TenantCache Doctor - Environment Health Check |
+-----------------------------------------------+
Diagnostic Verifications:
  Python Runtime:   PASS (Python 3.14.x)
  Lab Application:  PASS (FastAPI target loaded successfully)
  Tenant Simulator: PASS (5 Tenants, 10 Users, 27 Resources)
  Cache Simulator:  PASS (High-Fidelity RFC 9111 Proxy Engine Ready)
System is 100% operational for reproducible experiments.
```

---

## 3. Automated Test Suite Execution

The repository contains 39 automated test cases covering units, property invariants, differential execution, isolated test reset channels, and native Nginx proxy integration.

### Full Test Suite (All 39 Tests including Hypothesis Property Tests):
```bash
pytest tests/ -v
```
*Expected Result:* `39 passed` in ~20 seconds.

### Core Test Suite (37 Tests without Hypothesis Property Engine):
If Hypothesis is unavailable or network-isolated:
```bash
pytest tests/ -v --ignore=tests/unit/test_property_hypothesis.py
```
*Expected Result:* `37 passed` in ~16 seconds.

### Native Nginx Integration Suite (8 Proxy Configurations):
```bash
pytest tests/integration/test_real_nginx.py -v
```
*Expected Result:* All 8 archetypes ($V_1$–$V_6$, $S_1$, $S_2$) pass live against the local Nginx instance.

---

## 4. Benchmark & Research Study Reproduction

All experimental outputs are completely deterministic across seeds and can be recomputed via the CLI:

### 1. Comprehensive Benchmark (66 Scenarios, Dataset v1.1):
```bash
python -m tenantcache.cli benchmark --version v1.1 --profile comprehensive
```
Generates:
- `benchmarks/results/benchmark_report.md`
- `benchmarks/results/benchmark_results.json`
- `benchmarks/results/benchmark_results.csv`

### 2. Component Ablation Study (V1 Archetype):
```bash
python -m tenantcache.cli ablation --version v1.1
```
Generates:
- `benchmarks/results/ablation_report.md`

### 3. Multi-Seed Deterministic Reproducibility (Seeds 42–46):
```bash
python -m tenantcache.cli reproducibility --version v1.1
```
Generates:
- `benchmarks/results/reproducibility_report.md`

---

## 5. Dockerized Lab Execution & Security Boundary

Docker Compose is provided for containerized deployment of the lab target and proxy:

> [!WARNING] Loopback Binding & Security Notice
> The Docker laboratory packages an intentionally vulnerable reverse-proxy cache configuration ($V_1$). To prevent unauthorized local network exposure, `docker-compose.yml` binds all published ports strictly to `127.0.0.1` (`127.0.0.1:8080` and `127.0.0.1:8000`). Never bind these services to `0.0.0.0` or expose them to untrusted LANs.

```bash
# Build and run containerized lab (bound to 127.0.0.1)
docker compose up -d

# Verify containers are bound to 127.0.0.1
docker compose ps

# Execute scan against containerized proxy
python -m tenantcache.cli scan --archetype V1_MISSING_TENANT_KEY

# Teardown
docker compose down
```
