# TenantCache CLI Reference Manual

`tenantcache` is the unified command-line interface for environment diagnostics, benchmark generation, component ablation, and empirical verification.

---

## Command Overview

```bash
tenantcache [COMMAND] [OPTIONS]
```

| Command | Summary |
| :--- | :--- |
| `doctor` | Inspects system dependencies, Nginx binaries, and environment health. |
| `manifest` | Exports versioned scenario manifests (`v1.0`: 54 cases, `v1.1`: 66 cases). |
| `benchmark` | Executes controlled empirical benchmarks across custom baselines and TenantCache. |
| `ablation` | Executes component ablation studies (evaluating sequencing, oracles, and identity). |
| `reproducibility` | Executes multi-seed reproducibility evaluations across 5 deterministic seeds. |
| `scan` | Executes active differential scans against a target reverse proxy. |

---

## 1. `tenantcache doctor`

Performs an environment health check, verifying Python version, FastAPI target application availability, Tenant Simulator universe initialization, and cache simulator readiness.

```bash
python -m tenantcache.cli doctor
```

**Output:**
```text
+-----------------------------------------------+
| TenantCache Doctor - Environment Health Check |
+-----------------------------------------------+
                        Diagnostic Verifications                         
+-----------------------------------------------------------------------+
| Component        | Status | Details                                   |
|------------------+--------+-------------------------------------------|
| Python Runtime   | PASS   | Python 3.14.7                             |
| Lab Application  | PASS   | FastAPI target loaded successfully        |
| Tenant Simulator | PASS   | 5 Tenants, 10 Users, 27 Resources         |
| Cache Simulator  | PASS   | High-Fidelity RFC 9111 Proxy Engine Ready |
+-----------------------------------------------------------------------+
System is 100% operational for reproducible experiments.
```

---

## 2. `tenantcache manifest`

Generates and exports the JSON benchmark test manifest.

```bash
python -m tenantcache.cli manifest --version v1.1
```

**Options:**
- `--version [v1.0|v1.1]`: Dataset version to generate. (Default: `v1.1` with 66 scenarios: 46 positive vulnerability cases, 20 balanced controls).

---

## 3. `tenantcache benchmark`

Executes the formal benchmark comparing Baseline A (stateless reference), Baseline B (naive differential reference), and TenantCache.

```bash
python -m tenantcache.cli benchmark --version v1.1 --profile comprehensive
```

**Options:**
- `--version [v1.0|v1.1]`: Dataset corpus to evaluate.
- `--profile [matched-budget|comprehensive]`:
  - `matched-budget`: Evaluates all tools under an identical budget of 198 requests on Archetype $V_1$.
  - `comprehensive`: Evaluates performance across all 8 archetypes ($V_1$–$V_6$, $S_1$, $S_2$).

---

## 4. `tenantcache ablation`

Runs the component ablation study to isolate the causal impact of cache sequencing, ground-truth authorization oracles, and multi-identity modeling.

```bash
python -m tenantcache.cli ablation --version v1.1
```

---

## 5. `tenantcache reproducibility`

Executes 5 sequential repetitions across deterministic pseudo-random seeds (`[42, 43, 44, 45, 46]`) to measure variance ($\sigma$) in precision, recall, and throughput.

```bash
python -m tenantcache.cli reproducibility --version v1.1
```
