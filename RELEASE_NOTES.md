# TenantCache v1.1.0 — Release Notes & Distribution Manifest

**Release Version:** `v1.1.0`  
**Date:** 2026-11-02  
**Status:** **Certified Production Research Release**  
**Lead Author:** Ramkumar V. (`ramkumar.v@research.tenantcache.org`)  
**Affiliation:** Advanced Systems & Cybersecurity Research Group  

---

## 1. Overview

**TenantCache** is an automated, identity-aware differential security testing framework designed to systematically detect, reproduce, and mathematically verify cross-tenant and cross-user HTTP cache isolation failures in reverse-proxy caching layers (e.g., Nginx, Varnish, Cloudflare).

This release represents the culmination of extensive peer-review audit cycles, featuring an airtight dual state-machine verification model ($\Sigma_{\text{auth}} \times \Sigma_{\text{cache}}$), independent fail-closed authorization oracles, live native Nginx proxy validation across eight archetypes ($V_1$–$V_6$, $S_1$, $S_2$), and complete deterministic reproducibility on the reconciled 66-scenario **Dataset v1.1**.

---

## 2. Release Highlights & Security Architecture

- **Fail-Closed Security Oracle:** The ground-truth authorization oracle binds strictly to an internal, immutable registered-principal ledger. Inaccessible or unregistered identities immediately fail closed (`AuthDecision.DENY`), preventing attribute spoofing.
- **Strict Canonical Route & Resource Resolution:** Eliminates ambiguous substring matching across origin routes; all resources resolve strictly by canonical resource identifier (`res_{tenant}_dashboard`) and exact endpoint path.
- **RFC 9110/9111 HTTP Method Consistency:** Full support for `GET` and `HEAD` semantics across origin endpoints and verification subrequests; unsupported mutation methods are rejected with `405 Method Not Allowed`.
- **Authorization-Decision Parity ($S_2$):** Demonstrates production-grade defensible caching using Nginx `auth_request` subrequests. Parity is maintained via a shared policy engine where inaccessible or deleted resources are deliberately mapped to HTTP `403 Forbidden` in proxy subrequests, guaranteeing fail-closed edge protection while preserving REST `404 Not Found` semantics at the origin.
- **Zero Runtime Residue:** Release packaging prunes all generated log files, runtime configurations, temporary PID files, and synthetic cache entries.

---

## 3. Benchmark & Verification Summary

### Matched-Budget Evaluation (198 Requests per Methodology, Dataset v1.1, $N=66$)
| Methodology | Budget | TP | FP | TN | FN | Precision (95% CI) | Recall (95% CI) | Specificity (95% CI) | F1 Score |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Baseline A (Stateless DAST)** | 198 | 0 | 0 | 20 | 46 | *N/A* | **0.0000** `[0.00, 0.08]` | **1.0000** `[0.84, 1.00]` | *N/A* |
| **Baseline B (Naive Diffing)** | 198 | 38 | 12 | 8 | 8 | 0.7600 `[0.63, 0.86]` | 0.8261 `[0.69, 0.91]` | 0.4000 `[0.22, 0.61]` | 0.7917 |
| **TenantCache (Proposed)** | 198 | **46** | **0** | **20** | **0** | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.84, 1.00]` | **1.0000** |

*Note on Baseline Scoping:* Baselines A and B represent custom reference implementations engineered to isolate specific algorithmic properties (stateless single-request probing and naive token differential checking without authorization state synchronization). They do not evaluate commercial enterprise DAST suites.

### Test Execution Matrix
- **Core Test Suite (37 tests):** **100% Passed** in network-isolated environments (`pytest tests/ -v --ignore=tests/unit/test_property_hypothesis.py`).
- **Full Test Suite (39 tests):** **100% Passed** in clean-room environments with Hypothesis property testing (`pytest tests/ -v`).
- **Live Nginx Integration (8 tests):** **100% Passed** against live native Nginx binaries on Windows and Linux (`pytest tests/integration/test_real_nginx.py -v`).

---

## 4. Release Artifacts & Cryptographic Provenance

All release assets are cryptographically signed via SHA-256 digests:

| File Name | File Size | SHA-256 Checksum |
| :--- | :--- | :--- |
| **`tenantcache.zip`** | 2,289,951 bytes | `375fa5c783702a65177a69af9182d866a4ca1410cf8ca6d6f066c16228c5fac2` |
| **`tenantcache.zip.sha256`** | 83 bytes | Checksum verification sidecar for `tenantcache.zip` |
| **`SHA256SUMS`** | 83 bytes | Canonical root manifest |

### Verifying Release Integrity
```bash
# On Linux / macOS:
sha256sum -c tenantcache.zip.sha256

# On Windows (PowerShell):
$Expected = (Get-Content tenantcache.zip.sha256).Split(" ")[0]
$Actual = (Get-FileHash tenantcache.zip -Algorithm SHA256).Hash.ToLower()
if ($Expected -eq $Actual) { Write-Host "VERIFIED: Checksum Matches" -ForegroundColor Green } else { Write-Host "CHECKSUM MISMATCH" -ForegroundColor Red }
```

---

## 5. Quickstart & Reproduction Commands

### Installation
```bash
# Extract canonical release archive
unzip tenantcache.zip -d tenantcache-v1.1.0
cd tenantcache-v1.1.0

# Install dependencies from exact constraints
pip install -r constraints.txt

# Or install wheel directly without network access
pip install . --no-deps
```

### Health Check & Research Replication
```bash
# Run environment health check
tenantcache doctor

# Run comprehensive benchmark across all 66 scenarios
tenantcache benchmark --version v1.1 --profile comprehensive

# Run component ablation study
tenantcache ablation --version v1.1

# Run multi-seed reproducibility validation (5 seeds)
tenantcache reproducibility --version v1.1

# Execute core test suite (offline)
pytest tests/ -v --ignore=tests/unit/test_property_hypothesis.py
```

---

## 6. Academic Citation

If you utilize TenantCache, its benchmark corpus, or its differential cache verification methodology in your academic research, please cite:

```bibtex
@inproceedings{ramkumar2026tenantcache,
  title     = {Automated Differential Verification of Cache Isolation in Multi-Tenant Web Applications},
  author    = {Ramkumar, V.},
  booktitle = {Proceedings of the International Conference on Software Engineering and Cybersecurity},
  year      = {2026},
  note      = {Artifact available at https://github.com/tenantcache/tenantcache}
}
```
