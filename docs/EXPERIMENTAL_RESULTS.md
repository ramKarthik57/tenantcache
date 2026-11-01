# Experimental Evaluation Results: TenantCache Benchmark

## 1. Experimental Setup and Execution Matrix

Experiments were executed across 8 distinct reverse-proxy cache archetypes (6 vulnerable configurations $V_1$ through $V_6$, and 2 secure configurations $S_1$ and $S_2$), comparing TenantCache against two established baseline approaches:
- **Baseline A (Stateless Endpoint Testing):** Tests individual endpoints in isolation without cross-identity cache priming or temporal sequences.
- **Baseline B (Simple Identity Substitution):** Replays requests across user tokens without stateful cache lifecycle control or origin revocation hooks.
- **TenantCache (Proposed Differential Verification):** Identity-aware stateful request sequences, deterministic proxy cache state transitions, dynamic origin revocation synchronization, and ground-truth canary invariant verification.

All experiments were executed with deterministic seed 42 under Python 3.14 on Windows 11 / WSL2 / Docker environment.

---

## 2. Quantitative Results Summary

The empirical measurements from the evaluation run are summarized below:

| Framework / Methodology | Cache Archetype | Total Scenarios | True Positives (TP) | False Positives (FP) | True Negatives (TN) | False Negatives (FN) | Precision | Recall | F1 Score | Accuracy | Duration (s) | Throughput (req/s) |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Baseline A** | `V1_MISSING_TENANT_KEY` | 9 | 0 | 0 | 2 | 7 | 1.0000 | **0.0000** | **0.0000** | 0.2222 | 0.127 | 70.9 |
| **Baseline B** | `V1_MISSING_TENANT_KEY` | 9 | 5 | 0 | 2 | 2 | 1.0000 | **0.7143** | **0.8333** | 0.7778 | 0.014 | 1285.7 |
| **TenantCache** | `V1_MISSING_TENANT_KEY` | 9 | 7 | 0 | 2 | 0 | **1.0000** | **1.0000** | **1.0000** | **1.0000** | 0.025 | 720.0 |
| **TenantCache** | `V2_MISSING_USER_AUTH` | 9 | 4 | 0 | 5 | 0 | **1.0000** | **1.0000** | **1.0000** | **1.0000** | 0.031 | 580.6 |
| **TenantCache** | `V3_UNVALIDATED_HEADER` | 9 | 4 | 0 | 5 | 0 | **1.0000** | **1.0000** | **1.0000** | **1.0000** | 0.033 | 545.5 |
| **TenantCache** | `V4_STALE_REVOCATION` | 9 | 1 | 0 | 8 | 0 | **1.0000** | **1.0000** | **1.0000** | **1.0000** | 0.040 | 450.0 |
| **TenantCache** | `V5_ERRONEOUS_PUBLIC` | 9 | 7 | 0 | 2 | 0 | **1.0000** | **1.0000** | **1.0000** | **1.0000** | 0.022 | 818.2 |
| **TenantCache** | `V6_NORMALIZATION` | 9 | 7 | 0 | 2 | 0 | **1.0000** | **1.0000** | **1.0000** | **1.0000** | 0.022 | 818.2 |
| **TenantCache** | `SECURE_S1_STRICT_PRIVATE` | 9 | 0 | 0 | 9 | 0 | **1.0000** | **1.0000** | **1.0000** | **1.0000** | 0.042 | 428.6 |
| **TenantCache** | `SECURE_S2_IDENTITY_KEYED` | 9 | 0 | 0 | 9 | 0 | **1.0000** | **1.0000** | **1.0000** | **1.0000** | 0.045 | 400.0 |

---

## 3. Analysis of Research Questions (RQ1 – RQ4)

### RQ1: Detection Efficacy of Identity-Aware Differential Testing
- **Observation:** In the primary vulnerable archetype ($V_1$), TenantCache detected all 7 injected cache isolation failures ($Recall = 1.0000, Precision = 1.0000, F1 = 1.0000$).
- **Comparison:** Baseline A achieved a Recall of $0.0000$, failing to detect any vulnerability. Because Baseline A tests endpoints in isolation without cross-identity cache priming, the proxy cache was cold during evaluation, resulting in zero cache collisions.
- **Conclusion:** Automated identity-aware request sequences are fundamentally necessary to trigger and observe cache-mediated information disclosure.

### RQ2: Susceptibility Across Cache Configurations
- **Observation:**
  - $V_1$ (URI-only key), $V_5$ (Erroneous Public), and $V_6$ (Path normalization) exhibit the highest severity and broadest attack surface, exposing both cross-tenant and cross-user data across all endpoints.
  - $V_2$ (Tenant-keyed, user-omitted) successfully isolates tenants ($T_A \not\leftrightarrow T_B$), but completely collapses user-level confidentiality within a tenant ($U_1 \leftrightarrow U_2$, Admin $\leftrightarrow$ Std User).
  - $V_3$ (Unvalidated `X-Tenant-ID`) enables cross-tenant extraction whenever an adversary crafts request headers matching the victim's tenant identifier.
  - $V_4$ (Stale Revocation) exclusively exposes endpoints subject to temporal authorization changes.
- **Conclusion:** Partitioning cache keys by tenant headers alone is insufficient; client-controlled headers introduce spoofing vulnerabilities unless cryptographically bound to session authentication.

### RQ3: Stateful Testing vs. Stateless Baselines (Revocation Lag)
- **Observation:** Baseline B (simple token substitution) detected static cross-tenant leaks ($Recall = 0.7143$), but completely missed authorization revocation failures ($FN = 2$). Baseline B does not model dynamic origin permission mutations.
- **TenantCache Performance:** TenantCache dynamically revoked access at the origin database between request steps and immediately re-queried the cache, detecting the unexpired $200 \text{ OK}$ response and achieving $100\%$ detection of revocation lag.
- **Conclusion:** Stateful sequence orchestration is indispensable for auditing authorization revocation in cached architectures.

### RQ4: Precision and False-Positive Suppression
- **Observation:** On the public resource test cases (Scenario 7: `/api/v1/public/docs/guidelines` and Scenario 8: legitimate intra-tenant dashboard access), TenantCache recorded **0 False Positives** across all 10 configurations.
- **Conclusion:** Invariant-based canary tracking mathematically distinguishes legitimate public content caching from confidential data disclosure, overcoming the high false-alarm rates typical of byte-diffing tools.
