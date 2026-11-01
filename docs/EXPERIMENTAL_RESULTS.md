# Experimental Evaluation Results: Expanded 54-Scenario Benchmark & Ablation Study

## 1. Experimental Setup and Execution Matrix

Experiments were executed across 8 distinct reverse-proxy cache archetypes (6 vulnerable configurations $V_1$ through $V_6$, and 2 secure configurations $S_1$ and $S_2$), comparing TenantCache against two established baseline approaches on an expanded **54-scenario benchmark corpus** spanning 5 enterprise tenants (`Acme`, `Beta`, `Gamma`, `Delta`, `Epsilon`):
- **Baseline A (Stateless Endpoint Testing):** Tests individual endpoints in isolation without cross-identity cache priming or temporal sequences. Equalized exploration budget.
- **Baseline B (Simple Identity Substitution):** Replays requests across user tokens without stateful cache lifecycle control or origin revocation hooks.
- **TenantCache (Proposed Differential Verification):** Identity-aware stateful request sequences, deterministic proxy cache state transitions, dynamic origin revocation synchronization, and ground-truth canary invariant verification.
- **Native Nginx Validation:** Real Nginx (1.26.2) on `localhost:8080` executed live to confirm reproduction on production proxy binaries (`tests/integration/test_real_nginx.py`).

All experiments were executed with deterministic seed 42 under Python 3.14 on Windows 11.

---

## 2. Quantitative Results Summary (with 95% Wilson Confidence Intervals)

| Framework / Methodology | Cache Archetype | Total Scenarios | True Positives (TP) | False Positives (FP) | True Negatives (TN) | False Negatives (FN) | Precision (95% CI) | Recall (95% CI) | Specificity (95% CI) | Accuracy (95% CI) | FPR | Total Requests | Cache Resets | State Transitions | Principals Covered | Duration |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Baseline A** | `V1_MISSING_TENANT_KEY` | 54 | 0 | 0 | 10 | 44 | *N/A (Undefined)* | 0.0000 `[0.00, 0.08]` | 1.0000 `[0.72, 1.00]` | 0.1852 `[0.10, 0.31]` | 0.00 | 54 | 54 | 0 | 10 | 0.237s |
| **Baseline B** | `V1_MISSING_TENANT_KEY` | 54 | 33 | 8 | 2 | 11 | 0.8049 `[0.66, 0.90]` | 0.7500 `[0.60, 0.86]` | 0.2000 `[0.04, 0.56]` | 0.6481 `[0.51, 0.76]` | **0.80** | 108 | 0 | 0 | 10 | 0.030s |
| **TenantCache** | `V1_MISSING_TENANT_KEY` | 54 | 44 | 0 | 10 | 0 | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.72, 1.00]` | **1.0000** `[0.93, 1.00]` | **0.00** | 108 | 54 | 8 | 10 | 0.140s |
| **TenantCache** | `V2_MISSING_USER_AUTH` | 54 | 27 | 0 | 24 | 3 | **1.0000** `[0.87, 1.00]` | **0.9000** `[0.74, 0.97]` | **1.0000** `[0.86, 1.00]` | **0.9444** `[0.85, 0.98]` | **0.00** | 108 | 54 | 8 | 10 | 0.190s |
| **TenantCache** | `V3_UNVALIDATED_HEADER` | 54 | 27 | 0 | 24 | 3 | **1.0000** `[0.87, 1.00]` | **0.9000** `[0.74, 0.97]` | **1.0000** `[0.86, 1.00]` | **0.9444** `[0.85, 0.98]` | **0.00** | 108 | 54 | 8 | 10 | 0.220s |
| **TenantCache** | `V4_STALE_REVOCATION` | 54 | 8 | 0 | 46 | 0 | **1.0000** `[0.68, 1.00]` | **1.0000** `[0.68, 1.00]` | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.93, 1.00]` | **0.00** | 108 | 54 | 8 | 10 | 0.270s |
| **TenantCache** | `V5_ERRONEOUS_PUBLIC` | 54 | 44 | 0 | 10 | 0 | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.72, 1.00]` | **1.0000** `[0.93, 1.00]` | **0.00** | 108 | 54 | 8 | 10 | 0.150s |
| **TenantCache** | `V6_NORMALIZATION` | 54 | 44 | 0 | 10 | 0 | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.72, 1.00]` | **1.0000** `[0.93, 1.00]` | **0.00** | 108 | 54 | 8 | 10 | 0.140s |
| **TenantCache** | `SECURE_S1_STRICT_PRIVATE` | 54 | 0 | 0 | 54 | 0 | *N/A (Undefined)* | *N/A (Undefined)* | **1.0000** `[0.93, 1.00]` | **1.0000** `[0.93, 1.00]` | **0.00** | 108 | 54 | 8 | 10 | 0.260s |
| **TenantCache** | `SECURE_S2_IDENTITY_KEYED` | 54 | 0 | 0 | 54 | 0 | *N/A (Undefined)* | *N/A (Undefined)* | **1.0000** `[0.93, 1.00]` | **1.0000** `[0.93, 1.00]` | **0.00** | 108 | 54 | 8 | 10 | 0.260s |

---

## 3. Systematic Component Ablation Study

To isolate the exact contribution of each architectural component, an ablation study was executed on the primary vulnerable archetype ($V_1$), comparing the full proposed pipeline against three degraded variants:

| System Variant | Identity Aware | Cache Sequenced | Ground-Truth Oracle | Precision | Recall | F1 Score | False Positive Rate (FPR) | TP / FN | Role in System Architecture |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|---|
| **Full TenantCache** | **YES** | **YES** | **YES** | **1.0000** | **1.0000** | **1.0000** | **0.0000** | **44 / 0** | Full proposed verification pipeline |
| **Ablation 1: No Cache Sequencing** | YES | **NO** | YES | *N/A* | **0.0000** | *N/A* | 0.0000 | 0 / 44 | Evaluates endpoints statelessly; proxy cache remains cold |
| **Ablation 2: No Ground-Truth Oracle** | YES | YES | **NO** | 0.8049 | 0.7500 | 0.7765 | **0.8000** | 33 / 11 | Relies on naive response diffing; flags public content as leaks |
| **Ablation 3: No Identity Awareness** | **NO** | YES | YES | *N/A* | **0.0000** | *N/A* | 0.0000 | 0 / 44 | Replays single anonymous requests; cannot cross boundaries |

### Key Ablation Insights:
1. **Cache Sequencing is Essential for Recall:** Disabling cache-state sequencing (Ablation 1) collapses recall from $1.00 \to 0.00$. Without deliberately priming the cache with an authorized request prior to probing, proxy cache hits cannot occur.
2. **Ground-Truth Oracle is Essential for Precision:** Disabling the oracle (Ablation 2) causes the False Positive Rate to surge from $0.00 \to 0.80$ ($80\%$). Naive response-length or status diffing misclassifies legitimate public guidelines and intra-tenant collaborations as breaches.
3. **Identity Awareness is Essential for Multi-Tenant Coverage:** Single-token replay (Ablation 3) fails to test any tenant or privilege boundaries, missing all 44 isolation failures.
