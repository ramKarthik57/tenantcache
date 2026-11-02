# Experimental Evaluation Results: Reconciled 66-Scenario Benchmark, Ablation Study, & Reproducibility

## 1. Experimental Setup and Declared Dataset Versions

Experiments were executed across 8 distinct reverse-proxy cache archetypes (6 vulnerable configurations $V_1$ through $V_6$, and 2 secure configurations $S_1$ and $S_2$), comparing TenantCache against two established baseline approaches under two distinct experimental protocols:
1. **Matched-Budget Experiment (Equal-Resource):** All three tools are allocated an equal budget of 3 requests per scenario (total 198 requests), equal timeouts (5.0s), equal principal coverage (10 principals), and identical scenario evaluation.
2. **Capability Experiment (Native Workflow):** Tools operate under their standard execution modes, explicitly isolating the architectural advantage provided by synchronized state exploration.

### Declared Dataset Versions & Scenario Manifests

All test scenarios are version-controlled in the repository:
- **Corpus v1.0 (Legacy 54 Scenarios):** Documented in [`benchmarks/manifests/scenarios_v1.0.json`](../benchmarks/manifests/scenarios_v1.0.json) and `.csv`. Contains 46 vulnerable scenarios and 8 benign negative controls.
- **Corpus v1.1 (Reconciled & Expanded 66 Scenarios):** Documented in [`benchmarks/manifests/scenarios_v1.1.json`](../benchmarks/manifests/scenarios_v1.1.json) and `.csv`. Contains 46 vulnerable scenarios and 20 benign negative controls (8 public cross-tenant documents, 4 intra-tenant shared dashboards, 4 intra-user authorized profile accesses, and 4 authorized project accesses prior to revocation).

---

## 2. Quantitative Results: Matched-Budget vs. Capability Evaluation

### 2.1 Matched-Budget Experiment (Equal 3-Request Budget per Scenario, Total 198 Requests)

| Testing Approach | Cache Archetype | Requests | Resets | Transitions | TP | FP | TN | FN | Precision (95% Wilson CI) | Recall (95% Wilson CI) | Specificity (95% Wilson CI) | False Positive Rate |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Baseline A (Stateless DAST)** | `V1` | 198 | 66 | 0 | 0 | 0 | 20 | 46 | *N/A (Undefined)* | **0.0000** `[0.00, 0.08]` | **1.0000** `[0.84, 1.00]` | **0.0000** `[0.00, 0.16]` |
| **Baseline B (Naive Diffing)** | `V1` | 198 | 66 | 8 | 38 | 12 | 8 | 8 | **0.7600** `[0.63, 0.86]` | **0.8261** `[0.69, 0.91]` | **0.4000** `[0.22, 0.61]` | **0.6000** `[0.39, 0.78]` |
| **TenantCache (Proposed)** | `V1` | 198 | 66 | 8 | 46 | 0 | 20 | 0 | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.84, 1.00]` | **0.0000** `[0.00, 0.16]` |

*Key Empirical Takeaway:* When all three tools are allocated identical 198-request testing budgets and per-scenario cache resets, Baseline A's detection recall remains identically $0.00\%$. Baseline B detects static token substitution leaks (38 TP) but misses all 8 temporal revocation scenarios (8 FN) and flags legitimate public/shared content as leaks (12 FP, 60% FPR). TenantCache achieves 100% precision and recall with 0 false positives.

---

### 2.2 Comprehensive Capability Evaluation Across All 8 Archetypes (Dataset v1.1)

| Methodology | Cache Archetype | Scenarios | TP | FP | TN | FN | Precision (95% CI) | Recall (95% CI) | Specificity (95% CI) | Accuracy (95% CI) | FPR | Total Requests | Duration |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Baseline A** | `V1_MISSING_TENANT_KEY` | 66 | 0 | 0 | 20 | 46 | *N/A* | 0.0000 `[0.00, 0.08]` | 1.0000 `[0.84, 1.00]` | 0.3030 `[0.21, 0.42]` | 0.00 | 66 | 0.46s |
| **Baseline B** | `V1_MISSING_TENANT_KEY` | 66 | 38 | 12 | 8 | 8 | 0.7600 `[0.63, 0.86]` | 0.8261 `[0.69, 0.91]` | 0.4000 `[0.22, 0.61]` | 0.6970 `[0.58, 0.79]` | **0.60** | 132 | 0.60s |
| **TenantCache** | `V1_MISSING_TENANT_KEY` | 66 | 46 | 0 | 20 | 0 | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.84, 1.00]` | **1.0000** `[0.94, 1.00]` | **0.00** | 132 | 0.60s |
| **TenantCache** | `V2_MISSING_USER_AUTH` | 66 | 29 | 0 | 34 | 3 | **1.0000** `[0.88, 1.00]` | **0.9062** `[0.76, 0.97]` | **1.0000** `[0.90, 1.00]` | **0.9545** `[0.87, 0.98]` | **0.00** | 132 | 0.78s |
| **TenantCache** | `V3_UNVALIDATED_HEADER` | 66 | 29 | 0 | 34 | 3 | **1.0000** `[0.88, 1.00]` | **0.9062** `[0.76, 0.97]` | **1.0000** `[0.90, 1.00]` | **0.9545** `[0.87, 0.98]` | **0.00** | 132 | 0.77s |
| **TenantCache** | `V4_STALE_REVOCATION` | 66 | 8 | 0 | 58 | 0 | **1.0000** `[0.68, 1.00]` | **1.0000** `[0.68, 1.00]` | **1.0000** `[0.94, 1.00]` | **1.0000** `[0.94, 1.00]` | **0.00** | 132 | 0.94s |
| **TenantCache** | `V5_ERRONEOUS_PUBLIC` | 66 | 46 | 0 | 20 | 0 | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.84, 1.00]` | **1.0000** `[0.94, 1.00]` | **0.00** | 132 | 0.60s |
| **TenantCache** | `V6_NORMALIZATION` | 66 | 46 | 0 | 20 | 0 | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.84, 1.00]` | **1.0000** `[0.94, 1.00]` | **0.00** | 132 | 0.61s |
| **TenantCache** | `SECURE_S1_STRICT_PRIVATE` | 66 | 0 | 0 | 66 | 0 | *N/A (Undefined)* | *N/A (Undefined)* | **1.0000** `[0.94, 1.00]` | **1.0000** `[0.94, 1.00]` | **0.00** | 132 | 1.08s |
| **TenantCache** | `SECURE_S2_IDENTITY_KEYED` | 66 | 0 | 0 | 66 | 0 | *N/A (Undefined)* | *N/A (Undefined)* | **1.0000** `[0.94, 1.00]` | **1.0000** `[0.94, 1.00]` | **0.00** | 132 | 1.01s |

---

## 3. Systematic Component Ablation & Category Confusion Matrices

To measure the independent contribution of each system component, an ablation study was conducted on Archetype $V_1$ across all 66 scenarios:

| System Variant | Identity Aware | Cache Sequenced | Ground-Truth Oracle | Precision | Recall | F1 Score | False Positive Rate (FPR) | TP / FN | Primary Role |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|---|
| **Full TenantCache** | **YES** | **YES** | **YES** | **1.0000** | **1.0000** | **1.0000** | **0.0000** | **46 / 0** | Full proposed verification pipeline |
| **Ablation 1: No Cache Sequencing** | YES | **NO** | YES | *N/A* | **0.0000** | *N/A* | 0.0000 | 0 / 46 | Evaluates endpoints without priming cache |
| **Ablation 2: No Ground-Truth Oracle** | YES | YES | **NO** | 0.7600 | 0.8261 | 0.7917 | **0.6000** | 38 / 8 | Relies on naive diffing; flags public content |
| **Control: Single-User Reachability Control** | **NO** | YES | YES | *N/A* | **0.0000** | *N/A* | 0.0000 | 0 / 46 | Single authenticated user (Alice vs. Alice); reachability control (TP=0, FN=46 by construction) |

### Category-Wise Confusion Matrix for Ablation 2 (No Ground-Truth Oracle)

| Vulnerability Category | Total in Corpus | True Positives (TP) | False Negatives (FN) | False Positives (FP) | True Negatives (TN) | Detection Behavior |
|---|:---:|:---:|:---:|:---:|:---:|---|
| **Cross-Tenant** | 14 | 14 | 0 | 0 | 0 | Observable cross-token response collision detected |
| **Cross-User** | 10 | 10 | 0 | 0 | 0 | Observable cross-user profile collision detected |
| **Privilege Boundary** | 8 | 8 | 0 | 0 | 0 | Observable cross-role collision detected |
| **Stale Revocation** | 8 | 0 | **8** | 0 | 0 | **Missed 100%:** Same-user probe after revocation treated as benign hit |
| **Cache-Key Spoofing** | 6 | 6 | 0 | 0 | 0 | Observable spoofing collision detected |
| **Benign Controls** | 20 | 0 | 0 | **12** | 8 | **12 False Positives:** Flags 8 public docs and 4 intra-tenant shared dashboards |

### Category-Wise Confusion Matrix for Control: Single-User Reachability Control

| Vulnerability Category | Total in Corpus | True Positives (TP) | False Negatives (FN) | Category Recall | Root Cause of Missed Vulnerabilities |
|---|:---:|:---:|:---:|:---:|---|
| **Cross-Tenant** | 14 | 0 | **14** | **0.00%** | Single user (Alice vs. Alice); cross-tenant request boundaries never crossed. |
| **Cross-User** | 10 | 0 | **10** | **0.00%** | Single user (Alice vs. Alice); cross-user profile boundaries never crossed. |
| **Privilege Boundary** | 8 | 0 | **8** | **0.00%** | Single user (Alice vs. Alice); privilege boundaries never crossed. |
| **Stale Revocation** | 8 | 0 | **8** | **0.00%** | Single user (Alice vs. Alice) tested; origin returns authorized 200 OK without revocation trigger. |
| **Cache-Key Spoofing** | 6 | 0 | **6** | **0.00%** | Single user (Alice vs. Alice); headers match legitimate identity. |
| **Benign Controls** | 20 | 0 | 0 (TN: 20) | N/A | Public endpoints and Alice's own dashboards return authorized 200 OK without leakage. |

---

## 4. Multi-Seed Reproducibility Evaluation Across 5 Repetitions

To separate scenario-level statistical confidence intervals from repeated-run execution variability, 5 deterministic-seed repetitions were conducted:

| Repetition Seed | Recall | Precision | Specificity | Accuracy | Execution Duration (s) | Throughput (Req/s) |
|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Seed 42** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.8349s | 158.1 |
| **Seed 43** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.5206s | 253.5 |
| **Seed 44** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.6242s | 211.5 |
| **Seed 45** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.6812s | 193.8 |
| **Seed 46** | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.6700s | 197.0 |
| **Summary Statistics** | **1.0000 (std: 0.0)** | **1.0000 (std: 0.0)** | **1.0000 (std: 0.0)** | **1.0000 (std: 0.0)** | **0.6662s (std: 0.1143s)** | **202.8 (std: 34.6)** |

*Observation:* Across all 5 independent runs, detection metrics exhibit **zero variance** ($\sigma = 0.0000$), confirming that the methodology is completely deterministic and reproducible.


---

## 5. Statistical Scope, Confidence Intervals & Generalization Calibration

The quantitative evaluation is calibrated specifically against the controlled 66-scenario corpus (Dataset v1.1):
1. **Execution Stability vs. Population Generalization:** The multi-seed reproducibility experiment demonstrates execution stability, algorithmic determinism, and test harness repeatability across pseudo-random iterations. It should not be conflated with asymptotic generalization across thousands of unobserved real-world microarchitectures or proprietary edge CDN implementations.
2. **Confidence Intervals:** Classification results must be interpreted through the lens of the reported 95% Wilson score confidence intervals (e.g. Precision $[0.92, 1.00]$ on $V_1$ positive cases, $[0.68, 1.00]$ on $V_4$ revocation scenarios).
3. **Synthetic Ground-Truth Calibration:** The ground-truth oracle and proxy simulator accurately enforce RFC 9111 caching semantics. Empirical performance on real-world web applications will naturally vary according to header mutation proxies, non-standard CDN normalizing behavior, and application-specific session revocation latency.
