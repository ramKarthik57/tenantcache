# TenantCache: Experimental Evaluation and Benchmark Report

## 1. Quantitative Benchmark Summary

| Framework / Approach | Configuration Mode | Total Scenarios | TP | FP | TN | FN | Precision | Recall | F1 Score | Accuracy | Duration (s) | Req/s |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Baseline A (Stateless Endpoint Testing)** | `V1_MISSING_TENANT_KEY` | 9 | 0 | 0 | 2 | 7 | 1.0000 | 0.0000 | 0.0000 | 0.2222 | 0.127 | 71.1 |
| **Baseline B (Simple Identity Substitution)** | `V1_MISSING_TENANT_KEY` | 9 | 5 | 0 | 2 | 2 | 1.0000 | 0.7143 | 0.8333 | 0.7778 | 0.014 | 1264.8 |
| **TenantCache (Stateful Differential Verification)** | `V1_MISSING_TENANT_KEY` | 9 | 7 | 0 | 2 | 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.025 | 711.3 |
| **TenantCache (Stateful Differential Verification)** | `V2_MISSING_USER_AUTH` | 9 | 4 | 0 | 5 | 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.031 | 586.1 |
| **TenantCache (Stateful Differential Verification)** | `V3_UNVALIDATED_HEADER` | 9 | 4 | 0 | 5 | 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.033 | 553.5 |
| **TenantCache (Stateful Differential Verification)** | `V4_STALE_REVOCATION` | 9 | 1 | 0 | 8 | 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.040 | 449.9 |
| **TenantCache (Stateful Differential Verification)** | `V5_ERRONEOUS_PUBLIC` | 9 | 7 | 0 | 2 | 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.022 | 821.0 |
| **TenantCache (Stateful Differential Verification)** | `V6_NORMALIZATION` | 9 | 7 | 0 | 2 | 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.022 | 829.9 |
| **TenantCache (Stateful Differential Verification)** | `SECURE_S1_STRICT_PRIVATE` | 9 | 0 | 0 | 9 | 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.042 | 425.6 |
| **TenantCache (Stateful Differential Verification)** | `SECURE_S2_IDENTITY_KEYED` | 9 | 0 | 0 | 9 | 0 | 1.0000 | 1.0000 | 1.0000 | 1.0000 | 0.045 | 395.4 |

## 2. Confirmed Vulnerability Findings Breakdown

| ID | Severity | Leakage Class | Target Endpoint | Victim Tenant | Adversary Principal | Detected Canary | Cache Status |
|---|---|---|---|---|---|---|:---:|
| `FINDING-ADEB70A9` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_acme` | `tenant_beta::bob[admin]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-DD04149C` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/invoices/inv-101` | `tenant_acme` | `tenant_beta::brian[standard_user]` | `TC_CANARY_d1b19514...` | `HIT` |
| `FINDING-A9D4399B` | **HIGH** | `PRIVILEGE_ESCALATION_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_acme::alex[standard_user]` | `TC_CANARY_38bceca1...` | `HIT` |
| `FINDING-49E276EE` | **HIGH** | `PRIVILEGE_ESCALATION_LEAK` | `/api/v1/admin/audit-logs` | `tenant_acme` | `tenant_acme::alex[standard_user]` | `TC_CANARY_d0896b1b...` | `HIT` |
| `FINDING-110EC390` | **HIGH** | `CACHE_KEY_SPOOFING_LEAK` | `/api/v1/tenant/dashboard` | `tenant_acme` | `tenant_beta::bob[admin]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-C20FB8E3` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_beta` | `tenant_acme::alice[admin]` | `TC_CANARY_3f932f1f...` | `HIT` |
| `FINDING-DA99A383` | **HIGH** | `STALE_REVOCATION_LEAK` | `/api/v1/shared/projects/proj-alpha` | `tenant_acme` | `tenant_acme::alex[standard_user]` | `TC_CANARY_8ac87b18...` | `HIT` |
