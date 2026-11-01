# TenantCache: Experimental Evaluation and Statistical Benchmark Report

## 1. Quantitative Benchmark Summary (with 95% Wilson Confidence Intervals)

| Framework / Approach | Archetype | Scenarios | TP | FP | TN | FN | Precision (95% CI) | Recall (95% CI) | F1 Score | Accuracy (95% CI) | Duration | Req/s |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Baseline A (Stateless Endpoint Testing)** | `V1_MISSING_TENANT_KEY` | 54 | 0 | 0 | 10 | 44 | *Undefined (N/A)* | 0.0000 `[0.00, 0.08]` | 0.0000 | 0.1852 `[0.10, 0.31]` | 0.237s | 227.4 |
| **Baseline B (Simple Identity Substitution)** | `V1_MISSING_TENANT_KEY` | 54 | 34 | 4 | 6 | 10 | 0.8947 `[0.76, 0.96]` | 0.7727 `[0.63, 0.87]` | 0.8293 | 0.7407 `[0.61, 0.84]` | 0.030s | 3616.0 |
| **TenantCache (Stateful Differential Verification)** | `V1_MISSING_TENANT_KEY` | 54 | 40 | 0 | 10 | 4 | 1.0000 `[0.91, 1.00]` | 0.9091 `[0.79, 0.96]` | 0.9524 | 0.9259 `[0.82, 0.97]` | 0.147s | 735.1 |
| **TenantCache (Stateful Differential Verification)** | `V2_MISSING_USER_AUTH` | 54 | 23 | 0 | 24 | 7 | 1.0000 `[0.86, 1.00]` | 0.7667 `[0.59, 0.88]` | 0.8679 | 0.8704 `[0.76, 0.94]` | 0.208s | 520.3 |
| **TenantCache (Stateful Differential Verification)** | `V3_UNVALIDATED_HEADER` | 54 | 23 | 0 | 24 | 7 | 1.0000 `[0.86, 1.00]` | 0.7667 `[0.59, 0.88]` | 0.8679 | 0.8704 `[0.76, 0.94]` | 0.214s | 504.1 |
| **TenantCache (Stateful Differential Verification)** | `V4_STALE_REVOCATION` | 54 | 4 | 0 | 46 | 4 | 1.0000 `[0.51, 1.00]` | 0.5000 `[0.22, 0.78]` | 0.6667 | 0.9259 `[0.82, 0.97]` | 0.270s | 400.8 |
| **TenantCache (Stateful Differential Verification)** | `V5_ERRONEOUS_PUBLIC` | 54 | 40 | 0 | 10 | 4 | 1.0000 `[0.91, 1.00]` | 0.9091 `[0.79, 0.96]` | 0.9524 | 0.9259 `[0.82, 0.97]` | 0.172s | 626.8 |
| **TenantCache (Stateful Differential Verification)** | `V6_NORMALIZATION` | 54 | 40 | 0 | 10 | 4 | 1.0000 `[0.91, 1.00]` | 0.9091 `[0.79, 0.96]` | 0.9524 | 0.9259 `[0.82, 0.97]` | 0.152s | 711.2 |
| **TenantCache (Stateful Differential Verification)** | `SECURE_S1_STRICT_PRIVATE` | 54 | 0 | 0 | 54 | 0 | 1.0000 `[0.00, 0.00]` | 1.0000 `[0.00, 0.00]` | 1.0000 | 1.0000 `[0.93, 1.00]` | 0.253s | 426.4 |
| **TenantCache (Stateful Differential Verification)** | `SECURE_S2_IDENTITY_KEYED` | 54 | 0 | 0 | 54 | 0 | 1.0000 `[0.00, 0.00]` | 1.0000 `[0.00, 0.00]` | 1.0000 | 1.0000 `[0.93, 1.00]` | 0.255s | 423.7 |

## 2. Statistical Invariant and Methodology Notes

- **Baseline A Precision:** When a baseline makes 0 positive predictions (TP=0, FP=0), Precision is mathematically undefined ($0/0$) and is explicitly reported as *Undefined (N/A)* rather than artificially defaulted to 1.0.
- **Wilson Score Intervals:** Reported as `[lower, upper]` at a 95% confidence level ($z = 1.96$), reflecting the sample size uncertainty over the 54-scenario benchmark corpus.
- **Expanded Corpus:** Evaluates 54 scenarios across 5 distinct enterprise tenants and multiple departments (14 cross-tenant, 10 cross-user private, 8 privilege boundary, 8 stateful revocation, 6 header spoofing, 8 benign public/shared controls).

## 3. Confirmed Vulnerability Findings Breakdown

| ID | Severity | Leakage Class | Target Endpoint | Victim Tenant | Adversary Principal | Detected Canary | Cache Status |
|---|---|---|---|---|---|---|:---:|
| `FINDING-1512121F` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_acme` | `tenant_beta::bob[admin]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-F94EE80A` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_acme` | `tenant_delta::david[admin]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-0E634300` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_acme` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-D59C00D4` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_acme` | `tenant_delta::diana[standard_user]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-CE02D22C` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_acme` | `tenant_epsilon::eric[guest]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-8DF3C681` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/invoices/inv-101` | `tenant_acme` | `tenant_beta::brian[standard_user]` | `TC_CANARY_e3c6f9b7...` | `HIT` |
| `FINDING-77C55219` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/invoices/inv-202` | `tenant_beta` | `tenant_acme::alex[standard_user]` | `TC_CANARY_af041e4d...` | `HIT` |
| `FINDING-F7E6EC56` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/invoices/inv-101` | `tenant_acme` | `tenant_delta::david[admin]` | `TC_CANARY_e3c6f9b7...` | `HIT` |
| `FINDING-E11F195F` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/invoices/inv-202` | `tenant_beta` | `tenant_epsilon::eric[guest]` | `TC_CANARY_af041e4d...` | `HIT` |
| `FINDING-6D73E4B5` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/invoices/inv-101` | `tenant_acme` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_e3c6f9b7...` | `HIT` |
| `FINDING-95E996AE` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/invoices/inv-202` | `tenant_beta` | `tenant_delta::diana[standard_user]` | `TC_CANARY_af041e4d...` | `HIT` |
| `FINDING-417548BB` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_acme::alex[standard_user]` | `TC_CANARY_38bceca1...` | `HIT` |
| `FINDING-842CA4E8` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_acme::amanda[standard_user]` | `TC_CANARY_38bceca1...` | `HIT` |
| `FINDING-9DEA3B79` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_beta::brian[standard_user]` | `TC_CANARY_38bceca1...` | `HIT` |
| `FINDING-805D8D58` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_beta::bob[admin]` | `TC_CANARY_38bceca1...` | `HIT` |
| `FINDING-3CE886B2` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_38bceca1...` | `HIT` |
| `FINDING-0353E359` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_delta::diana[standard_user]` | `TC_CANARY_38bceca1...` | `HIT` |
| `FINDING-1582819F` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_delta::david[admin]` | `TC_CANARY_38bceca1...` | `HIT` |
| `FINDING-FFC284EF` | **HIGH** | `PRIVILEGE_ESCALATION_LEAK` | `/api/v1/admin/audit-logs` | `tenant_acme` | `tenant_acme::alex[standard_user]` | `TC_CANARY_081d1fbe...` | `HIT` |
| `FINDING-0F8C66A5` | **HIGH** | `PRIVILEGE_ESCALATION_LEAK` | `/api/v1/admin/audit-logs` | `tenant_acme` | `tenant_acme::amanda[standard_user]` | `TC_CANARY_081d1fbe...` | `HIT` |
| `FINDING-354DC715` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/admin/audit-logs` | `tenant_acme` | `tenant_beta::brian[standard_user]` | `TC_CANARY_081d1fbe...` | `HIT` |
| `FINDING-35E08593` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/admin/audit-logs` | `tenant_acme` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_081d1fbe...` | `HIT` |
| `FINDING-5AD93B8B` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/admin/audit-logs` | `tenant_acme` | `tenant_delta::diana[standard_user]` | `TC_CANARY_081d1fbe...` | `HIT` |
| `FINDING-93702132` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/admin/audit-logs` | `tenant_acme` | `tenant_epsilon::eric[guest]` | `TC_CANARY_081d1fbe...` | `HIT` |
| `FINDING-7C8E6261` | **HIGH** | `STALE_REVOCATION_LEAK` | `/api/v1/shared/projects/proj-alpha` | `tenant_acme` | `tenant_acme::amanda[standard_user]` | `TC_CANARY_0c4938c7...` | `HIT` |
| `FINDING-729FAF4F` | **HIGH** | `CACHE_KEY_SPOOFING_LEAK` | `/api/v1/tenant/dashboard` | `tenant_acme` | `tenant_beta::bob[admin]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-815ABBFC` | **HIGH** | `CACHE_KEY_SPOOFING_LEAK` | `/api/v1/tenant/dashboard` | `tenant_acme` | `tenant_delta::david[admin]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-92E015B2` | **HIGH** | `CACHE_KEY_SPOOFING_LEAK` | `/api/v1/tenant/dashboard` | `tenant_acme` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-A5A35518` | **HIGH** | `CACHE_KEY_SPOOFING_LEAK` | `/api/v1/tenant/invoices/inv-101` | `tenant_acme` | `tenant_epsilon::eric[guest]` | `TC_CANARY_e3c6f9b7...` | `HIT` |
| `FINDING-E75607C5` | **HIGH** | `CACHE_KEY_SPOOFING_LEAK` | `/api/v1/tenant/invoices/inv-202` | `tenant_beta` | `tenant_delta::diana[standard_user]` | `TC_CANARY_af041e4d...` | `HIT` |
| `FINDING-E75C26A3` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_acme` | `tenant_beta::brian[standard_user]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-46DD9321` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_beta` | `tenant_acme::alice[admin]` | `TC_CANARY_3f932f1f...` | `HIT` |
| `FINDING-C81E3CF9` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_gamma` | `tenant_delta::david[admin]` | `TC_CANARY_4e016019...` | `HIT` |
| `FINDING-0251DE15` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_delta` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_48fa92a0...` | `HIT` |
| `FINDING-2192ADBE` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_beta` | `tenant_delta::diana[standard_user]` | `TC_CANARY_3f932f1f...` | `HIT` |
| `FINDING-54C82D58` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_delta` | `tenant_epsilon::eric[guest]` | `TC_CANARY_48fa92a0...` | `HIT` |
| `FINDING-78E492E1` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_acme::alice[admin]` | `TC_CANARY_66ad9c8e...` | `HIT` |
| `FINDING-4D6CBE0F` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_acme::alex[standard_user]` | `TC_CANARY_15a94a7e...` | `HIT` |
| `FINDING-197CFDF0` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_beta` | `tenant_beta::brian[standard_user]` | `TC_CANARY_c152670d...` | `HIT` |
| `FINDING-CB4BA983` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_beta` | `tenant_beta::bob[admin]` | `TC_CANARY_1bcc67ac...` | `HIT` |
| `FINDING-2C6794C9` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_delta` | `tenant_delta::diana[standard_user]` | `TC_CANARY_256d551c...` | `HIT` |
| `FINDING-5D2C93DF` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_acme::amanda[standard_user]` | `TC_CANARY_66ad9c8e...` | `HIT` |
| `FINDING-640973B6` | **HIGH** | `PRIVILEGE_ESCALATION_LEAK` | `/api/v1/admin/audit-logs` | `tenant_beta` | `tenant_beta::brian[standard_user]` | `TC_CANARY_a120535f...` | `HIT` |
| `FINDING-1F7E96F7` | **HIGH** | `PRIVILEGE_ESCALATION_LEAK` | `/api/v1/admin/audit-logs` | `tenant_gamma` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_85720407...` | `HIT` |
| `FINDING-A90D1871` | **HIGH** | `PRIVILEGE_ESCALATION_LEAK` | `/api/v1/admin/audit-logs` | `tenant_delta` | `tenant_delta::diana[standard_user]` | `TC_CANARY_392baa5e...` | `HIT` |
| `FINDING-58B9B927` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/admin/audit-logs` | `tenant_beta` | `tenant_epsilon::eric[guest]` | `TC_CANARY_a120535f...` | `HIT` |
| `FINDING-516267EB` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/admin/audit-logs` | `tenant_delta` | `tenant_epsilon::eric[guest]` | `TC_CANARY_392baa5e...` | `HIT` |
| `FINDING-6037AEB3` | **HIGH** | `STALE_REVOCATION_LEAK` | `/api/v1/shared/projects/proj-alpha` | `tenant_acme` | `tenant_acme::alex[standard_user]` | `TC_CANARY_0c4938c7...` | `HIT` |
| `FINDING-B2927B72` | **HIGH** | `STALE_REVOCATION_LEAK` | `/api/v1/shared/projects/proj-titan` | `tenant_beta` | `tenant_beta::brian[standard_user]` | `TC_CANARY_4cb9de3a...` | `HIT` |
| `FINDING-EEB081B3` | **HIGH** | `STALE_REVOCATION_LEAK` | `/api/v1/shared/projects/proj-neural` | `tenant_gamma` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_16df738c...` | `HIT` |
| `FINDING-F67DDBE4` | **HIGH** | `STALE_REVOCATION_LEAK` | `/api/v1/shared/projects/proj-quantum` | `tenant_delta` | `tenant_delta::diana[standard_user]` | `TC_CANARY_1646ff19...` | `HIT` |
| `FINDING-6B403DC3` | **HIGH** | `CACHE_KEY_SPOOFING_LEAK` | `/api/v1/tenant/dashboard` | `tenant_beta` | `tenant_acme::alice[admin]` | `TC_CANARY_3f932f1f...` | `HIT` |
| `FINDING-EDEA4C14` | **HIGH** | `CACHE_KEY_SPOOFING_LEAK` | `/api/v1/tenant/dashboard` | `tenant_gamma` | `tenant_delta::david[admin]` | `TC_CANARY_4e016019...` | `HIT` |
| `FINDING-77D23EF3` | **HIGH** | `CACHE_KEY_SPOOFING_LEAK` | `/api/v1/tenant/dashboard` | `tenant_delta` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_48fa92a0...` | `HIT` |
