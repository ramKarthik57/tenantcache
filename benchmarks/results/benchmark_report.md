# TenantCache: Experimental Evaluation and Statistical Benchmark Report

## 1. Quantitative Benchmark Summary (with 95% Wilson Confidence Intervals)

| Framework / Approach | Archetype | Scenarios | TP | FP | TN | FN | Precision (95% CI) | Recall (95% CI) | Specificity (95% CI) | Accuracy (95% CI) | FPR | Resets | Trans | Principals | Duration |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Baseline A (Stateless Endpoint Testing)** | `V1_MISSING_TENANT_KEY` | 54 | 0 | 0 | 10 | 44 | *N/A (Undefined)* | 0.0000 `[0.00, 0.08]` | 1.0000 `[0.72, 1.00]` | 0.1852 `[0.10, 0.31]` | 0.00 | 54 | 0 | 9 | 0.236s |
| **Baseline B (Simple Identity Substitution)** | `V1_MISSING_TENANT_KEY` | 54 | 33 | 8 | 2 | 11 | 0.8049 `[0.66, 0.90]` | 0.7500 `[0.61, 0.85]` | 0.2000 `[0.06, 0.51]` | 0.6481 `[0.51, 0.76]` | 0.80 | 0 | 0 | 10 | 0.037s |
| **TenantCache (Stateful Differential Verification)** | `V1_MISSING_TENANT_KEY` | 54 | 44 | 0 | 10 | 0 | 1.0000 `[0.92, 1.00]` | 1.0000 `[0.92, 1.00]` | 1.0000 `[0.72, 1.00]` | 1.0000 `[0.93, 1.00]` | 0.00 | 54 | 8 | 9 | 0.148s |
| **TenantCache (Stateful Differential Verification)** | `V2_MISSING_USER_AUTH` | 54 | 27 | 0 | 24 | 3 | 1.0000 `[0.88, 1.00]` | 0.9000 `[0.74, 0.97]` | 1.0000 `[0.86, 1.00]` | 0.9444 `[0.85, 0.98]` | 0.00 | 54 | 8 | 9 | 0.197s |
| **TenantCache (Stateful Differential Verification)** | `V3_UNVALIDATED_HEADER` | 54 | 27 | 0 | 24 | 3 | 1.0000 `[0.88, 1.00]` | 0.9000 `[0.74, 0.97]` | 1.0000 `[0.86, 1.00]` | 0.9444 `[0.85, 0.98]` | 0.00 | 54 | 8 | 9 | 0.224s |
| **TenantCache (Stateful Differential Verification)** | `V4_STALE_REVOCATION` | 54 | 8 | 0 | 46 | 0 | 1.0000 `[0.68, 1.00]` | 1.0000 `[0.68, 1.00]` | 1.0000 `[0.92, 1.00]` | 1.0000 `[0.93, 1.00]` | 0.00 | 54 | 8 | 9 | 0.277s |
| **TenantCache (Stateful Differential Verification)** | `V5_ERRONEOUS_PUBLIC` | 54 | 44 | 0 | 10 | 0 | 1.0000 `[0.92, 1.00]` | 1.0000 `[0.92, 1.00]` | 1.0000 `[0.72, 1.00]` | 1.0000 `[0.93, 1.00]` | 0.00 | 54 | 8 | 9 | 0.150s |
| **TenantCache (Stateful Differential Verification)** | `V6_NORMALIZATION` | 54 | 44 | 0 | 10 | 0 | 1.0000 `[0.92, 1.00]` | 1.0000 `[0.92, 1.00]` | 1.0000 `[0.72, 1.00]` | 1.0000 `[0.93, 1.00]` | 0.00 | 54 | 8 | 9 | 0.143s |
| **TenantCache (Stateful Differential Verification)** | `SECURE_S1_STRICT_PRIVATE` | 54 | 0 | 0 | 54 | 0 | *N/A (Undefined)* | *N/A (Undefined)* | 1.0000 `[0.93, 1.00]` | 1.0000 `[0.93, 1.00]` | 0.00 | 54 | 8 | 9 | 0.262s |
| **TenantCache (Stateful Differential Verification)** | `SECURE_S2_IDENTITY_KEYED` | 54 | 0 | 0 | 54 | 0 | *N/A (Undefined)* | *N/A (Undefined)* | 1.0000 `[0.93, 1.00]` | 1.0000 `[0.93, 1.00]` | 0.00 | 54 | 8 | 9 | 0.268s |

## 2. Statistical Invariant and Methodology Notes

- **Zero-Denominator Precision & Recall (Secure S1 & S2):** When a secure configuration yields 0 positive scenarios ($TP + FP = 0, TP + FN = 0$), Precision and Recall are mathematically undefined and reported as *N/A (Undefined)*. Specificity is calculated as $TN / (TN + FP) = 54/54 = 1.000$ (with Wilson CI $[0.93, 1.00]$) and Accuracy is $1.000$.
- **Baseline A Precision:** When Baseline A generates zero positive predictions ($TP=0, FP=0$), Precision is mathematically undefined and reported as *N/A (Undefined)*.
- **Exploration Budget Documentation:** Baseline comparisons track explicit operational parameters: `Total Requests`, `Cache Resets`, `State Transitions`, and `Distinct Principals Covered`.
- **Wilson Score Intervals:** Calculated at a 95% confidence level ($z = 1.96$), capturing sample size uncertainty over the 54-scenario benchmark corpus.

## 3. Confirmed Vulnerability Findings Breakdown

| ID | Severity | Leakage Class | Target Endpoint | Victim Tenant | Adversary Principal | Detected Canary | Cache Status |
|---|---|---|---|---|---|---|:---:|
| `FINDING-33A10857` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_acme` | `tenant_beta::bob[admin]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-969B0E6A` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_acme` | `tenant_delta::david[admin]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-12272C2C` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_acme` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-717EE2D7` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_acme` | `tenant_delta::diana[standard_user]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-76D33D05` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_acme` | `tenant_epsilon::eric[guest]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-C2AFCF8A` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/invoices/inv-101` | `tenant_acme` | `tenant_beta::brian[standard_user]` | `TC_CANARY_e3c6f9b7...` | `HIT` |
| `FINDING-9D32AF77` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/invoices/inv-202` | `tenant_beta` | `tenant_acme::alex[standard_user]` | `TC_CANARY_af041e4d...` | `HIT` |
| `FINDING-085B177D` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/invoices/inv-101` | `tenant_acme` | `tenant_delta::david[admin]` | `TC_CANARY_e3c6f9b7...` | `HIT` |
| `FINDING-E8A7CAF2` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/invoices/inv-202` | `tenant_beta` | `tenant_epsilon::eric[guest]` | `TC_CANARY_af041e4d...` | `HIT` |
| `FINDING-836E9410` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/invoices/inv-101` | `tenant_acme` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_e3c6f9b7...` | `HIT` |
| `FINDING-CCCD4303` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/invoices/inv-202` | `tenant_beta` | `tenant_delta::diana[standard_user]` | `TC_CANARY_af041e4d...` | `HIT` |
| `FINDING-66C04A51` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_acme::alex[standard_user]` | `TC_CANARY_38bceca1...` | `HIT` |
| `FINDING-6EC7091E` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_acme::amanda[standard_user]` | `TC_CANARY_38bceca1...` | `HIT` |
| `FINDING-8A51EF11` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_beta::brian[standard_user]` | `TC_CANARY_38bceca1...` | `HIT` |
| `FINDING-D440ADFC` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_beta::bob[admin]` | `TC_CANARY_38bceca1...` | `HIT` |
| `FINDING-00BE5A9B` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_38bceca1...` | `HIT` |
| `FINDING-14C53BBC` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_delta::diana[standard_user]` | `TC_CANARY_38bceca1...` | `HIT` |
| `FINDING-76CD1D93` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_delta::david[admin]` | `TC_CANARY_38bceca1...` | `HIT` |
| `FINDING-ED009616` | **HIGH** | `PRIVILEGE_ESCALATION_LEAK` | `/api/v1/admin/audit-logs` | `tenant_acme` | `tenant_acme::alex[standard_user]` | `TC_CANARY_081d1fbe...` | `HIT` |
| `FINDING-B5E7EEEE` | **HIGH** | `PRIVILEGE_ESCALATION_LEAK` | `/api/v1/admin/audit-logs` | `tenant_acme` | `tenant_acme::amanda[standard_user]` | `TC_CANARY_081d1fbe...` | `HIT` |
| `FINDING-D57BC066` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/admin/audit-logs` | `tenant_acme` | `tenant_beta::brian[standard_user]` | `TC_CANARY_081d1fbe...` | `HIT` |
| `FINDING-7CB0DB1F` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/admin/audit-logs` | `tenant_acme` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_081d1fbe...` | `HIT` |
| `FINDING-B117D476` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/admin/audit-logs` | `tenant_acme` | `tenant_delta::diana[standard_user]` | `TC_CANARY_081d1fbe...` | `HIT` |
| `FINDING-A0B90D93` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/admin/audit-logs` | `tenant_acme` | `tenant_epsilon::eric[guest]` | `TC_CANARY_081d1fbe...` | `HIT` |
| `FINDING-E81598A5` | **HIGH** | `CACHE_KEY_SPOOFING_LEAK` | `/api/v1/tenant/dashboard` | `tenant_acme` | `tenant_beta::bob[admin]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-BAA99F6E` | **HIGH** | `CACHE_KEY_SPOOFING_LEAK` | `/api/v1/tenant/dashboard` | `tenant_acme` | `tenant_delta::david[admin]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-25CC0081` | **HIGH** | `CACHE_KEY_SPOOFING_LEAK` | `/api/v1/tenant/dashboard` | `tenant_acme` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-B248D92D` | **HIGH** | `CACHE_KEY_SPOOFING_LEAK` | `/api/v1/tenant/invoices/inv-101` | `tenant_acme` | `tenant_epsilon::eric[guest]` | `TC_CANARY_e3c6f9b7...` | `HIT` |
| `FINDING-370287E8` | **HIGH** | `CACHE_KEY_SPOOFING_LEAK` | `/api/v1/tenant/invoices/inv-202` | `tenant_beta` | `tenant_delta::diana[standard_user]` | `TC_CANARY_af041e4d...` | `HIT` |
| `FINDING-824D1940` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_acme` | `tenant_beta::brian[standard_user]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-08304813` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_beta` | `tenant_acme::alice[admin]` | `TC_CANARY_3f932f1f...` | `HIT` |
| `FINDING-EB02D545` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_gamma` | `tenant_delta::david[admin]` | `TC_CANARY_4e016019...` | `HIT` |
| `FINDING-41F3B170` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_delta` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_48fa92a0...` | `HIT` |
| `FINDING-F8ED6FFB` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_beta` | `tenant_delta::diana[standard_user]` | `TC_CANARY_3f932f1f...` | `HIT` |
| `FINDING-193CEBE1` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_delta` | `tenant_epsilon::eric[guest]` | `TC_CANARY_48fa92a0...` | `HIT` |
| `FINDING-ADF8D17C` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_acme::alice[admin]` | `TC_CANARY_66ad9c8e...` | `HIT` |
| `FINDING-9C787F04` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_acme::alex[standard_user]` | `TC_CANARY_15a94a7e...` | `HIT` |
| `FINDING-F7471604` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_beta` | `tenant_beta::brian[standard_user]` | `TC_CANARY_c152670d...` | `HIT` |
| `FINDING-9B92E8F9` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_beta` | `tenant_beta::bob[admin]` | `TC_CANARY_1bcc67ac...` | `HIT` |
| `FINDING-6FED9ECE` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_delta` | `tenant_delta::diana[standard_user]` | `TC_CANARY_256d551c...` | `HIT` |
| `FINDING-3F5955D0` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_acme::amanda[standard_user]` | `TC_CANARY_66ad9c8e...` | `HIT` |
| `FINDING-866B07AE` | **HIGH** | `PRIVILEGE_ESCALATION_LEAK` | `/api/v1/admin/audit-logs` | `tenant_beta` | `tenant_beta::brian[standard_user]` | `TC_CANARY_a120535f...` | `HIT` |
| `FINDING-7FD99B96` | **HIGH** | `PRIVILEGE_ESCALATION_LEAK` | `/api/v1/admin/audit-logs` | `tenant_gamma` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_85720407...` | `HIT` |
| `FINDING-46A0A73E` | **HIGH** | `PRIVILEGE_ESCALATION_LEAK` | `/api/v1/admin/audit-logs` | `tenant_delta` | `tenant_delta::diana[standard_user]` | `TC_CANARY_392baa5e...` | `HIT` |
| `FINDING-565E4471` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/admin/audit-logs` | `tenant_beta` | `tenant_epsilon::eric[guest]` | `TC_CANARY_a120535f...` | `HIT` |
| `FINDING-2ACA5548` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/admin/audit-logs` | `tenant_delta` | `tenant_epsilon::eric[guest]` | `TC_CANARY_392baa5e...` | `HIT` |
| `FINDING-C415FEC2` | **HIGH** | `STALE_REVOCATION_LEAK` | `/api/v1/shared/projects/proj-alpha` | `tenant_acme` | `tenant_acme::alex[standard_user]` | `TC_CANARY_797b28a1...` | `HIT` |
| `FINDING-77A2B5A5` | **HIGH** | `STALE_REVOCATION_LEAK` | `/api/v1/shared/projects/proj-titan` | `tenant_beta` | `tenant_beta::brian[standard_user]` | `TC_CANARY_40fc7aee...` | `HIT` |
| `FINDING-4B2E84F9` | **HIGH** | `STALE_REVOCATION_LEAK` | `/api/v1/shared/projects/proj-neural` | `tenant_gamma` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_e0c79c1b...` | `HIT` |
| `FINDING-85430DCE` | **HIGH** | `STALE_REVOCATION_LEAK` | `/api/v1/shared/projects/proj-quantum` | `tenant_delta` | `tenant_delta::diana[standard_user]` | `TC_CANARY_21f64ea9...` | `HIT` |
| `FINDING-B16CFD08` | **HIGH** | `STALE_REVOCATION_LEAK` | `/api/v1/shared/projects/proj-supply` | `tenant_acme` | `tenant_acme::amanda[standard_user]` | `TC_CANARY_b3fef7ee...` | `HIT` |
| `FINDING-2071427D` | **HIGH** | `STALE_REVOCATION_LEAK` | `/api/v1/shared/projects/proj-audit` | `tenant_beta` | `tenant_beta::brian[standard_user]` | `TC_CANARY_f744d4f7...` | `HIT` |
| `FINDING-8363D55E` | **HIGH** | `STALE_REVOCATION_LEAK` | `/api/v1/shared/projects/proj-cloud` | `tenant_gamma` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_ae6227eb...` | `HIT` |
| `FINDING-5C53BE4C` | **HIGH** | `STALE_REVOCATION_LEAK` | `/api/v1/shared/projects/proj-crypto` | `tenant_delta` | `tenant_delta::diana[standard_user]` | `TC_CANARY_0435622c...` | `HIT` |
| `FINDING-AE679DB0` | **HIGH** | `CACHE_KEY_SPOOFING_LEAK` | `/api/v1/tenant/dashboard` | `tenant_beta` | `tenant_acme::alice[admin]` | `TC_CANARY_3f932f1f...` | `HIT` |
| `FINDING-8CD03620` | **HIGH** | `CACHE_KEY_SPOOFING_LEAK` | `/api/v1/tenant/dashboard` | `tenant_gamma` | `tenant_delta::david[admin]` | `TC_CANARY_4e016019...` | `HIT` |
| `FINDING-ADEDF81B` | **HIGH** | `CACHE_KEY_SPOOFING_LEAK` | `/api/v1/tenant/dashboard` | `tenant_delta` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_48fa92a0...` | `HIT` |
