# TenantCache: Experimental Evaluation and Statistical Benchmark Report

## 1. Quantitative Benchmark Summary (with 95% Wilson Confidence Intervals)

| Framework / Approach | Archetype | Scenarios | TP | FP | TN | FN | Precision (95% CI) | Recall (95% CI) | Specificity (95% CI) | Accuracy (95% CI) | FPR | Resets | Trans | Principals | Duration |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Baseline A (Matched-Budget Stateless DAST)** | `V1_MISSING_TENANT_KEY` | 66 | 0 | 0 | 20 | 46 | *N/A (Undefined)* | 0.0000 `[0.00, 0.08]` | 1.0000 `[0.84, 1.00]` | 0.3030 `[0.21, 0.42]` | 0.00 | 66 | 0 | 10 | 1.445s |
| **Baseline B (Matched-Budget Naive Diffing)** | `V1_MISSING_TENANT_KEY` | 66 | 34 | 17 | 5 | 10 | 0.6667 `[0.53, 0.78]` | 0.7727 `[0.63, 0.87]` | 0.2273 `[0.10, 0.43]` | 0.5909 `[0.47, 0.70]` | 0.77 | 0 | 0 | 10 | 0.127s |
| **Baseline A (Capability Stateless DAST)** | `V1_MISSING_TENANT_KEY` | 66 | 0 | 0 | 20 | 46 | *N/A (Undefined)* | 0.0000 `[0.00, 0.08]` | 1.0000 `[0.84, 1.00]` | 0.3030 `[0.21, 0.42]` | 0.00 | 66 | 0 | 10 | 0.535s |
| **Baseline B (Capability Naive Diffing)** | `V1_MISSING_TENANT_KEY` | 66 | 34 | 17 | 5 | 10 | 0.6667 `[0.53, 0.78]` | 0.7727 `[0.63, 0.87]` | 0.2273 `[0.10, 0.43]` | 0.5909 `[0.47, 0.70]` | 0.77 | 0 | 0 | 10 | 0.125s |
| **TenantCache (Capability Verification)** | `V1_MISSING_TENANT_KEY` | 66 | 46 | 0 | 20 | 0 | 1.0000 `[0.92, 1.00]` | 1.0000 `[0.92, 1.00]` | 1.0000 `[0.84, 1.00]` | 1.0000 `[0.94, 1.00]` | 0.00 | 66 | 8 | 10 | 0.521s |
| **TenantCache (Capability Verification)** | `V2_MISSING_USER_AUTH` | 66 | 29 | 0 | 34 | 3 | 1.0000 `[0.88, 1.00]` | 0.9062 `[0.76, 0.97]` | 1.0000 `[0.90, 1.00]` | 0.9545 `[0.87, 0.98]` | 0.00 | 66 | 8 | 10 | 0.744s |
| **TenantCache (Capability Verification)** | `V3_UNVALIDATED_HEADER` | 66 | 29 | 0 | 34 | 3 | 1.0000 `[0.88, 1.00]` | 0.9062 `[0.76, 0.97]` | 1.0000 `[0.90, 1.00]` | 0.9545 `[0.87, 0.98]` | 0.00 | 66 | 8 | 10 | 0.711s |
| **TenantCache (Capability Verification)** | `V4_STALE_REVOCATION` | 66 | 8 | 0 | 58 | 0 | 1.0000 `[0.68, 1.00]` | 1.0000 `[0.68, 1.00]` | 1.0000 `[0.94, 1.00]` | 1.0000 `[0.94, 1.00]` | 0.00 | 66 | 8 | 10 | 0.948s |
| **TenantCache (Capability Verification)** | `V5_ERRONEOUS_PUBLIC` | 66 | 46 | 0 | 20 | 0 | 1.0000 `[0.92, 1.00]` | 1.0000 `[0.92, 1.00]` | 1.0000 `[0.84, 1.00]` | 1.0000 `[0.94, 1.00]` | 0.00 | 66 | 8 | 10 | 0.603s |
| **TenantCache (Capability Verification)** | `V6_NORMALIZATION` | 66 | 46 | 0 | 20 | 0 | 1.0000 `[0.92, 1.00]` | 1.0000 `[0.92, 1.00]` | 1.0000 `[0.84, 1.00]` | 1.0000 `[0.94, 1.00]` | 0.00 | 66 | 8 | 10 | 0.599s |
| **TenantCache (Capability Verification)** | `SECURE_S1_STRICT_PRIVATE` | 66 | 0 | 0 | 66 | 0 | *N/A (Undefined)* | *N/A (Undefined)* | 1.0000 `[0.94, 1.00]` | 1.0000 `[0.94, 1.00]` | 0.00 | 66 | 8 | 10 | 1.071s |
| **TenantCache (Capability Verification)** | `SECURE_S2_IDENTITY_KEYED` | 66 | 0 | 0 | 66 | 0 | *N/A (Undefined)* | *N/A (Undefined)* | 1.0000 `[0.94, 1.00]` | 1.0000 `[0.94, 1.00]` | 0.00 | 66 | 8 | 10 | 1.107s |

## 2. Statistical Invariant and Methodology Notes

- **Zero-Denominator Precision & Recall (Secure S1 & S2):** When a secure configuration yields 0 positive scenarios ($TP + FP = 0, TP + FN = 0$), Precision and Recall are mathematically undefined and reported as *N/A (Undefined)*. Specificity is calculated as $TN / (TN + FP) = 54/54 = 1.000$ (with Wilson CI $[0.93, 1.00]$) and Accuracy is $1.000$.
- **Baseline A Precision:** When Baseline A generates zero positive predictions ($TP=0, FP=0$), Precision is mathematically undefined and reported as *N/A (Undefined)*.
- **Exploration Budget Documentation:** Baseline comparisons track explicit operational parameters: `Total Requests`, `Cache Resets`, `State Transitions`, and `Distinct Principals Covered`.
- **Wilson Score Intervals:** Calculated at a 95% confidence level ($z = 1.96$), capturing sample size uncertainty over the 54-scenario benchmark corpus.

## 3. Confirmed Vulnerability Findings Breakdown

| ID | Severity | Leakage Class | Target Endpoint | Victim Tenant | Adversary Principal | Detected Canary | Cache Status |
|---|---|---|---|---|---|---|:---:|
| `FINDING-F6638AA2` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_acme` | `tenant_beta::bob[admin]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-586E1E94` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_acme` | `tenant_delta::david[admin]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-0B290F3A` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_acme` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-8DDB6CFC` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_acme` | `tenant_delta::diana[standard_user]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-B3103512` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_acme` | `tenant_epsilon::eric[guest]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-70D74C2C` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/invoices/inv-101` | `tenant_acme` | `tenant_beta::brian[standard_user]` | `TC_CANARY_e3c6f9b7...` | `HIT` |
| `FINDING-369C9B8E` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/invoices/inv-202` | `tenant_beta` | `tenant_acme::alex[standard_user]` | `TC_CANARY_af041e4d...` | `HIT` |
| `FINDING-4F464F1F` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/invoices/inv-101` | `tenant_acme` | `tenant_delta::david[admin]` | `TC_CANARY_e3c6f9b7...` | `HIT` |
| `FINDING-7E827C6F` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/invoices/inv-202` | `tenant_beta` | `tenant_epsilon::eric[guest]` | `TC_CANARY_af041e4d...` | `HIT` |
| `FINDING-C51F3DFD` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/invoices/inv-101` | `tenant_acme` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_e3c6f9b7...` | `HIT` |
| `FINDING-18ED7CD1` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/invoices/inv-202` | `tenant_beta` | `tenant_delta::diana[standard_user]` | `TC_CANARY_af041e4d...` | `HIT` |
| `FINDING-CBF2805A` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_acme::alex[standard_user]` | `TC_CANARY_38bceca1...` | `HIT` |
| `FINDING-80E81DA6` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_acme::amanda[standard_user]` | `TC_CANARY_38bceca1...` | `HIT` |
| `FINDING-1BF708D3` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_beta::brian[standard_user]` | `TC_CANARY_38bceca1...` | `HIT` |
| `FINDING-DF76C12F` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_beta::bob[admin]` | `TC_CANARY_38bceca1...` | `HIT` |
| `FINDING-34E9B5AF` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_gamma::clara[admin]` | `TC_CANARY_38bceca1...` | `HIT` |
| `FINDING-D48AA890` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_delta::diana[standard_user]` | `TC_CANARY_38bceca1...` | `HIT` |
| `FINDING-1DD8C8DC` | **HIGH** | `PRIVILEGE_ESCALATION_LEAK` | `/api/v1/admin/audit-logs` | `tenant_acme` | `tenant_acme::alex[standard_user]` | `TC_CANARY_081d1fbe...` | `HIT` |
| `FINDING-8D628601` | **HIGH** | `PRIVILEGE_ESCALATION_LEAK` | `/api/v1/admin/audit-logs` | `tenant_acme` | `tenant_acme::amanda[standard_user]` | `TC_CANARY_081d1fbe...` | `HIT` |
| `FINDING-5EF03FB4` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/admin/audit-logs` | `tenant_acme` | `tenant_beta::brian[standard_user]` | `TC_CANARY_081d1fbe...` | `HIT` |
| `FINDING-6CC8B1B1` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/admin/audit-logs` | `tenant_acme` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_081d1fbe...` | `HIT` |
| `FINDING-73214978` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/admin/audit-logs` | `tenant_acme` | `tenant_delta::diana[standard_user]` | `TC_CANARY_081d1fbe...` | `HIT` |
| `FINDING-2FC86C0C` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/admin/audit-logs` | `tenant_acme` | `tenant_epsilon::eric[guest]` | `TC_CANARY_081d1fbe...` | `HIT` |
| `FINDING-0645189E` | **HIGH** | `CACHE_KEY_SPOOFING_LEAK` | `/api/v1/tenant/dashboard` | `tenant_acme` | `tenant_beta::bob[admin]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-6E2E46EF` | **HIGH** | `CACHE_KEY_SPOOFING_LEAK` | `/api/v1/tenant/dashboard` | `tenant_acme` | `tenant_delta::david[admin]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-29CC1D13` | **HIGH** | `CACHE_KEY_SPOOFING_LEAK` | `/api/v1/tenant/dashboard` | `tenant_acme` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-056E8601` | **HIGH** | `CACHE_KEY_SPOOFING_LEAK` | `/api/v1/tenant/invoices/inv-101` | `tenant_acme` | `tenant_epsilon::eric[guest]` | `TC_CANARY_e3c6f9b7...` | `HIT` |
| `FINDING-042E248F` | **HIGH** | `CACHE_KEY_SPOOFING_LEAK` | `/api/v1/tenant/invoices/inv-202` | `tenant_beta` | `tenant_delta::diana[standard_user]` | `TC_CANARY_af041e4d...` | `HIT` |
| `FINDING-909D1A5B` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_acme` | `tenant_beta::brian[standard_user]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-47BE0B9E` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_38bceca1...` | `HIT` |
| `FINDING-9B335A41` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_delta::david[admin]` | `TC_CANARY_38bceca1...` | `HIT` |
| `FINDING-71880882` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_beta` | `tenant_acme::alice[admin]` | `TC_CANARY_3f932f1f...` | `HIT` |
| `FINDING-6A6CD1AB` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_gamma` | `tenant_delta::david[admin]` | `TC_CANARY_4e016019...` | `HIT` |
| `FINDING-9124311D` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_delta` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_48fa92a0...` | `HIT` |
| `FINDING-B1F571E9` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_beta` | `tenant_delta::diana[standard_user]` | `TC_CANARY_3f932f1f...` | `HIT` |
| `FINDING-A8EFCAA5` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_delta` | `tenant_epsilon::eric[guest]` | `TC_CANARY_48fa92a0...` | `HIT` |
| `FINDING-5C209D3C` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_acme::alice[admin]` | `TC_CANARY_66ad9c8e...` | `HIT` |
| `FINDING-C275D007` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_acme::alex[standard_user]` | `TC_CANARY_15a94a7e...` | `HIT` |
| `FINDING-10238639` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_acme::alice[admin]` | `TC_CANARY_15a94a7e...` | `HIT` |
| `FINDING-358C39D4` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_acme::amanda[standard_user]` | `TC_CANARY_66ad9c8e...` | `HIT` |
| `FINDING-7EFD2E94` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_beta` | `tenant_beta::brian[standard_user]` | `TC_CANARY_c152670d...` | `HIT` |
| `FINDING-9C74462B` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_beta` | `tenant_beta::bob[admin]` | `TC_CANARY_1bcc67ac...` | `HIT` |
| `FINDING-12FB3C3A` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_gamma` | `tenant_gamma::clara[admin]` | `TC_CANARY_54d56fd3...` | `HIT` |
| `FINDING-11FBC8ED` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_delta` | `tenant_delta::diana[standard_user]` | `TC_CANARY_256d551c...` | `HIT` |
| `FINDING-5F494E85` | **HIGH** | `PRIVILEGE_ESCALATION_LEAK` | `/api/v1/admin/audit-logs` | `tenant_beta` | `tenant_beta::brian[standard_user]` | `TC_CANARY_a120535f...` | `HIT` |
| `FINDING-D1C284F9` | **HIGH** | `PRIVILEGE_ESCALATION_LEAK` | `/api/v1/admin/audit-logs` | `tenant_gamma` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_85720407...` | `HIT` |
| `FINDING-9C822C1D` | **HIGH** | `PRIVILEGE_ESCALATION_LEAK` | `/api/v1/admin/audit-logs` | `tenant_delta` | `tenant_delta::diana[standard_user]` | `TC_CANARY_392baa5e...` | `HIT` |
| `FINDING-6C4BC8AD` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/admin/audit-logs` | `tenant_beta` | `tenant_epsilon::eric[guest]` | `TC_CANARY_a120535f...` | `HIT` |
| `FINDING-D6CEF7ED` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/admin/audit-logs` | `tenant_delta` | `tenant_epsilon::eric[guest]` | `TC_CANARY_392baa5e...` | `HIT` |
| `FINDING-EE82B8DC` | **HIGH** | `STALE_REVOCATION_LEAK` | `/api/v1/shared/projects/proj-alpha` | `tenant_acme` | `tenant_acme::alex[standard_user]` | `TC_CANARY_797b28a1...` | `HIT` |
| `FINDING-B7A1C3A6` | **HIGH** | `STALE_REVOCATION_LEAK` | `/api/v1/shared/projects/proj-titan` | `tenant_beta` | `tenant_beta::brian[standard_user]` | `TC_CANARY_40fc7aee...` | `HIT` |
| `FINDING-41270741` | **HIGH** | `STALE_REVOCATION_LEAK` | `/api/v1/shared/projects/proj-neural` | `tenant_gamma` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_e0c79c1b...` | `HIT` |
| `FINDING-8228AD05` | **HIGH** | `STALE_REVOCATION_LEAK` | `/api/v1/shared/projects/proj-quantum` | `tenant_delta` | `tenant_delta::diana[standard_user]` | `TC_CANARY_21f64ea9...` | `HIT` |
| `FINDING-93BE830A` | **HIGH** | `STALE_REVOCATION_LEAK` | `/api/v1/shared/projects/proj-supply` | `tenant_acme` | `tenant_acme::amanda[standard_user]` | `TC_CANARY_b3fef7ee...` | `HIT` |
| `FINDING-4850FF5E` | **HIGH** | `STALE_REVOCATION_LEAK` | `/api/v1/shared/projects/proj-audit` | `tenant_beta` | `tenant_beta::brian[standard_user]` | `TC_CANARY_f744d4f7...` | `HIT` |
| `FINDING-5FD5F1AE` | **HIGH** | `STALE_REVOCATION_LEAK` | `/api/v1/shared/projects/proj-cloud` | `tenant_gamma` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_ae6227eb...` | `HIT` |
| `FINDING-A977F8EC` | **HIGH** | `STALE_REVOCATION_LEAK` | `/api/v1/shared/projects/proj-crypto` | `tenant_delta` | `tenant_delta::diana[standard_user]` | `TC_CANARY_0435622c...` | `HIT` |
| `FINDING-901F7103` | **HIGH** | `CACHE_KEY_SPOOFING_LEAK` | `/api/v1/tenant/dashboard` | `tenant_beta` | `tenant_acme::alice[admin]` | `TC_CANARY_3f932f1f...` | `HIT` |
| `FINDING-4CB3C8A2` | **HIGH** | `CACHE_KEY_SPOOFING_LEAK` | `/api/v1/tenant/dashboard` | `tenant_gamma` | `tenant_delta::david[admin]` | `TC_CANARY_4e016019...` | `HIT` |
| `FINDING-D084F548` | **HIGH** | `CACHE_KEY_SPOOFING_LEAK` | `/api/v1/tenant/dashboard` | `tenant_delta` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_48fa92a0...` | `HIT` |
