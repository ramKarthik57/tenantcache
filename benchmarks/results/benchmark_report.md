# TenantCache: Experimental Evaluation and Statistical Benchmark Report

## 1. Quantitative Benchmark Summary (with 95% Wilson Confidence Intervals)

| Framework / Approach | Archetype | Scenarios | TP | FP | TN | FN | Precision (95% CI) | Recall (95% CI) | Specificity (95% CI) | Accuracy (95% CI) | FPR | Resets | Trans | Principals | Duration |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Baseline A (Matched-Budget Stateless DAST)** | `V1_MISSING_TENANT_KEY` | 66 | 0 | 0 | 20 | 46 | *N/A (Undefined)* | 0.0000 `[0.00, 0.08]` | 1.0000 `[0.84, 1.00]` | 0.3030 `[0.21, 0.42]` | 0.00 | 66 | 0 | 10 | 0.623s |
| **Baseline B (Matched-Budget Naive Diffing)** | `V1_MISSING_TENANT_KEY` | 66 | 38 | 12 | 8 | 8 | 0.7600 `[0.63, 0.86]` | 0.8261 `[0.69, 0.91]` | 0.4000 `[0.22, 0.61]` | 0.6970 `[0.58, 0.79]` | 0.60 | 66 | 8 | 10 | 0.350s |
| **TenantCache (Matched-Budget Verification)** | `V1_MISSING_TENANT_KEY` | 66 | 46 | 0 | 20 | 0 | 1.0000 `[0.92, 1.00]` | 1.0000 `[0.92, 1.00]` | 1.0000 `[0.84, 1.00]` | 1.0000 `[0.94, 1.00]` | 0.00 | 66 | 8 | 10 | 0.566s |
| **Baseline A (Capability Stateless DAST)** | `V1_MISSING_TENANT_KEY` | 66 | 0 | 0 | 20 | 46 | *N/A (Undefined)* | 0.0000 `[0.00, 0.08]` | 1.0000 `[0.84, 1.00]` | 0.3030 `[0.21, 0.42]` | 0.00 | 66 | 0 | 10 | 0.250s |
| **Baseline B (Capability Naive Diffing)** | `V1_MISSING_TENANT_KEY` | 66 | 38 | 12 | 8 | 8 | 0.7600 `[0.63, 0.86]` | 0.8261 `[0.69, 0.91]` | 0.4000 `[0.22, 0.61]` | 0.6970 `[0.58, 0.79]` | 0.60 | 66 | 8 | 10 | 0.313s |
| **TenantCache (Capability Verification)** | `V1_MISSING_TENANT_KEY` | 66 | 46 | 0 | 20 | 0 | 1.0000 `[0.92, 1.00]` | 1.0000 `[0.92, 1.00]` | 1.0000 `[0.84, 1.00]` | 1.0000 `[0.94, 1.00]` | 0.00 | 66 | 8 | 10 | 0.295s |
| **TenantCache (Capability Verification)** | `V2_MISSING_USER_AUTH` | 66 | 29 | 0 | 34 | 3 | 1.0000 `[0.88, 1.00]` | 0.9062 `[0.76, 0.97]` | 1.0000 `[0.90, 1.00]` | 0.9545 `[0.87, 0.98]` | 0.00 | 66 | 8 | 10 | 0.433s |
| **TenantCache (Capability Verification)** | `V3_UNVALIDATED_HEADER` | 66 | 29 | 0 | 34 | 3 | 1.0000 `[0.88, 1.00]` | 0.9062 `[0.76, 0.97]` | 1.0000 `[0.90, 1.00]` | 0.9545 `[0.87, 0.98]` | 0.00 | 66 | 8 | 10 | 0.426s |
| **TenantCache (Capability Verification)** | `V4_STALE_REVOCATION` | 66 | 8 | 0 | 58 | 0 | 1.0000 `[0.68, 1.00]` | 1.0000 `[0.68, 1.00]` | 1.0000 `[0.94, 1.00]` | 1.0000 `[0.94, 1.00]` | 0.00 | 66 | 8 | 10 | 0.507s |
| **TenantCache (Capability Verification)** | `V5_ERRONEOUS_PUBLIC` | 66 | 46 | 0 | 20 | 0 | 1.0000 `[0.92, 1.00]` | 1.0000 `[0.92, 1.00]` | 1.0000 `[0.84, 1.00]` | 1.0000 `[0.94, 1.00]` | 0.00 | 66 | 8 | 10 | 0.348s |
| **TenantCache (Capability Verification)** | `V6_NORMALIZATION` | 66 | 46 | 0 | 20 | 0 | 1.0000 `[0.92, 1.00]` | 1.0000 `[0.92, 1.00]` | 1.0000 `[0.84, 1.00]` | 1.0000 `[0.94, 1.00]` | 0.00 | 66 | 8 | 10 | 0.329s |
| **TenantCache (Capability Verification)** | `SECURE_S1_STRICT_PRIVATE` | 66 | 0 | 0 | 66 | 0 | *N/A (Undefined)* | *N/A (Undefined)* | 1.0000 `[0.94, 1.00]` | 1.0000 `[0.94, 1.00]` | 0.00 | 66 | 8 | 10 | 0.593s |
| **TenantCache (Capability Verification)** | `SECURE_S2_IDENTITY_KEYED` | 66 | 0 | 0 | 66 | 0 | *N/A (Undefined)* | *N/A (Undefined)* | 1.0000 `[0.94, 1.00]` | 1.0000 `[0.94, 1.00]` | 0.00 | 66 | 8 | 10 | 0.612s |

## 2. Statistical Invariant and Methodology Notes

- **Zero-Denominator Precision & Recall (Secure S1 & S2):** When a secure configuration yields 0 positive scenarios ($TP + FP = 0, TP + FN = 0$), Precision and Recall are mathematically undefined and reported as *N/A (Undefined)*. Specificity is calculated as $TN / (TN + FP) = 66/66 = 1.000$ (with Wilson 95% CI $[0.94, 1.00]$) and Accuracy is $1.000$.
- **Baseline A Precision:** When Baseline A generates zero positive predictions ($TP=0, FP=0$), Precision is mathematically undefined and reported as *N/A (Undefined)*.
- **Exploration Budget Documentation:** Baseline comparisons track explicit operational parameters: `Total Requests`, `Cache Resets`, `State Transitions`, and `Distinct Principals Covered`.
- **Wilson Score Intervals:** Calculated at a 95% confidence level dynamically ($z \approx 1.96$), capturing sample size uncertainty over the benchmark corpus.

## 3. Confirmed Vulnerability Findings Breakdown

| ID | Severity | Leakage Class | Target Endpoint | Victim Tenant | Adversary Principal | Detected Canary | Cache Status |
|---|---|---|---|---|---|---|:---:|
| `FINDING-AAAFDAAF` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `unknown` | `tenant_beta::bob[admin]` | `TC_CANARY_3f932f1f...` | `HIT` |
| `FINDING-5617EECB` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `unknown` | `tenant_acme::alice[admin]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-6895DCC5` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `unknown` | `tenant_delta::david[admin]` | `TC_CANARY_48fa92a0...` | `HIT` |
| `FINDING-6582B660` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `unknown` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_4e016019...` | `HIT` |
| `FINDING-02CAFBE4` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `unknown` | `tenant_delta::diana[standard_user]` | `TC_CANARY_48fa92a0...` | `HIT` |
| `FINDING-586EFAB5` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `unknown` | `tenant_epsilon::eric[guest]` | `TC_CANARY_48fa92a0...` | `HIT` |
| `FINDING-6161FA72` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/invoices/inv-101` | `unknown` | `tenant_beta::brian[standard_user]` | `TC_CANARY_e3c6f9b7...` | `HIT` |
| `FINDING-8386990F` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/invoices/inv-202` | `unknown` | `tenant_acme::alex[standard_user]` | `TC_CANARY_af041e4d...` | `HIT` |
| `FINDING-F9290789` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/invoices/inv-101` | `unknown` | `tenant_delta::david[admin]` | `TC_CANARY_e3c6f9b7...` | `HIT` |
| `FINDING-D8DCE9C6` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/invoices/inv-202` | `unknown` | `tenant_epsilon::eric[guest]` | `TC_CANARY_af041e4d...` | `HIT` |
| `FINDING-E53220DB` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/invoices/inv-101` | `unknown` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_e3c6f9b7...` | `HIT` |
| `FINDING-6EE54EE3` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/invoices/inv-202` | `unknown` | `tenant_delta::diana[standard_user]` | `TC_CANARY_af041e4d...` | `HIT` |
| `FINDING-ADAF7EE0` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `unknown` | `tenant_epsilon::eric[guest]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-7AD9E5FA` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/user/profile` | `unknown` | `tenant_acme::alex[standard_user]` | `TC_CANARY_66ad9c8e...` | `HIT` |
| `FINDING-C4EDA2BA` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/user/profile` | `unknown` | `tenant_acme::alice[admin]` | `TC_CANARY_38bceca1...` | `HIT` |
| `FINDING-CAD89C98` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/user/profile` | `unknown` | `tenant_acme::amanda[standard_user]` | `TC_CANARY_15a94a7e...` | `HIT` |
| `FINDING-17BC5A2C` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/user/profile` | `unknown` | `tenant_beta::brian[standard_user]` | `TC_CANARY_1bcc67ac...` | `HIT` |
| `FINDING-BFA28251` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/user/profile` | `unknown` | `tenant_beta::bob[admin]` | `TC_CANARY_c152670d...` | `HIT` |
| `FINDING-99E94DA9` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/user/profile` | `unknown` | `tenant_gamma::clara[admin]` | `TC_CANARY_54d56fd3...` | `HIT` |
| `FINDING-4EEFC0B9` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/user/profile` | `unknown` | `tenant_delta::diana[standard_user]` | `TC_CANARY_256d551c...` | `HIT` |
| `FINDING-7C82D43E` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/admin/audit-logs` | `unknown` | `tenant_acme::alex[standard_user]` | `TC_CANARY_081d1fbe...` | `HIT` |
| `FINDING-9B8E5423` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/admin/audit-logs` | `unknown` | `tenant_acme::amanda[standard_user]` | `TC_CANARY_081d1fbe...` | `HIT` |
| `FINDING-A9CA9D0E` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/admin/audit-logs` | `unknown` | `tenant_beta::brian[standard_user]` | `TC_CANARY_a120535f...` | `HIT` |
| `FINDING-2AD6CBB8` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/admin/audit-logs` | `unknown` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_85720407...` | `HIT` |
| `FINDING-92A55422` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/admin/audit-logs` | `unknown` | `tenant_delta::diana[standard_user]` | `TC_CANARY_392baa5e...` | `HIT` |
| `FINDING-3BD9DAC4` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/admin/audit-logs` | `unknown` | `tenant_epsilon::eric[guest]` | `TC_CANARY_081d1fbe...` | `HIT` |
| `FINDING-CA989EBA` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/admin/audit-logs` | `unknown` | `tenant_epsilon::eric[guest]` | `TC_CANARY_a120535f...` | `HIT` |
| `FINDING-AB9C6771` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/admin/audit-logs` | `unknown` | `tenant_epsilon::eric[guest]` | `TC_CANARY_392baa5e...` | `HIT` |
| `FINDING-7A64D0B3` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/invoices/inv-101` | `unknown` | `tenant_epsilon::eric[guest]` | `TC_CANARY_e3c6f9b7...` | `HIT` |
| `FINDING-1CADA0ED` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/public/docs/guidelines` | `unknown` | `tenant_beta::bob[admin]` | `TC_PUBLIC_DOC_GENE...` | `HIT` |
| `FINDING-0A741CEA` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/public/docs/terms` | `unknown` | `tenant_gamma::charlie[standard_user]` | `TC_PUBLIC_TERMS_OF...` | `HIT` |
| `FINDING-5F7B3C78` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/public/docs/guidelines` | `unknown` | `tenant_delta::david[admin]` | `TC_PUBLIC_DOC_GENE...` | `HIT` |
| `FINDING-29C53120` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/public/docs/terms` | `unknown` | `tenant_epsilon::eric[guest]` | `TC_PUBLIC_TERMS_OF...` | `HIT` |
| `FINDING-34ED3174` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `unknown` | `tenant_acme::alex[standard_user]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-F51F9016` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `unknown` | `tenant_acme::amanda[standard_user]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-AAEEA86C` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `unknown` | `tenant_beta::brian[standard_user]` | `TC_CANARY_3f932f1f...` | `HIT` |
| `FINDING-07EE5AF0` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/public/docs/guidelines` | `unknown` | `tenant_beta::brian[standard_user]` | `TC_PUBLIC_DOC_GENE...` | `HIT` |
| `FINDING-6A8A5EF4` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/public/docs/guidelines` | `unknown` | `tenant_delta::diana[standard_user]` | `TC_PUBLIC_DOC_GENE...` | `HIT` |
| `FINDING-A32C7C97` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_acme` | `tenant_beta::bob[admin]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-A023FE22` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_beta` | `tenant_acme::alice[admin]` | `TC_CANARY_3f932f1f...` | `HIT` |
| `FINDING-A6286BC6` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_gamma` | `tenant_delta::david[admin]` | `TC_CANARY_4e016019...` | `HIT` |
| `FINDING-E9D2B38E` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_delta` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_48fa92a0...` | `HIT` |
| `FINDING-2E67C03D` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_acme` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-5AFE20CE` | **CRITICAL** | `CROSS_TENANT_LEAK` | `/api/v1/tenant/dashboard` | `tenant_beta` | `tenant_delta::diana[standard_user]` | `TC_CANARY_3f932f1f...` | `HIT` |
| `FINDING-A2E2E055` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_acme::alex[standard_user]` | `TC_CANARY_38bceca1...` | `HIT` |
| `FINDING-2BDC7BC6` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_acme::alice[admin]` | `TC_CANARY_66ad9c8e...` | `HIT` |
| `FINDING-CCEA1832` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_acme::amanda[standard_user]` | `TC_CANARY_38bceca1...` | `HIT` |
| `FINDING-F296B38F` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_acme::alex[standard_user]` | `TC_CANARY_15a94a7e...` | `HIT` |
| `FINDING-F24B13BE` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_acme::alice[admin]` | `TC_CANARY_15a94a7e...` | `HIT` |
| `FINDING-8D744ABC` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_acme` | `tenant_acme::amanda[standard_user]` | `TC_CANARY_66ad9c8e...` | `HIT` |
| `FINDING-F95F792F` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_beta` | `tenant_beta::brian[standard_user]` | `TC_CANARY_c152670d...` | `HIT` |
| `FINDING-F5B3A06C` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_beta` | `tenant_beta::bob[admin]` | `TC_CANARY_1bcc67ac...` | `HIT` |
| `FINDING-7E834A72` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_gamma` | `tenant_gamma::clara[admin]` | `TC_CANARY_54d56fd3...` | `HIT` |
| `FINDING-966F4A3E` | **HIGH** | `CROSS_USER_LEAK` | `/api/v1/user/profile` | `tenant_delta` | `tenant_delta::diana[standard_user]` | `TC_CANARY_256d551c...` | `HIT` |
| `FINDING-B2DF9C41` | **HIGH** | `PRIVILEGE_ESCALATION_LEAK` | `/api/v1/admin/audit-logs` | `tenant_acme` | `tenant_acme::alex[standard_user]` | `TC_CANARY_081d1fbe...` | `HIT` |
| `FINDING-A1C2ECD0` | **HIGH** | `PRIVILEGE_ESCALATION_LEAK` | `/api/v1/admin/audit-logs` | `tenant_acme` | `tenant_acme::amanda[standard_user]` | `TC_CANARY_081d1fbe...` | `HIT` |
| `FINDING-54B723E8` | **HIGH** | `PRIVILEGE_ESCALATION_LEAK` | `/api/v1/admin/audit-logs` | `tenant_beta` | `tenant_beta::brian[standard_user]` | `TC_CANARY_a120535f...` | `HIT` |
| `FINDING-4C5919A4` | **HIGH** | `PRIVILEGE_ESCALATION_LEAK` | `/api/v1/admin/audit-logs` | `tenant_gamma` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_85720407...` | `HIT` |
| `FINDING-4C5CFE66` | **HIGH** | `PRIVILEGE_ESCALATION_LEAK` | `/api/v1/admin/audit-logs` | `tenant_delta` | `tenant_delta::diana[standard_user]` | `TC_CANARY_392baa5e...` | `HIT` |
| `FINDING-0DE0E48C` | **HIGH** | `STALE_REVOCATION_LEAK` | `/api/v1/shared/projects/proj-alpha` | `tenant_acme` | `tenant_acme::alex[standard_user]` | `TC_CANARY_797b28a1...` | `HIT` |
| `FINDING-07E0778E` | **HIGH** | `STALE_REVOCATION_LEAK` | `/api/v1/shared/projects/proj-titan` | `tenant_beta` | `tenant_beta::brian[standard_user]` | `TC_CANARY_40fc7aee...` | `HIT` |
| `FINDING-79EB0F86` | **HIGH** | `STALE_REVOCATION_LEAK` | `/api/v1/shared/projects/proj-neural` | `tenant_gamma` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_e0c79c1b...` | `HIT` |
| `FINDING-777895B8` | **HIGH** | `STALE_REVOCATION_LEAK` | `/api/v1/shared/projects/proj-quantum` | `tenant_delta` | `tenant_delta::diana[standard_user]` | `TC_CANARY_21f64ea9...` | `HIT` |
| `FINDING-9B6FEBED` | **HIGH** | `STALE_REVOCATION_LEAK` | `/api/v1/shared/projects/proj-supply` | `tenant_acme` | `tenant_acme::amanda[standard_user]` | `TC_CANARY_b3fef7ee...` | `HIT` |
| `FINDING-EDF7E8FC` | **HIGH** | `STALE_REVOCATION_LEAK` | `/api/v1/shared/projects/proj-audit` | `tenant_beta` | `tenant_beta::brian[standard_user]` | `TC_CANARY_f744d4f7...` | `HIT` |
| `FINDING-BDCE4512` | **HIGH** | `STALE_REVOCATION_LEAK` | `/api/v1/shared/projects/proj-cloud` | `tenant_gamma` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_ae6227eb...` | `HIT` |
| `FINDING-EB39134D` | **HIGH** | `STALE_REVOCATION_LEAK` | `/api/v1/shared/projects/proj-crypto` | `tenant_delta` | `tenant_delta::diana[standard_user]` | `TC_CANARY_0435622c...` | `HIT` |
| `FINDING-2181356A` | **HIGH** | `CACHE_KEY_SPOOFING_LEAK` | `/api/v1/tenant/dashboard` | `tenant_acme` | `tenant_beta::bob[admin]` | `TC_CANARY_18036548...` | `HIT` |
| `FINDING-6E5786F8` | **HIGH** | `CACHE_KEY_SPOOFING_LEAK` | `/api/v1/tenant/dashboard` | `tenant_beta` | `tenant_acme::alice[admin]` | `TC_CANARY_3f932f1f...` | `HIT` |
| `FINDING-CC4A2647` | **HIGH** | `CACHE_KEY_SPOOFING_LEAK` | `/api/v1/tenant/dashboard` | `tenant_gamma` | `tenant_delta::david[admin]` | `TC_CANARY_4e016019...` | `HIT` |
| `FINDING-B1BAC4F7` | **HIGH** | `CACHE_KEY_SPOOFING_LEAK` | `/api/v1/tenant/dashboard` | `tenant_delta` | `tenant_gamma::charlie[standard_user]` | `TC_CANARY_48fa92a0...` | `HIT` |
| `FINDING-8AAB39B9` | **HIGH** | `CACHE_KEY_SPOOFING_LEAK` | `/api/v1/tenant/invoices/inv-101` | `tenant_acme` | `tenant_epsilon::eric[guest]` | `TC_CANARY_e3c6f9b7...` | `HIT` |
| `FINDING-EA3A946C` | **HIGH** | `CACHE_KEY_SPOOFING_LEAK` | `/api/v1/tenant/invoices/inv-202` | `tenant_beta` | `tenant_delta::diana[standard_user]` | `TC_CANARY_af041e4d...` | `HIT` |
| `FINDING-1ABC21E4` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/user/profile` | `unknown` | `tenant_acme::alex[standard_user]` | `TC_CANARY_38bceca1...` | `HIT` |
| `FINDING-CAE92BFD` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/user/profile` | `unknown` | `tenant_acme::alice[admin]` | `TC_CANARY_66ad9c8e...` | `HIT` |
| `FINDING-8A62BB64` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/user/profile` | `unknown` | `tenant_acme::amanda[standard_user]` | `TC_CANARY_38bceca1...` | `HIT` |
| `FINDING-8C288FF3` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/user/profile` | `unknown` | `tenant_acme::alex[standard_user]` | `TC_CANARY_15a94a7e...` | `HIT` |
| `FINDING-F78262FA` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/user/profile` | `unknown` | `tenant_acme::alice[admin]` | `TC_CANARY_15a94a7e...` | `HIT` |
| `FINDING-DBE576B2` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/user/profile` | `unknown` | `tenant_acme::amanda[standard_user]` | `TC_CANARY_66ad9c8e...` | `HIT` |
| `FINDING-0E2ADF50` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/user/profile` | `unknown` | `tenant_beta::brian[standard_user]` | `TC_CANARY_c152670d...` | `HIT` |
| `FINDING-35885EA4` | **HIGH** | `CROSS_TENANT_LEAK` | `/api/v1/user/profile` | `unknown` | `tenant_beta::bob[admin]` | `TC_CANARY_1bcc67ac...` | `HIT` |
