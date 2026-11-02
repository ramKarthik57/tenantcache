# TenantCache Component Ablation Study (Dataset Version: v1.1)

## 1. High-Level Performance Comparison

| Variant | Identity | Cache Seq | Oracle | Precision | Recall | F1 Score | FPR | TP | FN |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Full TenantCache** | Yes | Yes | Yes | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 46 | 0 |
| **Ablation 1: No Cache Sequencing** | Yes | No | Yes | *N/A (Undefined)* | 0.0000 | *N/A (Undefined)* | 0.0000 | 0 | 46 |
| **Ablation 2: No Ground-Truth Oracle** | Yes | Yes | No | 0.7600 | 0.8261 | 0.7917 | 0.6000 | 38 | 8 |
| **Control: Single-User Reachability Control (No Identity Diversity)** | No | Yes | Yes | *N/A (Undefined)* | 0.0000 | *N/A (Undefined)* | 0.0000 | 0 | 46 |

## 2. Category-Wise Confusion Matrices

### Full TenantCache

| Vulnerability Category | TP | FP | TN | FN | Total |
|---|:---:|:---:|:---:|:---:|:---:|
| **CROSS_TENANT** | 14 | 0 | 0 | 0 | 14 |
| **CROSS_USER** | 10 | 0 | 0 | 0 | 10 |
| **PRIVILEGE_BOUNDARY** | 8 | 0 | 0 | 0 | 8 |
| **STALE_REVOCATION** | 8 | 0 | 0 | 0 | 8 |
| **CACHE_KEY_SPOOFING** | 6 | 0 | 0 | 0 | 6 |
| **BENIGN_CONTROLS** | 0 | 0 | 20 | 0 | 20 |

### Ablation 1: No Cache Sequencing

| Vulnerability Category | TP | FP | TN | FN | Total |
|---|:---:|:---:|:---:|:---:|:---:|
| **CROSS_TENANT** | 0 | 0 | 0 | 14 | 14 |
| **CROSS_USER** | 0 | 0 | 0 | 10 | 10 |
| **PRIVILEGE_BOUNDARY** | 0 | 0 | 0 | 8 | 8 |
| **STALE_REVOCATION** | 0 | 0 | 0 | 8 | 8 |
| **CACHE_KEY_SPOOFING** | 0 | 0 | 0 | 6 | 6 |
| **BENIGN_CONTROLS** | 0 | 0 | 20 | 0 | 20 |

### Ablation 2: No Ground-Truth Oracle

| Vulnerability Category | TP | FP | TN | FN | Total |
|---|:---:|:---:|:---:|:---:|:---:|
| **CROSS_TENANT** | 14 | 0 | 0 | 0 | 14 |
| **CROSS_USER** | 10 | 0 | 0 | 0 | 10 |
| **PRIVILEGE_BOUNDARY** | 8 | 0 | 0 | 0 | 8 |
| **STALE_REVOCATION** | 0 | 0 | 0 | 8 | 8 |
| **CACHE_KEY_SPOOFING** | 6 | 0 | 0 | 0 | 6 |
| **BENIGN_CONTROLS** | 0 | 12 | 8 | 0 | 20 |

### Control: Single-User Reachability Control (No Identity Diversity)

| Vulnerability Category | TP | FP | TN | FN | Total |
|---|:---:|:---:|:---:|:---:|:---:|
| **CROSS_TENANT** | 0 | 0 | 0 | 14 | 14 |
| **CROSS_USER** | 0 | 0 | 0 | 10 | 10 |
| **PRIVILEGE_BOUNDARY** | 0 | 0 | 0 | 8 | 8 |
| **STALE_REVOCATION** | 0 | 0 | 0 | 8 | 8 |
| **CACHE_KEY_SPOOFING** | 0 | 0 | 0 | 6 | 6 |
| **BENIGN_CONTROLS** | 0 | 0 | 20 | 0 | 20 |

