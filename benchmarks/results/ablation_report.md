# TenantCache Component Ablation Study (Dataset Version: v1.1)

## 1. High-Level Performance Comparison

| Variant | Identity | Cache Seq | Oracle | Precision | Recall | F1 Score | FPR | TP | FN |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Full TenantCache** | Yes | Yes | Yes | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 46 | 0 |
| **Ablation 1: No Cache Sequencing** | Yes | No | Yes | *N/A (Undefined)* | 0.0000 | *N/A (Undefined)* | 0.0000 | 0 | 46 |
| **Ablation 2: No Ground-Truth Oracle** | Yes | Yes | No | 0.6667 | 0.7727 | 0.7158 | 0.7727 | 34 | 10 |
| **Ablation 3: No Identity Awareness** | No | Yes | Yes | 1.0000 | 0.7241 | *N/A (Undefined)* | 0.0000 | 42 | 16 |

## 2. Category-Wise Confusion Matrices

### Full TenantCache

| Vulnerability Category | TP | FP | TN | FN | Total |
|---|:---:|:---:|:---:|:---:|:---:|
| **CROSS_TENANT** | 20 | 0 | 0 | 0 | 20 |
| **CROSS_USER** | 10 | 0 | 0 | 0 | 10 |
| **PRIVILEGE_BOUNDARY** | 8 | 0 | 0 | 0 | 8 |
| **STALE_REVOCATION** | 8 | 0 | 0 | 0 | 8 |
| **CACHE_KEY_SPOOFING** | 0 | 0 | 0 | 0 | 0 |
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
| **STALE_REVOCATION** | 8 | 0 | 0 | 0 | 8 |
| **CACHE_KEY_SPOOFING** | 6 | 0 | 0 | 0 | 6 |
| **BENIGN_CONTROLS** | 0 | 12 | 8 | 0 | 20 |

### Ablation 3: No Identity Awareness

| Vulnerability Category | TP | FP | TN | FN | Total |
|---|:---:|:---:|:---:|:---:|:---:|
| **CROSS_TENANT** | 8 | 0 | 0 | 6 | 14 |
| **CROSS_USER** | 10 | 0 | 0 | 0 | 10 |
| **PRIVILEGE_BOUNDARY** | 0 | 0 | 0 | 8 | 8 |
| **STALE_REVOCATION** | 8 | 0 | 0 | 0 | 8 |
| **CACHE_KEY_SPOOFING** | 4 | 0 | 0 | 2 | 6 |
| **BENIGN_CONTROLS** | 12 | 0 | 8 | 0 | 20 |

