# TenantCache Component Ablation Study

| Variant | Identity | Cache Seq | Oracle | Precision | Recall | F1 Score | FPR | TP | FN |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Full TenantCache** | Yes | Yes | Yes | 1.0000 | 1.0000 | 1.0000 | 0.0000 | 44 | 0 |
| **Ablation 1: No Cache Sequencing** | Yes | No | Yes | N/A | 0.0000 | N/A | 0.0000 | 0 | 44 |
| **Ablation 2: No Ground-Truth Oracle** | Yes | Yes | No | 0.8049 | 0.7500 | 0.7765 | 0.8000 | 33 | 11 |
| **Ablation 3: No Identity Awareness** | No | Yes | Yes | N/A | 0.0000 | N/A | 0.0000 | 34 | 20 |
