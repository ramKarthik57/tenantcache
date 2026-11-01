# System Architecture: TenantCache Verification Framework

## 1. High-Level Modular Decomposition

TenantCache is engineered as a decoupled, layered architecture separating test orchestration, request generation, stateful cache management, ground-truth oracle evaluation, and lab infrastructure:

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           TENANTCACHE CLI / RUNNER                          │
│                      (Typer / Rich Terminal UI / Scripts)                   │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │
┌──────────────────────────────────────▼──────────────────────────────────────┐
│                            ORCHESTRATION LAYER                              │
│   ┌────────────────────────┐                   ┌────────────────────────┐   │
│   │   Tenant Simulator     │                   │  Benchmark Controller  │   │
│   │ (Identities, Canaries, │                   │ (Baselines, Metrics,   │   │
│   │  Policies, Ground-Truth│                   │  Coverage, Reporting)  │   │
│   └───────────┬────────────┘                   └───────────┬────────────┘   │
└───────────────┼────────────────────────────────────────────┼────────────────┘
                │                                            │
┌───────────────▼────────────────────────────────────────────▼────────────────┐
│                          DIFFERENTIAL ENGINE LAYER                          │
│   ┌────────────────────────┐  Permutations     ┌────────────────────────┐   │
│   │   Request Generator    ├──────────────────►│  Differential Runner   │   │
│   │ (Headers, Auth, Query) │                   │ (Stateful Sequences)   │   │
│   └────────────────────────┘                   └───────────┬────────────┘   │
│                                                            │                │
│   ┌────────────────────────┐                   ┌───────────▼────────────┐   │
│   │ Cache State Controller │◄──────────────────┤ Leakage Detection Eng. │   │
│   │ (Warm, Cold, Purge)    │                   │ (Canary Invariant Chk) │   │
│   └────────────────────────┘                   └───────────┬────────────┘   │
└────────────────────────────────────────────────────────────┼────────────────┘
                                                             │
┌────────────────────────────────────────────────────────────▼────────────────┐
│                             VERIFICATION LAYER                              │
│   ┌────────────────────────┐                   ┌────────────────────────┐   │
│   │  Security Oracle A()   │                   │ Evaluation & Reporting │   │
│   │ (Ground-Truth Invariant│                   │ (Markdown, JSON, CSV)  │   │
│   └────────────────────────┘                   └────────────────────────┘   │
└──────────────────────────────────────┬──────────────────────────────────────┘
                                       │ HTTP / In-Process / Docker
┌──────────────────────────────────────▼──────────────────────────────────────┐
│                           CONTROLLED LAB ENVIRONMENT                        │
│   ┌────────────────────────┐                   ┌────────────────────────┐   │
│   │   Nginx / Proxy Cache  │◄─────────────────►│   FastAPI Multi-Tenant │   │
│   │ (Vulnerable / Secure)  │                   │      Backend Origin    │   │
│   └────────────────────────┘                   └────────────────────────┘   │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 2. Core Subsystems and Component Responsibilities

### 2.1 Subsystem 1: Tenant Simulator (`src/tenantcache/simulator/`)
- Generates synthetic multi-tenant structures:
  - Tenants: `Tenant-Acme`, `Tenant-Beta`, `Tenant-Gamma`.
  - Principals: Administrators, Standard Users, and Revoked Users.
  - Resources: Invoices, Secret Projects, Profile Documents, and Public Guidelines.
- Injects cryptographically verifiable canary tokens into every confidential field.
- Publishes the canonical Ground-Truth Access Graph to the Security Oracle.

### 2.2 Subsystem 2: Request Generation Engine (`src/tenantcache/generator/`)
- Constructs HTTP requests parameterized by:
  - Identity context (Bearer JWT tokens, session cookies).
  - Client-controlled tenant headers (`X-Tenant-ID`, `X-Org-Slug`).
  - Cache directives (`Cache-Control`, `If-None-Match`).
  - Resource target paths and normalized variations (e.g., trailing slashes, encoded characters).
- Builds deterministic stateful sequences:
  - Sequence $\alpha$: $P_A$ (Cold) $\to$ $P_B$ (Warm).
  - Sequence $\beta$: $P_B$ (Cold) $\to$ $P_A$ (Warm).
  - Sequence $\gamma$: $P_{\text{Admin}}$ (Cold) $\to$ $P_{\text{Std}}$ (Warm).
  - Sequence $\delta$: $P_A$ (Cold) $\to$ Revoke($P_A$) $\to$ $P_A$ (Re-fetch).

### 2.3 Subsystem 3: Cache State Controller (`src/tenantcache/cache/`)
- Manages and observes proxy cache state:
  - Detects cache hit/miss status via response headers (`X-Cache-Status`, `Age`, `Date`).
  - Provides cold cache resets via cache-purging endpoints, cache-busting nonces, or filesystem volume resets.
  - Implements the high-fidelity `ProxyCacheSimulator` for zero-overhead local execution replicating exact Nginx RFC 9111 caching logic when container runtimes are unavailable.

### 2.4 Subsystem 4: Security Oracle (`src/tenantcache/oracle/`)
- Encapsulates the ground-truth authorization matrix $\mathcal{A}(P, R, Q) \in \{\text{ALLOW}, \text{DENY}\}$.
- Decoupled from the target application's runtime responses: does not rely on HTTP status codes.
- Answers: "Under policy rules, is Principal $P$ permitted to view Resource $R$?"

### 2.5 Subsystem 5: Leakage Detection Engine (`src/tenantcache/detection/`)
- Invariant engine scanning response bodies against known canaries.
- Classifies confirmed findings into:
  - `CROSS_TENANT_LEAK` (Critical)
  - `CROSS_USER_LEAK` (High)
  - `PRIVILEGE_ESCALATION_LEAK` (High)
  - `STALE_REVOCATION_LEAK` (High)
  - `PUBLIC_RESOURCE_BENIGN_HIT` (Informational - Filtered out)
- Computes confidence scores and provides full reproducibility vectors.

### 2.6 Subsystem 6: Evaluation & Baseline Benchmark (`src/tenantcache/evaluation/`)
- Executes three comparative testing methodologies:
  1. **Baseline A (Stateless Endpoint Testing):** Tests individual endpoints without cache sequencing.
  2. **Baseline B (Simple Token Substitution):** Swaps tokens without controlling cache states.
  3. **TenantCache (Differential Invariant Testing):** Full stateful matrix with ground-truth verification.
- Calculates rigorous statistical metrics: True Positives (TP), False Positives (FP), True Negatives (TN), False Negatives (FN), Precision, Recall, F1 Score, and Execution Latency.
