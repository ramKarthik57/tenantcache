# TenantCache

> **Automated Differential Verification of Cache Isolation in Multi-Tenant Web Applications**

[![Python 3.11+](https://img.shields.io/badge/python-3.11%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-39%20passed%20(37%20core)-brightgreen.svg)]()
[![Precision](https://img.shields.io/badge/precision-1.0000-success.svg)]()
[![Recall](https://img.shields.io/badge/recall-1.0000-success.svg)]()

---

## 1. Executive Introduction & Problem Statement

Modern cloud-native Software-as-a-Service (SaaS) applications utilize shared reverse-proxy caching infrastructure (e.g. Nginx, Varnish, Cloudflare) to meet strict sub-millisecond latency requirements. Simultaneously, these platforms host multiple distinct corporate entities (**Tenants**).

However, an acute, systemic architectural friction exists:
- **Authorization Logic is Origin-Centric:** Access control policies (RBAC, ABAC, row-level tenant security) execute inside application code and database queries.
- **Caching Logic is Edge/Proxy-Centric:** Reverse proxies determine whether to serve a cached response using a synthetic **Cache Key**, conventionally constructed from minimal HTTP request attributes:
  $$\text{CacheKey} = \text{hash}(\text{Method}, \text{Scheme}, \text{Host}, \text{URI})$$

When an authenticated endpoint returns confidential tenant or user data without strictly isolating cache keys by verified identity context, or without forbidding shared caching (`Cache-Control: private, no-store`), **Tenant B receives Tenant A's private response directly from the proxy cache without the application server ever being consulted**.

Conventional stateless testing methodologies and standard authorization scanners typically evaluate endpoints without coordinating cache states or explicitly instruct proxies to bypass caching, leaving stateful proxy-mediated isolation failures unverified. In our controlled empirical benchmark, we evaluate custom reference implementations of these paradigms (Baseline A: Stateless DAST, Baseline B: Matched-Budget Naive Diffing) against TenantCache's stateful differential approach.

**TenantCache** is an automated, identity-aware differential security testing framework designed to systematically identify, reproduce, and mathematically verify cross-tenant and cross-user HTTP cache isolation failures across reverse-proxy layers.

---

## 2. System Architecture

```mermaid
flowchart TD
    subgraph CLI ["TenantCache CLI & Runner"]
        A[Typer CLI / PowerShell] --> B[Benchmark Suite]
    end

    subgraph Simulation ["Identity & Ground-Truth"]
        C[Tenant Simulator] -->|Synthesize Identities & Canaries| D[Security Oracle A(P, R)]
        C -->|Seed Universe| E[Request Generator]
    end

    subgraph Differential ["Differential Engine Layer"]
        E -->|Generate Sequences| F[Differential Runner]
        F --> G[Proxy Cache Simulator / Live Nginx]
        G --> H[FastAPI Target Application]
        F --> I[Leakage Detector]
        D -->|Ground-Truth Decisions| I
    end

    subgraph Reporting ["Audit & Research Verification"]
        I --> J[JSON / CSV / Markdown Reports]
    end
```

### Component Breakdown
1. **Tenant Simulator (`src/tenantcache/simulator/`):** Generates synthetic tenants, users, roles, resources, and cryptographically unique canaries (`TC_CANARY_<uuid>_<crc>`).
2. **Request Generation Engine (`src/tenantcache/generator/`):** Constructs stateful request sequences across multi-tenant principal matrices ($T_A \leftrightarrow T_B$, Admin $\leftrightarrow$ Std User, Authorized $\to$ Revoked).
3. **Cache State Controller (`src/tenantcache/cache/`):** Observes and controls proxy cache lifecycles ($S_{\text{cold}}, S_{\text{warm}}, S_{\text{purge}}$) across both native in-process ASGI simulation and real Nginx reverse-proxy instances.
4. **Security Oracle (`src/tenantcache/oracle/`):** Encapsulates ground-truth authorization $\mathcal{A}(P, R, Q) \in \{\text{ALLOW}, \text{DENY}\}$ using an isolated reference policy ledger decoupled from target application state.
5. **Leakage Detection Engine (`src/tenantcache/detection/`):** Correlates observable HTTP evidence, canary reflection tokens, and oracle authorization decisions. Also provides `OracleFreeDifferentialDetector` for comparative baseline ablation.
6. **Research Evaluation Engine (`src/tenantcache/evaluation/`):** Executes controlled benchmarks comparing Baselines A and B against TenantCache on versioned benchmark manifests (v1.0: 54 scenarios, v1.1: 66 scenarios).

---

## 3. The Security Invariant

TenantCache formalizes the cache confidentiality invariant as:

$$\forall P \in \mathcal{P}, \forall R \in \mathcal{R}, \forall S \in \mathcal{S}_{\text{cache}}: \quad \mathcal{A}(P, R, Q) = \text{DENY} \implies \mathcal{C}_R \cap \text{Tokens}(\text{Body}(\text{Resp}(P, Q_R, S))) = \emptyset$$

If the ground-truth authorization oracle asserts that Principal $P$ is denied access to Resource $R$, the HTTP response body must contain **zero** confidential canary tokens belonging to Resource $R$, regardless of whether the cache proxy returned HTTP 200, 304, or 403.

---

## 4. Controlled Configuration Archetypes

TenantCache includes 6 vulnerable and 2 secure reverse-proxy configuration archetypes:

| Archetype ID | Configuration Archetype | Mechanism / Root Cause | Severity |
|---|---|---|---|
| **$V_1$** | `V1_MISSING_TENANT_KEY` | Proxy cache key uses URI only (`$scheme$method$host$uri`); tenant context omitted. | **CRITICAL** |
| **$V_2$** | `V2_MISSING_USER_AUTH` | Proxy keys on tenant header, but omits user identity; user-private profiles leak within tenant. | **HIGH** |
| **$V_3$** | `V3_UNVALIDATED_HEADER` | Proxy keys on untrusted client header (`X-Tenant-ID`); attacker spoofs header to extract victim cache. | **HIGH** |
| **$V_4$** | `V4_STALE_REVOCATION` | Origin revokes user permission in DB, but proxy caches 200 OK without dynamic invalidation hooks. | **HIGH** |
| **$V_5$** | `V5_ERRONEOUS_PUBLIC` | Proxy or origin emits `Cache-Control: public` on authenticated private endpoints. | **CRITICAL** |
| **$V_6$** | `V6_NORMALIZATION` | Path-normalization aliasing (`$uri` collapses duplicate delimiters like `//` to `/`, causing aliased paths to collide). | **HIGH** |
| **$S_1$** | `SECURE_S1_STRICT_PRIVATE` | Authenticated requests unconditionally bypass cache (`proxy_cache_bypass $http_authorization`). | **SECURE** |
| **$S_2$** | `SECURE_S2_IDENTITY_KEYED` | Server-validated identity keying (`$auth_tenant|$auth_user`) with per-request authorization verification (`auth_request`) and client header stripping. | **SECURE** |

---

## 5. Quantitative Experimental Evaluation

> [!NOTE] Baseline Testing Scope & Evaluation Calibration
> Baselines A and B represent custom reference implementations designed to evaluate specific algorithmic properties: stateless active endpoint testing (without cache-state sequencing) and naive length/token differential testing (without an independent authorization oracle). These baselines rigorously isolate the necessity of cache sequencing and oracle-based semantic verification under equal request budgets (198 requests). They do not evaluate commercial enterprise DAST suites operating under custom multi-user automation scripts.

Empirical benchmark comparing conventional scanners against TenantCache across the canonical **Dataset v1.1 corpus** (66 scenarios: 46 vulnerable, 20 balanced benign controls; with 95% Wilson confidence intervals):

| Framework / Methodology | Cache Archetype | TP | FP | TN | FN | Precision (95% CI) | Recall (95% CI) | Specificity (95% CI) | Accuracy (95% CI) | Req / Budget |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Baseline A** (Matched-Budget DAST) | `V1_MISSING_TENANT_KEY` | 0 | 0 | 20 | 46 | *N/A (Undefined)* | 0.0000 `[0.00, 0.08]` | 1.0000 `[0.84, 1.00]` | 0.3030 `[0.21, 0.42]` | 198 / 198 |
| **Baseline B** (Matched-Budget Naive Diffing) | `V1_MISSING_TENANT_KEY` | 38 | 12 | 8 | 8 | 0.7600 `[0.63, 0.86]` | 0.8261 `[0.69, 0.91]` | 0.4000 `[0.22, 0.61]` | 0.6970 `[0.58, 0.79]` | 198 / 198 |
| **Baseline A** (Stateless DAST) | `V1_MISSING_TENANT_KEY` | 0 | 0 | 20 | 46 | *N/A (Undefined)* | 0.0000 `[0.00, 0.08]` | 1.0000 `[0.84, 1.00]` | 0.3030 `[0.21, 0.42]` | 66 / 66 |
| **Baseline B** (Naive Token Diffing) | `V1_MISSING_TENANT_KEY` | 38 | 12 | 8 | 8 | 0.7600 `[0.63, 0.86]` | 0.8261 `[0.69, 0.91]` | 0.4000 `[0.22, 0.61]` | 0.6970 `[0.58, 0.79]` | 132 / 132 |
| **TenantCache** | `V1_MISSING_TENANT_KEY` | 46 | 0 | 20 | 0 | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.84, 1.00]` | **1.0000** `[0.94, 1.00]` | 132 / 132 |
| **TenantCache** | `V2_MISSING_USER_AUTH` | 29 | 0 | 34 | 3 | **1.0000** `[0.88, 1.00]` | **0.9062** `[0.76, 0.97]` | **1.0000** `[0.90, 1.00]` | **0.9545** `[0.87, 0.98]` | 132 / 132 |
| **TenantCache** | `V3_UNVALIDATED_HEADER` | 29 | 0 | 34 | 3 | **1.0000** `[0.88, 1.00]` | **0.9062** `[0.76, 0.97]` | **1.0000** `[0.90, 1.00]` | **0.9545** `[0.87, 0.98]` | 132 / 132 |
| **TenantCache** | `V4_STALE_REVOCATION` | 8 | 0 | 58 | 0 | **1.0000** `[0.68, 1.00]` | **1.0000** `[0.68, 1.00]` | **1.0000** `[0.94, 1.00]` | **1.0000** `[0.94, 1.00]` | 132 / 132 |
| **TenantCache** | `V5_ERRONEOUS_PUBLIC` | 46 | 0 | 20 | 0 | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.84, 1.00]` | **1.0000** `[0.94, 1.00]` | 132 / 132 |
| **TenantCache** | `V6_NORMALIZATION` | 46 | 0 | 20 | 0 | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.84, 1.00]` | **1.0000** `[0.94, 1.00]` | 132 / 132 |
| **TenantCache** | `SECURE_S1_STRICT_PRIVATE` | 0 | 0 | 66 | 0 | *N/A (Undefined)* | *N/A (Undefined)* | **1.0000** `[0.94, 1.00]` | **1.0000** `[0.94, 1.00]` | 132 / 132 |
| **TenantCache** | `SECURE_S2_IDENTITY_KEYED` | 0 | 0 | 66 | 0 | *N/A (Undefined)* | *N/A (Undefined)* | **1.0000** `[0.94, 1.00]` | **1.0000** `[0.94, 1.00]` | 132 / 132 |

### Component Ablation Study (V1 Archetype, v1.1 Corpus)

| System Variant | Identity-Aware | Cache-Sequenced | Oracle-Guided | Precision | Recall | F1 Score | FPR | TP / FN |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Full TenantCache** | **YES** | **YES** | **YES** | **1.0000** | **1.0000** | **1.0000** | **0.0000** | **46 / 0** |
| **Ablation 1: No Cache Sequencing** | YES | NO | YES | *N/A* | 0.0000 | *N/A* | 0.0000 | 0 / 46 |
| **Ablation 2: No Ground-Truth Oracle** | YES | YES | NO | 0.7600 | 0.8261 | 0.7917 | 0.6000 | 38 / 8 |
| **Control: Single-User Reachability Control** | NO | YES | YES | *N/A* | 0.0000 | *N/A* | 0.0000 | 0 / 46 |

> [!NOTE] Reachability Control Invariant
> The single-user experiment ($TP=0, FN=46$) functions as a reachability control experiment rather than a general causal ablation: by construction, executing both priming and probing under a single principal makes multi-tenant/multi-user cache collisions structurally unobservable.

### Real Nginx Validation (Dual Validated: Windows 1.26.2 & Linux 1.26.3)
All eight proxy configurations (V1–V6, S1, S2) are validated against **actual Nginx binaries** (`tests/integration/test_real_nginx.py`):
1. **V1–V5:** Alice primes cache; Bob/prober requests same resource; Nginx returns `X-Cache-Status: HIT` with Alice's confidential canary reflected.
2. **V6 (Path-Normalization Aliasing):** Canonical path `/api/v1/tenant/dashboard` primed by Alice; Bob requests duplicate-slash alias `/api/v1/tenant//dashboard`; Nginx collapses `//` to `/` via `$uri`, returning Alice's cached dashboard.
3. **S1 (Strict Private):** Authenticated requests unconditionally return `X-Cache-Status: BYPASS` (0 leaks).
4. **S2 (Identity-Keyed Caching with Auth Verification):** Nginx validates access via `auth_request /_auth_verify` subrequest to origin and keys cache with `$uri|$auth_tenant|$auth_user`, stripping unauthenticated client headers. Alice repeat returns `HIT`; Bob request returns `MISS` with his own data (0 leaks); post-revocation requests and unmapped routes return `403 Forbidden` without serving cached data.

---

## 6. Installation & Quickstart

### Prerequisites
- Python 3.11+ (Zero external database or cloud dependencies required).
- Windows PowerShell or POSIX Bash.
- Optional: Local Nginx binary for native integration tests (`nginx` in PATH or bundled in `lab/nginx_runtime/`).

### Setup
```bash
# 1. Install dependencies with exact tested constraints
pip install -r requirements.txt -c constraints.txt

# 2. Install TenantCache package in editable mode
pip install -e .

# 3. Verify environment
tenantcache doctor
```

### Running Scans and Benchmarks
```bash
# Execute differential scan on Vulnerable Archetype V1
tenantcache scan --archetype V1_MISSING_TENANT_KEY

# Execute differential scan on Secure Archetype S2
tenantcache scan --archetype SECURE_S2_IDENTITY_KEYED

# Export scenario manifests (v1.0 and v1.1)
tenantcache manifest --version v1.1

# Execute full comprehensive research benchmark
tenantcache benchmark --profile comprehensive --version v1.1

# Execute component ablation study
tenantcache ablation --version v1.1

# Execute multi-seed reproducibility study
tenantcache reproducibility --version v1.1
```

### Running Automated Test Suite
```bash
# Full test suite (all 39 tests including Hypothesis property-based tests):
pytest tests/ -v

# Core test suite (37 tests, executable in network-isolated environments without Hypothesis):
pytest tests/ -v --ignore=tests/unit/test_property_hypothesis.py
```
All 39 tests (unit, integration, real Nginx, hypothesis property, end-to-end) run and pass reliably (37 passed when ignoring Hypothesis).

---

## 7. Project Documentation Index

- [LITERATURE_REVIEW.md](docs/LITERATURE_REVIEW.md): Peer-reviewed survey of RFC 9111, USENIX Security, IEEE S&P, and Black Hat research.
- [RELATED_WORK.md](docs/RELATED_WORK.md): Taxonomy comparing Autorize, Param Miner, DAST, and RESTler.
- [RESEARCH_GAP.md](docs/RESEARCH_GAP.md): The semantic disconnect between application authorization and edge caching.
- [NOVELTY_ASSESSMENT.md](docs/NOVELTY_ASSESSMENT.md): Analysis of genuine scientific vs. engineering novelty.
- [RESEARCH_QUESTIONS.md](docs/RESEARCH_QUESTIONS.md): Formal formulation of RQ1–RQ4 and falsifiable hypotheses.
- [THREAT_MODEL.md](docs/THREAT_MODEL.md): Detailed threat actors, trust boundaries, and attack vectors.
- [METHODOLOGY.md](docs/METHODOLOGY.md): Invariant math, canary generation, and sequence mechanics.
- [ARCHITECTURE.md](docs/ARCHITECTURE.md): Modular system design and component decomposition.
- [EXPERIMENTAL_RESULTS.md](docs/EXPERIMENTAL_RESULTS.md): Quantitative experimental data and analysis.
- [LIMITATIONS.md](docs/LIMITATIONS.md): Scope boundaries and threats to validity.
- [REPRODUCIBILITY.md](docs/REPRODUCIBILITY.md): Exact step-by-step reproduction instructions.
- [SECURITY_AUDIT.md](docs/SECURITY_AUDIT.md): Framework self-defense audit and target guardrails.
- [DECISIONS.md](docs/DECISIONS.md): Architectural Decision Records (ADRs).
- [DEVELOPMENT_LOG.md](docs/DEVELOPMENT_LOG.md): Milestone development diary.
- [paper/manuscript.md](paper/manuscript.md): Full academic research manuscript.
- [paper/references.bib](paper/references.bib): BibTeX references.

---

## 8. License

TenantCache is released under the [MIT License](LICENSE).
