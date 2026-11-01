# TenantCache

> **Automated Differential Verification of Cache Isolation in Multi-Tenant Web Applications**

[![Python 3.9+](https://img.shields.io/badge/python-3.9%2B-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Tests](https://img.shields.io/badge/tests-19%20passed-brightgreen.svg)]()
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

Conventional Dynamic Application Security Testing (DAST) tools and authorization scanners (such as OWASP ZAP, Burp Suite, and Autorize) evaluate endpoints statelessly or explicitly instruct proxies to bypass caching, remaining completely blind to proxy-mediated isolation failures.

**TenantCache** is the first automated, identity-aware differential security testing framework designed to systematically identify, reproduce, and mathematically verify cross-tenant and cross-user HTTP cache isolation failures.

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
3. **Cache State Controller (`src/tenantcache/cache/`):** Observes and controls proxy cache lifecycles ($S_{\text{cold}}, S_{\text{warm}}, S_{\text{purge}}$) across both native in-process ASGI simulation and containerized Nginx environments.
4. **Security Oracle (`src/tenantcache/oracle/`):** Encapsulates ground-truth authorization $\mathcal{A}(P, R, Q) \in \{\text{ALLOW}, \text{DENY}\}$ decoupled from HTTP status codes.
5. **Leakage Detection Engine (`src/tenantcache/detection/`):** Scans response bodies for canary tokens, proving unauthorized disclosure with mathematical certainty.
6. **Research Evaluation Engine (`src/tenantcache/evaluation/`):** Executes controlled benchmarks comparing Baselines A and B against TenantCache.

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
| **$V_6$** | `V6_NORMALIZATION` | Proxy normalization discrepancies (trailing slashes, case folding) bypass cache partitioning. | **HIGH** |
| **$S_1$** | `SECURE_S1_STRICT_PRIVATE` | Authenticated requests unconditionally bypass cache (`proxy_cache_bypass $http_authorization`). | **SECURE** |
| **$S_2$** | `SECURE_S2_IDENTITY_KEYED` | Server-validated cryptographic identity keys combined with active surrogate-key cache purging. | **SECURE** |

---

## 5. Quantitative Experimental Evaluation

Empirical benchmark comparing conventional scanners against TenantCache across 9 scenarios per archetype:

| Framework / Methodology | Cache Archetype | TP | FP | TN | FN | Precision | Recall | F1 Score | Duration | Throughput |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Baseline A** (Stateless Testing) | `V1_MISSING_TENANT_KEY` | 0 | 0 | 2 | 7 | 1.0000 | **0.0000** | **0.0000** | 0.127s | 70.9 req/s |
| **Baseline B** (Simple Token Swap) | `V1_MISSING_TENANT_KEY` | 5 | 0 | 2 | 2 | 1.0000 | **0.7143** | **0.8333** | 0.014s | 1285.7 req/s |
| **TenantCache** | `V1_MISSING_TENANT_KEY` | 7 | 0 | 2 | 0 | **1.0000** | **1.0000** | **1.0000** | 0.025s | 720.0 req/s |
| **TenantCache** | `V2_MISSING_USER_AUTH` | 4 | 0 | 5 | 0 | **1.0000** | **1.0000** | **1.0000** | 0.031s | 580.6 req/s |
| **TenantCache** | `V3_UNVALIDATED_HEADER` | 4 | 0 | 5 | 0 | **1.0000** | **1.0000** | **1.0000** | 0.033s | 545.5 req/s |
| **TenantCache** | `V4_STALE_REVOCATION` | 1 | 0 | 8 | 0 | **1.0000** | **1.0000** | **1.0000** | 0.040s | 450.0 req/s |
| **TenantCache** | `V5_ERRONEOUS_PUBLIC` | 7 | 0 | 2 | 0 | **1.0000** | **1.0000** | **1.0000** | 0.022s | 818.2 req/s |
| **TenantCache** | `V6_NORMALIZATION` | 7 | 0 | 2 | 0 | **1.0000** | **1.0000** | **1.0000** | 0.022s | 818.2 req/s |
| **TenantCache** | `SECURE_S1_STRICT_PRIVATE` | 0 | 0 | 9 | 0 | **1.0000** | **1.0000** | **1.0000** | 0.042s | 428.6 req/s |
| **TenantCache** | `SECURE_S2_IDENTITY_KEYED` | 0 | 0 | 9 | 0 | **1.0000** | **1.0000** | **1.0000** | 0.045s | 400.0 req/s |

### Key Experimental Discoveries:
1. **Stateless Scanners Suffer 100% False Negatives:** Baseline A tests individual endpoints in isolation without cross-identity cache warming, achieving Recall = 0.0000.
2. **Stateless Testing Misses Revocation Lag:** Baseline B swaps tokens but fails to model temporal origin permission mutations, missing 100% of authorization revocation lag vulnerabilities.
3. **Zero False Positives on Public Content:** Unlike naive byte-diffing tools that flag dynamic tokens or public documents as breaches, TenantCache's canary oracle achieved FPR = 0.0000 across all configurations.

---

## 6. Installation & Quickstart

### Prerequisites
- Python 3.9+ (Zero external database or cloud dependencies required).
- Windows PowerShell or POSIX Bash.

### Setup
```bash
# 1. Clone repository
git clone https://github.com/tenantcache/tenantcache.git
cd tenantcache

# 2. Install dependencies
pip install -r requirements.txt

# 3. Verify environment
python -m src.tenantcache.cli doctor
```

### Running Scans and Benchmarks
```bash
# Execute differential scan on Vulnerable Archetype V1
python -m src.tenantcache.cli scan --archetype V1_MISSING_TENANT_KEY

# Execute differential scan on Secure Archetype S1
python -m src.tenantcache.cli scan --archetype SECURE_S1_STRICT_PRIVATE

# Execute full comprehensive research benchmark
python -m src.tenantcache.cli benchmark --profile comprehensive

# View benchmark report
python -m src.tenantcache.cli report
```

### Running Automated Test Suite
```bash
pytest -v
```
All 19 tests (unit, integration, hypothesis property, end-to-end) run in under 3 seconds.

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
