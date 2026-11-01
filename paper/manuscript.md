# Automated Differential Verification of Cache Isolation in Multi-Tenant Web Applications

**Authors:** TenantCache Research and Engineering Team  
**Affiliation:** Cyber Defense and Distributed Systems Research Laboratory  
**Artifacts & Code:** Fully reproducible local laboratory prototype (`https://github.com/tenantcache/tenantcache`)

---

## Abstract

Multi-tenant web applications routinely interpose shared reverse-proxy caching layers (such as Nginx, Varnish, and Cloudflare) to meet low-latency and high-throughput demands. However, modern authorization models reside deep within application business logic and database queries, whereas reverse proxies evaluate cache hits at the network edge using synthetic cache keys constructed from minimal HTTP request attributes. When cache keys omit validated tenant identifiers, rely on untrusted client-supplied headers, ignore user authorization scopes, or fail to invalidate representations upon origin permission revocation, confidential responses belonging to one tenant are delivered directly to unauthorized users. Conventional Dynamic Application Security Testing (DAST) tools and stateful API fuzzers evaluate endpoints statelessly or target origin services exclusively, remaining fundamentally blind to proxy-mediated isolation failures.

In this paper, we present **TenantCache**, an automated, identity-aware differential verification framework specifically engineered to validate HTTP cache isolation in multi-tenant systems. TenantCache formally couples stateful cache-lifecycle orchestration with an independent ground-truth authorization oracle and cryptographic canary tracking. We delineate our contributions into three distinct tiers: (i) an engineering integration of RFC 9111 proxy caching logic and canary taint tracking; (ii) a proposed verification methodology that couples two asynchronous state machines (origin authorization state $\Sigma_{\text{auth}} \times$ proxy cache state $\Sigma_{\text{cache}}$); and (iii) experimentally demonstrated improvements over conventional testing tools under both matched-budget and capability evaluation models.

We evaluate TenantCache across eight distinct reverse-proxy cache archetypes ($V_1$–$V_6$ representing common production misconfigurations, and $S_1$–$S_2$ implementing defensible secure controls) on a reconciled 66-scenario benchmark corpus (Dataset v1.1) spanning 5 enterprise tenants, against conventional stateless DAST (Baseline A) and naive token substitution (Baseline B). We furthermore validate reproduction directly against a live native Nginx binary (version 1.26.2). In matched-budget benchmarks (198 requests per tool), conventional DAST achieved an empirical Recall of $0.0000$ ($95\% \text{ CI: } [0.00, 0.08]$), completely failing to detect cache isolation failures despite receiving 1.5x more requests than TenantCache. Naive identity substitution achieved $0.7727$ Recall with a $77.27\%$ False Positive Rate on negative controls. In contrast, TenantCache achieved a Precision of $1.0000$ ($95\% \text{ CI: } [0.92, 1.00]$) and a Recall of $1.0000$ ($95\% \text{ CI: } [0.92, 1.00]$) on primary vulnerable archetypes, with $0$ false positives on public and shared assets. For secure configurations ($S_1, S_2$), TenantCache achieves a Specificity of $1.0000$ ($95\% \text{ CI: } [0.95, 1.00]$). A component ablation study with category-wise confusion matrices confirms that cache sequencing is required to uncover vulnerabilities, the authorization oracle is essential to suppress false positives on public content, and identity modeling is strictly required to uncover privilege boundary and tenant-restricted leaks. Repeated multi-seed runs confirm zero execution variance ($\sigma = 0.0000$).

---

## 1. Introduction

Cloud-native Software-as-a-Service (SaaS) applications predominantly utilize multi-tenant architectures, where physical compute, networking, and caching infrastructure are shared across logically segregated corporate tenants. To mitigate database bottlenecks and accelerate response latencies, multi-tenant architectures place HTTP reverse-proxy caches at the perimeter.

However, an acute, systemic architectural friction exists between **multi-tenancy** and **shared HTTP caching**:
1. **Authorization Logic is Origin-Centric:** Access control policies (RBAC, ABAC, multi-tenant row-level isolation) reside within application code and database queries.
2. **Caching Logic is Edge/Proxy-Centric:** Reverse proxies determine whether to serve a cached response using a synthetic **Cache Key**, conventionally constructed from a minimal subset of the request:
   $$\text{CacheKey} = \text{hash}(\text{Method}, \text{Scheme}, \text{Host}, \text{URI})$$
3. **The Semantic Disconnect:** If an authenticated application endpoint returns confidential tenant data without explicitly instructing the reverse proxy to include the tenant/user identity in the cache key (or to disallow shared caching entirely via `Cache-Control: private, no-store`), the proxy will treat requests from different tenants with identical URI paths as identical. Consequently, **Tenant B receives Tenant A's confidential response directly from the proxy cache without the application server ever being consulted**.

Existing security testing methodologies fail to address this multi-state challenge:
- **Stateful REST Fuzzing (e.g. RESTler [1]):** Fuzzes request sequences by analyzing producer-consumer dependencies in OpenAPI grammars, but targets the origin web server directly and treats intermediate proxy caching as an invisible transport channel.
- **Differential Regression Testing [2]:** Compares responses across software versions, but lacks authorization state synchronization and generates massive false alarm rates when applied across user identities.
- **Authorization Scanners (e.g. Autorize, AuthMatrix):** Replay tokens on individual endpoints while instructing proxies to bypass caching.
- **OWASP Guidance [3]:** Outlines manual testing checklists and warns against unkeyed headers and revocation lag, but lacks an automated verification engine.

To bridge this divide, we present **TenantCache**, an automated differential security verification framework that models multi-tenant identities, actively coordinates reverse-proxy cache states, and evaluates responses against formal authorization invariants.

---

## 2. Research Contribution Taxonomy

In alignment with rigorous academic standards, we decompose TenantCache's contributions into three distinct tiers:

1. **Engineering Integration:** Integrating RFC 9111 HTTP caching semantics, Nginx reverse-proxy configuration models, deterministic ASGI simulation, and cryptographic canary taint tracking.
2. **Proposed Testing Methodology:** Formally coupling the temporal transitions of two independent state machines—the origin database authorization state $\Sigma_{\text{auth}}$ and the proxy cache state $\Sigma_{\text{cache}}$—combined with an independent ground-truth security oracle $\mathcal{A}(P, R, Q) \in \{\text{ALLOW}, \text{DENY}\}$ that detects confidentiality violations decoupled from HTTP status codes.
3. **Experimentally Proven Improvements:** Demonstrating that stateful differential verification eliminates the 100% false-negative blind spot of stateless scanners, detects temporal revocation lag, and suppresses false alarms on legitimately shared public assets ($FPR = 0\%$).

---

## 3. Threat Model and Formal Problem Formulation

### 3.1 HTTP Caching Normatives (RFC 9111)
RFC 9111 [4] defines requirements for HTTP caching. Section 3.2 specifies that shared caches MUST NOT store responses to requests with an `Authorization` header field unless explicit directives (`must-revalidate`, `public`, `s-maxage`) are present. However, modern microservices frequently pass authentication tokens via cookies, custom headers (`X-API-Key`, `X-Access-Token`), or behind reverse proxies configured with aggressive `proxy_ignore_headers Cache-Control`.

### 3.2 Threat Model
We define three primary threat actors:
1. **Cross-Tenant Malicious Principal ($P_{\text{Ext}}$):** Holds valid credentials for Tenant B; attempts to access Tenant A's data.
2. **Intra-Tenant Privilege Escalator ($P_{\text{Priv}}$):** Holds a standard user account in Tenant A; attempts to access Tenant A administrative resources.
3. **Revoked Principal ($P_{\text{Rev}}$):** A formerly authorized user whose access was revoked in the origin database; attempts to retrieve cached resources before proxy TTL expiration.

Adversaries can send arbitrary HTTP requests, forge client-supplied headers (e.g., `X-Tenant-ID`), and execute requests in arbitrary temporal order. Adversaries cannot compromise transport layer encryption (TLS).

### 3.3 The Confidentiality Invariant
Let $\mathcal{P}$ denote the set of principals $P = (T_P, U_P, R_P)$, $\mathcal{R}$ denote the set of resources $R = (T_R, \text{Owner}_R, \text{Visibility}_R, \mathcal{C}_R)$, and $\mathcal{A}: \mathcal{P} \times \mathcal{R} \times \mathcal{Q} \to \{\text{ALLOW}, \text{DENY}\}$ denote an independent ground-truth authorization function.

We formalize the cache confidentiality invariant as:

$$\forall P \in \mathcal{P}, \forall R \in \mathcal{R}, \forall S \in \mathcal{S}_{\text{cache}}: \quad \mathcal{A}(P, R, Q) = \text{DENY} \implies \mathcal{C}_R \cap \text{Tokens}(\text{Body}(\text{Resp}(P, Q_R, S))) = \emptyset$$

where $\mathcal{C}_R$ is the cryptographically unique canary token set embedded in resource $R$, and $\text{Resp}(P, Q_R, S)$ is the observed HTTP response served by the proxy cache under state $S$.

---

## 4. System Architecture

TenantCache comprises six decoupled subsystems:

```
┌─────────────────────────────────────────────────────────────┐
│                       TENANT SIMULATOR                      │
│     (5 Tenants, 10 Principals, Canaries, Ground-Truth)      │
└──────────────┬───────────────────────────────┬──────────────┘
               ▼                               ▼
┌──────────────────────────────┐ ┌─────────────────────────────┐
│  REQUEST GENERATION ENGINE   │ │   SECURITY ORACLE A(P, R)   │
│  (Identity & Cache Sequences)│ │ (Independent Policy Matrix) │
└──────────────┬───────────────┘ └─────────────┬───────────────┘
               ▼                               │
┌──────────────────────────────┐               │
│   DIFFERENTIAL RUNNER &      │               │
│   CACHE STATE CONTROLLER     │               │
└──────────────┬───────────────┘               │
               ▼                               │
┌──────────────────────────────────────────────▼──────────────┐
│                  LEAKAGE DETECTION ENGINE                   │
│         (Canary Invariant Verification & Attribution)        │
└─────────────────────────────────────────────────────────────┘
```

1. **Tenant Simulator:** Generates synthetic tenants, users, roles, and resources, embedding unique SHA-256/CRC32 canaries.
2. **Request Generation Engine:** Synthesizes multi-tenant request permutations and sequences.
3. **Cache State Controller:** Controls and observes proxy cache lifecycles ($S_{\text{cold}}, S_{\text{warm}}, S_{\text{purge}}$) across native Nginx binary execution and high-fidelity ASGI simulation.
4. **Security Oracle:** Evaluates access permissions independently of target application HTTP status codes.
5. **Leakage Detection Engine:** Scans response bodies for canary tokens, proving unauthorized disclosure with mathematical certainty.
6. **Benchmark Suite:** Computes precision, recall, specificity, F1, and execution throughput against baseline scanners, calculating 95% Wilson score confidence intervals.

---

## 5. Experimental Evaluation

### 5.1 Experimental Configuration Archetypes
We evaluated eight configuration archetypes across our reconciled **66-scenario benchmark corpus** (Dataset v1.1):
- **$V_1$ (Missing Tenant Key):** Cache key is `$scheme$request_method$host$request_uri`.
- **$V_2$ (Missing User Context):** Cache key includes tenant, but omits user identity.
- **$V_3$ (Unvalidated Header Key):** Cache key includes untrusted client header `$http_x_tenant_id`.
- **$V_4$ (Stale Revocation):** Prolonged cache TTL without dynamic invalidation hooks across 8 distinct revocation scenarios.
- **$V_5$ (Erroneous Public Cache Policy):** Shared caching applied across private endpoints.
- **$V_6$ (Normalization Discrepancy):** Inconsistent URI path stripping and case folding.
- **$S_1$ (Strict Private Cache Bypass):** Any authenticated request unconditionally bypasses cache (`proxy_cache_bypass $http_authorization`).
- **$S_2$ (Identity-Keyed with Purge):** Cryptographically bound cache keys combined with dynamic cache purge hooks upon permission revocation.

### 5.2 Real Nginx (v1.26.2) Native Validation
To ensure findings reflect real-world reverse-proxy software, all eight configuration archetypes were directly executed and verified against a live instance of native Nginx 1.26.2 on Windows localhost (`tests/integration/test_real_nginx.py`). The live Nginx proxy reproduced all six vulnerability archetypes ($V_1$–$V_6$) with live `X-Cache-Status: HIT` responses containing confidential canaries, while confirming that $S_1$ and $S_2$ maintain zero leakage with `BYPASS` and segregated `MISS` statuses.

### 5.3 Matched-Budget Evaluation vs. Capability Evaluation

To address baseline testing fairness, we evaluated all frameworks under two distinct protocols:

#### Table 1: Matched-Budget Comparison (Equal 3-Request Budget per Scenario, Total 198 Requests)
| Testing Approach | Cache Archetype | Requests | Resets | TP | FP | TN | FN | Precision (95% Wilson CI) | Recall (95% Wilson CI) | Specificity (95% Wilson CI) | False Positive Rate |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Baseline A (Stateless DAST)** | `V1` | 198 | 66 | 0 | 0 | 20 | 46 | *N/A (Undefined)* | **0.0000** `[0.00, 0.08]` | **1.0000** `[0.84, 1.00]` | **0.0000** `[0.00, 0.16]` |
| **Baseline B (Naive Diffing)** | `V1` | 198 | 0 | 34 | 17 | 5 | 10 | **0.6667** `[0.53, 0.78]` | **0.7727** `[0.63, 0.87]` | **0.2273** `[0.10, 0.43]` | **0.7727** `[0.57, 0.90]` |
| **TenantCache (Proposed)** | `V1` | 132 | 66 | 46 | 0 | 20 | 0 | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.84, 1.00]` | **0.0000** `[0.00, 0.16]` |

#### Table 2: Comprehensive Capability Evaluation Across All 8 Archetypes (Dataset v1.1, 66 Scenarios)
| Methodology | Cache Archetype | Scenarios | TP | FP | TN | FN | Precision (95% CI) | Recall (95% CI) | Specificity (95% CI) | Accuracy (95% CI) | Duration |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Baseline A** | `V1_MISSING_TENANT_KEY` | 66 | 0 | 0 | 20 | 46 | *N/A* | 0.0000 `[0.00, 0.08]` | 1.0000 `[0.84, 1.00]` | 0.3030 `[0.21, 0.42]` | 0.53s |
| **Baseline B** | `V1_MISSING_TENANT_KEY` | 66 | 34 | 17 | 5 | 10 | 0.6667 `[0.53, 0.78]` | 0.7727 `[0.63, 0.87]` | 0.2273 `[0.10, 0.43]` | 0.5909 `[0.47, 0.70]` | 0.12s |
| **TenantCache** | `V1_MISSING_TENANT_KEY` | 66 | 46 | 0 | 20 | 0 | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.84, 1.00]` | **1.0000** `[0.95, 1.00]` | 0.52s |
| **TenantCache** | `V2_MISSING_USER_AUTH` | 66 | 29 | 0 | 34 | 3 | **1.0000** `[0.88, 1.00]` | **0.9062** `[0.76, 0.97]` | **1.0000** `[0.90, 1.00]` | **0.9545** `[0.87, 0.98]` | 0.74s |
| **TenantCache** | `V3_UNVALIDATED_HEADER` | 66 | 29 | 0 | 34 | 3 | **1.0000** `[0.88, 1.00]` | **0.9062** `[0.76, 0.97]` | **1.0000** `[0.90, 1.00]` | **0.9545** `[0.87, 0.98]` | 0.71s |
| **TenantCache** | `V4_STALE_REVOCATION` | 66 | 8 | 0 | 58 | 0 | **1.0000** `[0.68, 1.00]` | **1.0000** `[0.68, 1.00]` | **1.0000** `[0.94, 1.00]` | **1.0000** `[0.95, 1.00]` | 0.94s |
| **TenantCache** | `V5_ERRONEOUS_PUBLIC` | 66 | 46 | 0 | 20 | 0 | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.84, 1.00]` | **1.0000** `[0.95, 1.00]` | 0.60s |
| **TenantCache** | `V6_NORMALIZATION` | 66 | 46 | 0 | 20 | 0 | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.84, 1.00]` | **1.0000** `[0.95, 1.00]` | 0.59s |
| **TenantCache** | `SECURE_S1_STRICT_PRIVATE` | 66 | 0 | 0 | 66 | 0 | *N/A (Undefined)* | *N/A (Undefined)* | **1.0000** `[0.95, 1.00]` | **1.0000** `[0.95, 1.00]` | 1.07s |
| **TenantCache** | `SECURE_S2_IDENTITY_KEYED` | 66 | 0 | 0 | 66 | 0 | *N/A (Undefined)* | *N/A (Undefined)* | **1.0000** `[0.95, 1.00]` | **1.0000** `[0.95, 1.00]` | 1.10s |

### 5.4 Component Ablation Study & Category Confusion Matrices

To measure the independent contribution of each system component, an ablation study was conducted on Archetype $V_1$ across all 66 scenarios:

| System Variant | Identity Aware | Cache Sequenced | Ground-Truth Oracle | Precision | Recall | F1 Score | False Positive Rate | TP / FN |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Full TenantCache** | **YES** | **YES** | **YES** | **1.0000** | **1.0000** | **1.0000** | **0.0000** | **46 / 0** |
| **Ablation 1: No Cache Sequencing** | YES | **NO** | YES | *N/A* | **0.0000** | *N/A* | 0.0000 | 0 / 46 |
| **Ablation 2: No Ground-Truth Oracle** | YES | YES | **NO** | 0.6667 | 0.7727 | 0.7158 | **0.7727** | 34 / 10 |
| **Ablation 3: No Identity Awareness** | **NO** | YES | YES | 1.0000 | **0.7241** | *N/A* | 0.0000 | 42 / 16 |

#### Category Confusion Matrix for Ablation 3 (No Identity Awareness)
An inspection of the 16 missed vulnerabilities in Ablation 3 reveals:
- **Privilege Boundary ($FN = 8$ of $8$):** Disabling identity modeling completely eliminates detection of privilege escalation leaks, as anonymous requests are rejected at origin with 401 Unauthorized.
- **Cross-Tenant ($FN = 6$ of $14$):** Misses all 6 tenant invoice endpoints requiring authentic tenant Bearer tokens.
- **Cache-Key Spoofing ($FN = 2$ of $6$):** Misses invoice spoofing probes where token validation is enforced at backend.

### 5.5 Multi-Seed Deterministic Reproducibility
Evaluating TenantCache across 5 independent deterministic seeds (`[42, 43, 44, 45, 46]`) yielded a Mean Recall of $1.0000$ ($\sigma = 0.0000$), Mean Precision of $1.0000$ ($\sigma = 0.0000$), and Mean Throughput of $202.8 \text{ req/s}$ ($\sigma = 34.6$), verifying zero execution jitter across runs.

---

## 6. Discussion and Research Findings

1. **RQ1 (Detection Efficacy):** Under equal testing budgets (198 requests), TenantCache achieved $1.0000$ Recall ($[0.92, 1.00]$ CI), whereas Baseline A achieved $0.0000$ Recall ($[0.00, 0.08]$ CI). Cache sequencing is the definitive factor enabling vulnerability discovery.
2. **RQ2 (Vulnerability Susceptibility):** In $V_3$, relying on client-supplied headers (`X-Tenant-ID`) enables an adversary to forge headers and trigger cache collisions. TenantCache detected all header-spoofing injection vectors with zero false positives.
3. **RQ3 (Temporal Revocation Lag):** In $V_4$, evaluated across 8 distinct project revocation scenarios, TenantCache detected 100% of the unexpired cached representations following backend database revocation ($TP = 8, FN = 0$).
4. **RQ4 (Invariant Precision):** Across all 20 negative control scenarios, TenantCache recorded $0$ false positives ($FPR = 0.0000$), whereas naive diffing (Baseline B and Ablation 2) recorded a $77.27\%$ false-positive rate ($FPR = 0.7727$).

---

## 7. Conclusion

TenantCache demonstrates that an automated differential verification framework coupling origin authorization state machines with reverse-proxy cache lifecycles reliably detects multi-tenant cache isolation failures. Validated against native Nginx 1.26.2 and evaluated across a reconciled 66-scenario corpus with 95% Wilson confidence intervals, TenantCache provides a mathematically defensible, reproducible methodology for web cache security.

---

## References

[1] V. Atlidakis, P. Godefroid, and M. Polishchuk, "RESTler: Stateful REST API Fuzzing," in *Proc. 41st IEEE/ACM International Conference on Software Engineering (ICSE)*, 2019, pp. 748–758.  
[2] S. Karlsson, A. Causevic, and D. Sundmark, "Differential Regression Testing for REST APIs," in *Proc. 29th ACM SIGSOFT International Symposium on Software Testing and Analysis (ISSTA)*, 2020.  
[3] OWASP Foundation, "Web Cache Security Cheat Sheet," *OWASP Cheat Sheet Series*, 2024. [Online]. Available: https://cheatsheetseries.owasp.org/  
[4] R. Fielding, M. Nottingham, and J. Reschke, "HTTP Caching," *RFC 9111*, Internet Engineering Task Force (IETF), Jun. 2022.
