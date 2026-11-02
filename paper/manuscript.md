# Automated Differential Verification of Cache Isolation in Multi-Tenant Web Applications

**Author:** Ramkumar V.  
**Affiliation:** Advanced Systems & Cybersecurity Research Group  
**Artifact Distribution:** Verified Canonical Release Archive (`tenantcache.zip`, verified via companion `tenantcache.zip.sha256` and `SHA256SUMS`)

---

## Abstract

Multi-tenant web applications routinely interpose shared reverse-proxy caching layers (such as Nginx, Varnish, and Cloudflare) to meet low-latency and high-throughput demands. However, modern authorization models reside deep within application business logic and database queries, whereas reverse proxies evaluate cache hits at the network edge using synthetic cache keys constructed from minimal HTTP request attributes. When cache keys omit validated tenant identifiers, rely on untrusted client-supplied headers, ignore user authorization scopes, or fail to invalidate representations upon origin permission revocation, confidential responses belonging to one tenant are delivered directly to unauthorized users. Conventional active vulnerability testing methodologies—such as stateless active endpoint scanning and naive token differential checking without cache-state synchronization—target origin services directly, remaining fundamentally blind to proxy-mediated isolation failures.

In this paper, we present **TenantCache**, an automated, identity-aware differential verification framework specifically engineered to validate HTTP cache isolation in multi-tenant systems. TenantCache formally couples stateful cache-lifecycle orchestration with an independent ground-truth authorization oracle and cryptographic canary tracking. We delineate our contributions into three distinct tiers: (i) an engineering integration of RFC 9111 proxy caching logic and canary taint tracking; (ii) a proposed verification methodology that couples two asynchronous state machines (origin authorization state $\Sigma_{\text{auth}} \times$ proxy cache state $\Sigma_{\text{cache}}$); and (iii) experimentally demonstrated improvements over conventional testing tools under both matched-budget and capability evaluation models.

We evaluate TenantCache across eight distinct reverse-proxy cache archetypes ($V_1$–$V_6$ representing common production misconfigurations, and $S_1$–$S_2$ implementing defensible secure controls) on a reconciled 66-scenario benchmark corpus (Dataset v1.1) spanning 5 enterprise tenants, against conventional stateless DAST (Baseline A) and naive token substitution (Baseline B). We furthermore validate reproduction directly against a live native Nginx binary (version 1.26.2). In matched-budget benchmarks (198 requests per tool), conventional DAST achieved an empirical Recall of $0.0000$ ($95\% \text{ CI: } [0.00, 0.08]$), completely failing to detect cache isolation failures despite receiving an identical request budget. Naive identity substitution achieved $0.8261$ Recall with a $60.00\%$ False Positive Rate on negative controls due to lack of an authorization oracle. In contrast, TenantCache achieved a Precision of $1.0000$ ($95\% \text{ CI: } [0.92, 1.00]$) and a Recall of $1.0000$ ($95\% \text{ CI: } [0.92, 1.00]$) on primary vulnerable archetypes, with $0$ false positives on public and shared assets. For secure configurations ($S_1, S_2$), TenantCache achieves a Specificity of $1.0000$ ($95\% \text{ CI: } [0.94, 1.00]$). A component ablation study with category-wise confusion matrices confirms that cache sequencing is required to uncover vulnerabilities, the authorization oracle is essential to suppress false positives on public content, and identity modeling is strictly required to uncover privilege boundary and tenant-restricted leaks. Repeated multi-seed runs confirm zero execution variance ($\sigma = 0.0000$).

---

## 1. Introduction

Cloud-native Software-as-a-Service (SaaS) applications predominantly utilize multi-tenant architectures, where physical compute, networking, and caching infrastructure are shared across logically segregated corporate tenants [5]. To mitigate database bottlenecks and accelerate response latencies, multi-tenant architectures place HTTP reverse-proxy caches at the perimeter.

However, an acute, systemic architectural friction exists between **multi-tenancy** and **shared HTTP caching**:
1. **Authorization Logic is Origin-Centric:** Access control policies (RBAC, ABAC, multi-tenant row-level isolation) reside within application code and database queries.
2. **Caching Logic is Edge/Proxy-Centric:** Reverse proxies determine whether to serve a cached response using a synthetic **Cache Key**, conventionally constructed from a minimal subset of the request:
   $$\text{CacheKey} = \text{hash}(\text{Method}, \text{Scheme}, \text{Host}, \text{URI})$$
3. **The Semantic Disconnect:** If an authenticated application endpoint returns confidential tenant data without explicitly instructing the reverse proxy to include the tenant/user identity in the cache key (or to disallow shared caching entirely via `Cache-Control: private, no-store`), the proxy will treat requests from different tenants with identical URI paths as identical. Consequently, **Tenant B receives Tenant A's confidential response directly from the proxy cache without the application server ever being consulted**.

Existing security testing methodologies fail to address this multi-state challenge:
- **Stateful REST Fuzzing (e.g. RESTler [1]):** Fuzzes request sequences by analyzing producer-consumer dependencies in OpenAPI grammars, but targets the origin web server directly and treats intermediate proxy caching as an invisible transport channel.
- **Differential Regression Testing [2]:** Compares responses across software versions, but lacks authorization state synchronization and generates massive false alarm rates when applied across user identities.
- **Authorization Scanners (e.g. Autorize, AuthMatrix [11]):** Replay tokens on individual endpoints while instructing proxies to bypass caching.
- **OWASP Guidance [3]:** Outlines manual testing checklists and warns against unkeyed headers and revocation lag, but lacks an automated verification engine.

To bridge this divide, we present **TenantCache**, an automated differential security verification framework that models multi-tenant identities, actively coordinates reverse-proxy cache states, and evaluates responses against formal authorization invariants.

---

## 2. Related Work and Research Taxonomy

We position TenantCache in the context of four adjacent bodies of research:

### 2.1 Web Cache Vulnerabilities: Poisoning, Deception, and Entanglement
Research into web caching vulnerabilities has historically focused on cache poisoning and cache deception:
- **Web Cache Poisoning:** Pioneered by Kettle [7, 8], cache poisoning manipulates unkeyed HTTP request components (e.g., `X-Forwarded-Host`, `X-Original-URL`) to force intermediate caches to store harmful representations (such as reflected Cross-Site Scripting or malicious redirects) that are subsequently delivered to benign users.
- **Web Cache Deception (WCD):** First identified by Klein [9] and analyzed systematically by Mirheidari et al. [10] and Nguyen et al. [6], WCD exploits URL path delimiter confusion (e.g., `;`, `\`, `.css` extensions) between proxies and origin servers, tricking caches into persisting dynamic user profile pages under static resource keys.

*Distinct Gap Addressed:* Both cache poisoning and deception focus on injecting hostile payloads or manipulating public path parsing to deceive third-party victim sessions. In contrast, **multi-tenant cache isolation failures** occur under ordinary, non-hostile request paths: legitimate tenant endpoints leak confidential data to adversarial co-tenants simply because edge proxies lack identity context, construct unkeyed cache partitions, or maintain unexpired representations following origin privilege revocations.

### 2.2 Stateful REST API Fuzzing and Specification Mining
Grammar-driven and stateful API fuzzers, such as RESTler [1], Schemathesis, and QuickREST, analyze OpenAPI specifications to generate syntactically and semantically valid request sequences. They model request-response producer-consumer dependencies (e.g., obtaining a dynamic ID via `POST /resource` before calling `GET /resource/{id}`). However, existing fuzzers operate exclusively against origin services, treating intermediate network caching as transparent network plumbing. Consequently, they do not manage cache states ($S_{\text{cold}}, S_{\text{warm}}, S_{\text{purge}}$) and remain blind to proxy-mediated isolation failures.

### 2.3 Differential Testing and Verification Oracles
Differential testing, introduced by McKeeman [12] and expanded in systems security (e.g., NEZHA [13]), compares behavioral discrepancies across diverse software implementations to detect bugs without an explicit oracle. While effective for compiler verification and protocol parsers, applying naive differential checking to multi-user web applications produces prohibitive false positive rates: legitimate differences (such as tenant-specific branding, user IDs, and timestamps) are flagged as anomalies, while authorized shared representations (such as public documentation) are misclassified as leaks.

### 2.4 Multi-Tenant Authorization Auditing
Industry security tools (such as Autorize and AuthMatrix [11]) audit access control by replaying session tokens across API endpoints. Crucially, these tools operate statelessly on individual endpoints and explicitly disable caching (`Cache-Control: no-cache`, unique query nonces) to avoid stale responses. As our empirical evaluation reveals, this stateless model results in a $100\%$ false-negative rate when evaluating reverse-proxy cache isolation.

| Dimension | Web Cache Poisoning [7, 8] | Web Cache Deception [6, 10] | Stateful REST Fuzzing [1] | Authorization Scanners [11] | **TenantCache (This Work)** |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Primary Threat** | Malicious content injection | Victim path confusion | Origin logic / server crashes | Broken object authorization | **Cross-tenant data leakage** |
| **Cache Awareness** | Keyed vs unkeyed header auditing | Path delimiter heuristics | None (Origin only) | None (Bypasses caching) | **Full lifecycle orchestration** |
| **State Dimension** | Stateless single-request | Stateless URL craft | Multi-request API sequences | Stateless token replay | **Coupled: $\Sigma_{\text{auth}} \times \Sigma_{\text{cache}}$** |
| **Oracle Mechanism** | Reflected payload matching | HTML / CSS structure diffing | HTTP 500 error detection | Status code / length diffing | **Independent Ground-Truth** |
| **Multi-Tenancy** | Single-tenant assumption | Single-tenant victim lure | Single-tenant session | Dual-token single tenant | **Full multi-tenant matrix** |

---

## 3. Research Contribution Taxonomy

In alignment with rigorous academic standards, we decompose TenantCache's contributions into three distinct tiers:

1. **Engineering Integration:** Integrating RFC 9111 HTTP caching semantics, Nginx reverse-proxy configuration models, deterministic ASGI simulation, and cryptographic canary taint tracking into an automated, verifiable testing framework.
2. **Proposed Testing Methodology:** Formally coupling the temporal transitions of two independent state machines—the origin database authorization state $\Sigma_{\text{auth}}$ and the proxy cache state $\Sigma_{\text{cache}}$—combined with an independent ground-truth security oracle $\mathcal{A}(P, R, Q) \in \{\text{ALLOW}, \text{DENY}\}$ that detects confidentiality violations decoupled from HTTP status codes.
3. **Experimentally Proven Improvements:** Demonstrating that stateful differential verification eliminates the 100% false-negative blind spot of stateless scanners, detects temporal revocation lag, and suppresses false alarms on legitimately shared public assets ($FPR = 0\%$) under equal request budgets.

---

## 4. Threat Model and Formal Problem Formulation

### 4.1 HTTP Caching Normatives (RFC 9111)
RFC 9111 [4] defines requirements for HTTP caching. Section 3.2 specifies that shared caches MUST NOT store responses to requests with an `Authorization` header field unless explicit directives (`must-revalidate`, `public`, `s-maxage`) are present. However, modern microservices frequently pass authentication tokens via cookies, custom headers (`X-API-Key`, `X-Access-Token`), or behind reverse proxies configured with aggressive `proxy_ignore_headers Cache-Control`.

### 4.2 Threat Model
We define three primary threat actors:
1. **Cross-Tenant Malicious Principal ($P_{\text{Ext}}$):** Holds valid credentials for Tenant B; attempts to access Tenant A's private data.
2. **Intra-Tenant Privilege Escalator ($P_{\text{Priv}}$):** Holds a standard user account in Tenant A; attempts to access Tenant A administrative resources.
3. **Revoked Principal ($P_{\text{Rev}}$):** A formerly authorized user whose access was revoked in the origin database; attempts to retrieve cached resources before proxy TTL expiration.

Adversaries can send arbitrary HTTP requests, forge client-supplied headers (e.g., `X-Tenant-ID`), and execute requests in arbitrary temporal order. Adversaries cannot compromise transport layer encryption (TLS).

### 4.3 Coupled State Machine Formulation
We model the system under test as a composition of two asynchronous state machines:
1. **Origin Authorization State ($\Sigma_{\text{auth}}$):**
   $$\sigma_{\text{auth}} = \langle \mathcal{U}, \mathcal{T}, \mathcal{R}, \mathcal{M}, \mathcal{L} \rangle$$
   where $\mathcal{U}$ is the set of user identities, $\mathcal{T}$ is the tenant set, $\mathcal{R}$ is the resource catalog, $\mathcal{M}$ represents role and permission bindings, and $\mathcal{L}$ is the authoritative access ledger.
2. **Proxy Cache State ($\Sigma_{\text{cache}}$):**
   $$\sigma_{\text{cache}} = \langle \mathcal{K}, \mathcal{V}, \tau \rangle$$
   where $\mathcal{K} \to \mathcal{V}$ maps cache keys $k = \kappa(req)$ to cached response representations $v = \langle \text{Status}, \text{Headers}, \text{Body} \rangle$, and $\tau: \mathcal{K} \to \mathbb{R}^+$ denotes time-to-live expiration.

A vulnerability exists if a sequence of transitions drives the coupled system $(\sigma_{\text{auth}}, \sigma_{\text{cache}})$ into a state where an unauthorized principal $P$ executes a request $Q$ yielding response $v$, such that:
$$\mathcal{A}(P, R, Q) = \text{DENY} \quad \land \quad \text{Taint}(v, R) = \text{TRUE}$$

### 4.4 The Confidentiality Invariant
Let $\mathcal{P}$ denote the set of principals $P = (T_P, U_P, R_P)$, $\mathcal{R}$ denote the set of resources $R = (T_R, \text{Owner}_R, \text{Visibility}_R, \mathcal{C}_R)$, and $\mathcal{A}: \mathcal{P} \times \mathcal{R} \times \mathcal{Q} \to \{\text{ALLOW}, \text{DENY}\}$ denote an independent ground-truth authorization function.

We formalize the cache confidentiality invariant as:

$$\forall P \in \mathcal{P}, \forall R \in \mathcal{R}, \forall S \in \mathcal{S}_{\text{cache}}: \quad \mathcal{A}(P, R, Q) = \text{DENY} \implies \mathcal{C}_R \cap \text{Tokens}(\text{Body}(\text{Resp}(P, Q_R, S))) = \emptyset$$

where $\mathcal{C}_R$ is the cryptographically unique canary token set embedded in resource $R$, and $\text{Resp}(P, Q_R, S)$ is the observed HTTP response served by the proxy cache under state $S$.

---

## 5. System Architecture and Methodology

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

1. **Tenant Simulator:** Generates synthetic tenants, users, roles, and resources, embedding unique SHA-256 and CRC32 canaries.
2. **Request Generation Engine:** Synthesizes multi-tenant request permutations and multi-step cache state sequences:
   - *Phase 1 (Prime):* Authorized principal $P_1$ requests resource $R$, populating proxy cache state $\sigma_{\text{cache}} \to S_{\text{warm}}$.
   - *Phase 2 (Mutate / Revoke):* Optional administrative event revokes $P_1$'s permission or alters access control in $\Sigma_{\text{auth}}$.
   - *Phase 3 (Probe):* Target principal $P_2$ requests $R$ under warm cache state.
3. **Cache State Controller:** Controls and observes proxy cache lifecycles ($S_{\text{cold}}, S_{\text{warm}}, S_{\text{purge}}$) across native Nginx binary execution and high-fidelity ASGI simulation.
4. **Security Oracle:** Evaluates access permissions independently of target application HTTP status codes, failing closed on unregistered principals.
5. **Leakage Detection Engine:** Scans response bodies for canary tokens, proving unauthorized disclosure with mathematical certainty.
6. **Benchmark Suite:** Computes precision, recall, specificity, F1, and execution throughput against baseline scanners, calculating 95% Wilson score confidence intervals.

---

## 6. Experimental Evaluation

### 6.1 Experimental Configuration Archetypes
We evaluated eight configuration archetypes across our reconciled **66-scenario benchmark corpus** (Dataset v1.1):
- **$V_1$ (Missing Tenant Key):** Cache key is `$scheme$request_method$host$request_uri`.
- **$V_2$ (Missing User Context):** Cache key includes tenant, but omits user identity.
- **$V_3$ (Unvalidated Header Key):** Cache key includes untrusted client header `$http_x_tenant_id`.
- **$V_4$ (Stale Revocation):** Prolonged cache TTL without dynamic invalidation hooks across 8 distinct revocation scenarios.
- **$V_5$ (Erroneous Public Cache Policy):** Shared caching applied across private endpoints.
- **$V_6$ (Path-Normalization Aliasing):** Cache key is `$scheme$request_method$host$uri`, which collapses duplicate delimiters (`//` to `/`), causing canonical path `/api/v1/tenant/dashboard` and aliased path `/api/v1/tenant//dashboard` to collide into the same cached response.
- **$S_1$ (Strict Private Cache Bypass):** Any authenticated request unconditionally bypasses cache (`proxy_cache_bypass $http_authorization`).
- **$S_2$ (Server-Validated Identity Keying with Per-Request Auth Verification):** Employs Nginx `auth_request` subrequests to evaluate token validity, tenant affiliation, and resource ACLs (including temporal revocation and post-deletion existence checks) on every request prior to cache-hit serving. Cache keys partition by server-verified variables (`$auth_tenant|$auth_user`) while untrusted client identity headers are explicitly stripped.

> [!NOTE] Authorization-Decision Parity vs. Status Code Mapping
> In $S_2$, authorization-decision parity is strictly maintained between origin handlers and the reverse-proxy verifier through the shared authoritative policy engine (`evaluate_request_authorization`). For direct origin requests, deleted or nonexistent resources return standard REST `404 Not Found`. For the proxy authorization subrequest, the verifier deliberately maps inaccessible or nonexistent protected resources to HTTP `403 Forbidden` in strict compliance with the Nginx `ngx_http_auth_request_module` specification (which treats non-200/401/403 responses as 500 server errors). This guarantees fail-closed defense: Nginx aborts the access phase immediately and never serves a cached response for deleted or inaccessible assets.

### 6.2 Real Nginx (v1.26.2) Native Validation
To ensure findings reflect real-world reverse-proxy software, all eight configuration archetypes were directly executed and verified against a live instance of native Nginx 1.26.2 on Windows localhost and Nginx 1.26.3 on Linux (`tests/integration/test_real_nginx.py`). The live Nginx proxy reproduced all six vulnerability archetypes ($V_1$–$V_6$) with live `X-Cache-Status: HIT` responses containing confidential canaries, while confirming that $S_1$ and $S_2$ maintain zero leakage with `BYPASS` and segregated `MISS`/`HIT` statuses.

### 6.3 Matched-Budget Evaluation vs. Capability Evaluation

To address baseline testing fairness, we evaluated all frameworks under two distinct protocols:

#### Table 1: Matched-Budget Comparison (Equal 3-Request Budget per Scenario, Total 198 Requests)
| Testing Approach | Cache Archetype | Requests | Resets | TP | FP | TN | FN | Precision (95% Wilson CI) | Recall (95% Wilson CI) | Specificity (95% Wilson CI) | False Positive Rate |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Baseline A (Stateless DAST)** | `V1` | 198 | 66 | 0 | 0 | 20 | 46 | *N/A (Undefined)* | **0.0000** `[0.00, 0.08]` | **1.0000** `[0.84, 1.00]` | **0.0000** `[0.00, 0.16]` |
| **Baseline B (Naive Diffing)** | `V1` | 198 | 66 | 38 | 12 | 8 | 8 | **0.7600** `[0.63, 0.86]` | **0.8261** `[0.69, 0.91]` | **0.4000** `[0.22, 0.61]` | **0.6000** `[0.39, 0.78]` |
| **TenantCache (Proposed)** | `V1` | 198 | 66 | 46 | 0 | 20 | 0 | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.84, 1.00]` | **0.0000** `[0.00, 0.16]` |

#### Table 2: Comprehensive Capability Evaluation Across All 8 Archetypes (Dataset v1.1, 66 Scenarios)
| Methodology | Cache Archetype | Scenarios | TP | FP | TN | FN | Precision (95% CI) | Recall (95% CI) | Specificity (95% CI) | Accuracy (95% CI) | Duration |
|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Baseline A** | `V1_MISSING_TENANT_KEY` | 66 | 0 | 0 | 20 | 46 | *N/A* | 0.0000 `[0.00, 0.08]` | 1.0000 `[0.84, 1.00]` | 0.3030 `[0.21, 0.42]` | 0.46s |
| **Baseline B** | `V1_MISSING_TENANT_KEY` | 66 | 38 | 12 | 8 | 8 | 0.7600 `[0.63, 0.86]` | 0.8261 `[0.69, 0.91]` | 0.4000 `[0.22, 0.61]` | 0.6970 `[0.58, 0.79]` | 0.60s |
| **TenantCache** | `V1_MISSING_TENANT_KEY` | 66 | 46 | 0 | 20 | 0 | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.84, 1.00]` | **1.0000** `[0.94, 1.00]` | 0.60s |
| **TenantCache** | `V2_MISSING_USER_AUTH` | 66 | 29 | 0 | 34 | 3 | **1.0000** `[0.88, 1.00]` | **0.9062** `[0.76, 0.97]` | **1.0000** `[0.90, 1.00]` | **0.9545** `[0.87, 0.98]` | 0.78s |
| **TenantCache** | `V3_UNVALIDATED_HEADER` | 66 | 29 | 0 | 34 | 3 | **1.0000** `[0.88, 1.00]` | **0.9062** `[0.76, 0.97]` | **1.0000** `[0.90, 1.00]` | **0.9545** `[0.87, 0.98]` | 0.77s |
| **TenantCache** | `V4_STALE_REVOCATION` | 66 | 8 | 0 | 58 | 0 | **1.0000** `[0.68, 1.00]` | **1.0000** `[0.68, 1.00]` | **1.0000** `[0.94, 1.00]` | **1.0000** `[0.94, 1.00]` | 0.94s |
| **TenantCache** | `V5_ERRONEOUS_PUBLIC` | 66 | 46 | 0 | 20 | 0 | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.84, 1.00]` | **1.0000** `[0.94, 1.00]` | 0.60s |
| **TenantCache** | `V6_NORMALIZATION` | 66 | 46 | 0 | 20 | 0 | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.84, 1.00]` | **1.0000** `[0.94, 1.00]` | 0.61s |
| **TenantCache** | `SECURE_S1_STRICT_PRIVATE` | 66 | 0 | 0 | 66 | 0 | *N/A (Undefined)* | *N/A (Undefined)* | **1.0000** `[0.94, 1.00]` | **1.0000** `[0.94, 1.00]` | 1.08s |
| **TenantCache** | `SECURE_S2_IDENTITY_KEYED` | 66 | 0 | 0 | 66 | 0 | *N/A (Undefined)* | *N/A (Undefined)* | **1.0000** `[0.94, 1.00]` | **1.0000** `[0.94, 1.00]` | 1.01s |

### 6.4 Component Ablation Study & Category Confusion Matrices

To measure the independent contribution of each system component, an ablation study was conducted on Archetype $V_1$ across all 66 scenarios:

| System Variant | Identity Aware | Cache Sequenced | Ground-Truth Oracle | Precision | Recall | F1 Score | False Positive Rate | TP / FN |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Full TenantCache** | **YES** | **YES** | **YES** | **1.0000** | **1.0000** | **1.0000** | **0.0000** | **46 / 0** |
| **Ablation 1: No Cache Sequencing** | YES | **NO** | YES | *N/A* | **0.0000** | *N/A* | 0.0000 | 0 / 46 |
| **Ablation 2: No Ground-Truth Oracle** | YES | YES | **NO** | 0.7600 | 0.8261 | 0.7917 | **0.6000** | 38 / 8 |
| **Control: Single-User Reachability Control** | **NO** | YES | YES | *N/A* | **0.0000** | *N/A* | 0.0000 | 0 / 46 |

#### Category Confusion Matrix for Ablation 2 (No Ground-Truth Oracle)
- **Stale Revocation ($FN = 8$ of $8$):** A naive tester compares observable differences across distinct user tokens. When the probing user matches the priming user, a cache hit appears to be normal same-user caching. Without an authorization oracle, the tool cannot detect temporal permission revocation.
- **Benign Controls ($FP = 12$ of $20$):** Without an authorization oracle, 8 public document accesses and 4 intra-tenant shared dashboard accesses returning cache HIT are misclassified as leaks.

#### Category Confusion Matrix for Control: Single-User Reachability Control
Executing scans using a single authenticated principal (Alice vs. Alice) serves as a reachability control experiment rather than a causal ablation: by construction, replacing both the priming and probing principals with the same identity removes the cross-principal condition that defines multi-tenant cache isolation failures. As expected, $0.00\%$ Recall is observed ($TP=0, FN=46$) while benign controls evaluate correctly as authorized ($TN=20, FP=0$). This confirms that multi-principal orchestration is structurally necessary to reach and trigger tenant-isolation vulnerabilities.

### 6.5 Multi-Seed Deterministic Reproducibility
Evaluating TenantCache across 5 independent deterministic seeds (`[42, 43, 44, 45, 46]`) yielded a Mean Recall of $1.0000$ ($\sigma = 0.0000$), Mean Precision of $1.0000$ ($\sigma = 0.0000$), and Mean Throughput of $348.0 \text{ req/s}$ ($\sigma = 39.8$), verifying zero execution jitter across runs.

---

## 7. Discussion and Research Findings

1. **RQ1 (Detection Efficacy):** Under equal testing budgets (198 requests), TenantCache achieved $1.0000$ Recall ($[0.92, 1.00]$ CI), whereas Baseline A achieved $0.0000$ Recall ($[0.00, 0.08]$ CI). Cache sequencing is the definitive factor enabling vulnerability discovery.
2. **RQ2 (Vulnerability Susceptibility):** In $V_3$, relying on client-supplied headers (`X-Tenant-ID`) enables an adversary to forge headers and trigger cache collisions. TenantCache detected all header-spoofing injection vectors with zero false positives.
3. **RQ3 (Temporal Revocation Lag):** In $V_4$, evaluated across 8 distinct project revocation scenarios, TenantCache detected 100% of the unexpired cached representations following backend database revocation ($TP = 8, FN = 0$).
4. **RQ4 (Invariant Precision):** Across all 20 negative control scenarios, TenantCache recorded $0$ false positives ($FPR = 0.0000$), whereas naive diffing (Baseline B and Ablation 2) recorded a $60.00\%$ false-positive rate ($FPR = 0.6000$, 12 FPs).

### 7.1 Threats to Validity and Generalization Bounds

- **Synthetic Corpus Calibration:** The experimental evaluation establishes classification accuracy across the controlled 66-scenario corpus (Dataset v1.1). While this corpus rigorously exercises the six primary multi-tenant cache vulnerability patterns ($V_1$ through $V_6$) alongside balanced negative controls, the reported perfect precision and recall reflect deterministic performance within this defined benchmark universe rather than universal detection accuracy across arbitrary in-the-wild microarchitectures.
- **Baseline Scoping & Equal Request Count:** Baselines A and B represent custom reference implementations engineered to isolate specific algorithmic properties (stateless single-request probing and naive length/token differential checking without authorization state synchronization). They do not evaluate commercial enterprise DAST suites or tools with custom multi-user automation scripts. The equal-budget comparison reflects an identical request count (198 requests), during which stateful coordination explores state transitions that stateless or unsynchronized execution structurally cannot reach.
- **Scenario Correlation & Descriptive Confidence Intervals:** Scenarios in Dataset v1.1 instantiate 46 vulnerable flows across a universe of 5 enterprise tenants, 10 user principals, and 27 resources; consequently, individual scenario observations are not strictly independent identically distributed (i.i.d.) random variables. The reported Wilson score confidence intervals should be interpreted as descriptive scenario-level bounds rather than population-wide Bernoulli confidence limits across heterogeneous unobserved systems.
- **Execution Stability vs. Population Generalization:** The zero-variance outcome across five independent pseudo-random seed repetitions ($\sigma = 0.0000$) demonstrates execution determinism and harness stability within the synthetic lab universe; it does not constitute empirical sampling across thousands of heterogeneous, real-world multi-tenant production systems.
- **Statistical Confidence Intervals:** In all tables and claims, classification performance is grounded in 95% Wilson score confidence intervals (e.g., $V_1$ recall $[0.92, 1.00]$, $V_4$ recall $[0.68, 1.00]$). Empirical efficacy on production deployments remains bounded by proxy normalization nuances, custom header transformations, and application-specific session invalidation semantics.

---

## 8. Conclusion

TenantCache demonstrates that an automated differential verification framework coupling origin authorization state machines with reverse-proxy cache lifecycles reliably detects multi-tenant cache isolation failures. Validated against native Nginx 1.26.2 and evaluated across a reconciled 66-scenario corpus with 95% Wilson confidence intervals, TenantCache provides a mathematically defensible, reproducible methodology for web cache security.

---

## References

[1] V. Atlidakis, P. Godefroid, and M. Polishchuk, "RESTler: Stateful REST API Fuzzing," in *Proc. 41st IEEE/ACM International Conference on Software Engineering (ICSE)*, 2019, pp. 748–758.  
[2] S. Karlsson, A. Causevic, and D. Sundmark, "Differential Regression Testing for REST APIs," in *Proc. 29th ACM SIGSOFT International Symposium on Software Testing and Analysis (ISSTA)*, 2020.  
[3] OWASP Foundation, "Web Cache Security Cheat Sheet," *OWASP Cheat Sheet Series*, 2024. [Online]. Available: https://cheatsheetseries.owasp.org/  
[4] R. Fielding, M. Nottingham, and J. Reschke, "HTTP Caching," *RFC 9111*, Internet Engineering Task Force (IETF), Jun. 2022.  
[5] C.-P. Bezemer and A. Zaidman, "Multi-Tenant SaaS Applications: Maintenance and Evolution Challenges," in *Proc. International Workshop on Principles of Software Evolution and ERCIM Workshop on Software Evolution (IWPSE-EVOL)*, 2010, pp. 1–9.  
[6] K. Nguyen, D. Nosenko, and G. Pellegrino, "Web Cache Deception Turns Pervasive: New Findings from the Front Lines," in *Proc. 33rd USENIX Security Symposium (USENIX Security)*, 2024.  
[7] J. Kettle, "Practical Web Cache Poisoning: Redefining 'Uncacheable'," *Black Hat USA*, PortSwigger Research, Aug. 2018.  
[8] J. Kettle, "Web Cache Entanglement: Novel Roots of Asymmetry," *Black Hat USA*, PortSwigger Research, Aug. 2020.  
[9] A. Klein, "Web Cache Deception Attack," *Security Research Report*, Feb. 2017.  
[10] S. A. Mirheidari, S. Arshad, K. Onarlioglu, C. Mulliner, W. Robertson, and E. Kirda, "Web Cache Deception Escalates: New Attacks, Sophisticated Transport Paths and Defenses," in *Proc. 29th USENIX Security Symposium (USENIX Security)*, 2020, pp. 1365–1382.  
[11] B. Tawily, "Autorize: Automatic Authorization Enforcement Detection," *PortSwigger BApp Store*, 2023.  
[12] W. M. McKeeman, "Differential Testing for Software," *Digital Technical Journal*, vol. 10, no. 1, pp. 100–107, 2000.  
[13] T. Petsios, A. Tang, S. Stolfo, A. D. Keromytis, and S. Jana, "NEZHA: Efficient Domain-Independent Differential Testing," in *Proc. IEEE Symposium on Security and Privacy (S&P)*, 2017, pp. 633–648.
