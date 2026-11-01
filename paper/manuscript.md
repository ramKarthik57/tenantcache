# Automated Differential Verification of Cache Isolation in Multi-Tenant Web Applications

**Authors:** TenantCache Research and Engineering Team  
**Affiliation:** Cyber Defense and Distributed Systems Research Laboratory  
**Artifacts & Code:** Fully reproducible local laboratory prototype (`https://github.com/tenantcache/tenantcache`)

---

## Abstract

Multi-tenant web applications routinely interpose shared reverse-proxy caching layers (such as Nginx, Varnish, and Cloudflare) to meet low-latency and high-throughput demands. However, modern authorization models reside deep within application business logic and database queries, whereas reverse proxies evaluate cache hits at the network edge using synthetic cache keys constructed from minimal HTTP request attributes. When cache keys omit validated tenant identifiers, rely on client-supplied headers, ignore user authorization scopes, or fail to invalidate representations upon origin permission revocation, confidential responses belonging to one tenant are delivered directly to unauthorized users. Conventional Dynamic Application Security Testing (DAST) tools and authorization scanners evaluate endpoints statelessly or explicitly bypass intermediate caches, remaining fundamentally blind to proxy-mediated isolation failures.

In this paper, we present **TenantCache**, the first automated, identity-aware differential verification framework specifically engineered to validate HTTP cache isolation in multi-tenant systems. TenantCache unifies stateful cache-lifecycle orchestration with an independent ground-truth authorization oracle and cryptographic canary tracking. By generating structured sequences across multi-tenant principal matrices ($T_A \leftrightarrow T_B$, Admin $\leftrightarrow$ Standard User, Authorized $\to$ Revoked) and inspecting proxy cache states, TenantCache provably attributes information leakage with zero false positives on legitimately shared public assets.

We evaluate TenantCache across eight distinct reverse-proxy cache archetypes ($V_1$–$V_6$ representing common production misconfigurations, and $S_1$–$S_2$ implementing defensible secure controls) against conventional stateless endpoint testing (Baseline A) and simple token substitution (Baseline B). In empirical benchmarks, conventional endpoint testing achieved an empirical Recall of $0.0000$ ($FN = 7$), completely failing to detect cache isolation failures. Simple identity substitution achieved $0.7143$ Recall, missing temporal authorization revocation lag. In contrast, TenantCache achieved a Precision of $1.0000$, a Recall of $1.0000$, and an F1 score of $1.0000$ across vulnerable and secure archetypes, demonstrating that stateful identity-aware differential verification is essential for guaranteeing multi-tenant cache confidentiality.

---

## 1. Introduction

Cloud-native Software-as-a-Service (SaaS) applications predominantly utilize multi-tenant architectures, where physical compute, networking, and caching infrastructure are shared across logically segregated corporate tenants. To mitigate database bottlenecks and accelerate response latencies, multi-tenant architectures place HTTP reverse-proxy caches at the perimeter.

However, an acute, systemic architectural friction exists between **multi-tenancy** and **shared HTTP caching**:
1. **Authorization Logic is Origin-Centric:** Access control policies (RBAC, ABAC, multi-tenant row-level isolation) reside within application code and database queries.
2. **Caching Logic is Edge/Proxy-Centric:** Reverse proxies determine whether to serve a cached response using a synthetic **Cache Key**, conventionally constructed from a minimal subset of the request:
   $$\text{CacheKey} = \text{hash}(\text{Method}, \text{Scheme}, \text{Host}, \text{URI})$$
3. **The Semantic Disconnect:** If an authenticated application endpoint returns confidential tenant data without explicitly instructing the reverse proxy to include the tenant/user identity in the cache key (or to disallow shared caching entirely via `Cache-Control: private, no-store`), the proxy will treat requests from different tenants with identical URI paths as identical. Consequently, **Tenant B receives Tenant A's confidential response directly from the proxy cache without the application server ever being consulted**.

Existing security tools fail to detect this class of vulnerability:
- **Authorization Scanners (Autorize, AuthMatrix):** Replay tokens on individual endpoints while instructing proxies to bypass caching.
- **Cache Poisoning Scanners (Param Miner):** Focus strictly on unkeyed header reflection for cross-site scripting (XSS), missing authentic multi-tenant data leaks.
- **Stateless DAST Tools (ZAP, Burp ActiveScan):** Analyze responses in isolation without coordinating multi-user cache-warming sequences.

To address this challenge, we introduce **TenantCache**, an automated differential security verification framework that models multi-tenant identities, manipulates reverse-proxy cache states, and evaluates responses against formal security invariants.

---

## 2. Background and Threat Model

### 2.1 HTTP Caching Normatives (RFC 9111)
RFC 9111 defines requirements for HTTP caching. Section 3.2 specifies that shared caches MUST NOT store responses to requests with an `Authorization` header field unless explicit directives (`must-revalidate`, `public`, `s-maxage`) are present. However, modern microservices frequently pass authentication tokens via cookies, custom headers (`X-API-Key`, `X-Access-Token`), or behind reverse proxies configured with aggressive `proxy_ignore_headers Cache-Control`.

### 2.2 Threat Model
We define three primary threat actors:
1. **Cross-Tenant Malicious Principal ($P_{\text{Ext}}$):** Holds valid credentials for Tenant B; attempts to access Tenant A's data.
2. **Intra-Tenant Privilege Escalator ($P_{\text{Priv}}$):** Holds a standard user account in Tenant A; attempts to access Tenant A administrative resources.
3. **Revoked Principal ($P_{\text{Rev}}$):** A formerly authorized user whose access was revoked in the origin database; attempts to retrieve cached resources before proxy TTL expiration.

Adversaries can send arbitrary HTTP requests, forge client-supplied headers (e.g., `X-Tenant-ID`), and execute requests in arbitrary temporal order. Adversaries cannot compromise transport layer encryption (TLS).

---

## 3. Formal Problem Formulation

Let $\mathcal{P}$ denote the set of principals $P = (T_P, U_P, R_P)$, $\mathcal{R}$ denote the set of resources $R = (T_R, \text{Owner}_R, \text{Visibility}_R, \mathcal{C}_R)$, and $\mathcal{A}: \mathcal{P} \times \mathcal{R} \times \mathcal{Q} \to \{\text{ALLOW}, \text{DENY}\}$ denote an independent ground-truth authorization function.

### 3.1 The Confidentiality Invariant
We formalize the cache confidentiality invariant as:

$$\forall P \in \mathcal{P}, \forall R \in \mathcal{R}, \forall S \in \mathcal{S}_{\text{cache}}: \quad \mathcal{A}(P, R, Q) = \text{DENY} \implies \mathcal{C}_R \cap \text{Tokens}(\text{Body}(\text{Resp}(P, Q_R, S))) = \emptyset$$

where $\mathcal{C}_R$ is the cryptographically unique canary token set embedded in resource $R$, and $\text{Resp}(P, Q_R, S)$ is the observed HTTP response served by the proxy cache under state $S$.

---

## 4. System Architecture

TenantCache comprises six decoupled subsystems:

```
┌─────────────────────────────────────────────────────────────┐
│                       TENANT SIMULATOR                      │
│     (Tenants, Users, Synthetic Canaries, Ground-Truth)      │
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
2. **Request Generation Engine:** Synthesizes multi-tenant request permutations and sequences ($\alpha, \beta, \gamma, \delta$).
3. **Cache State Controller:** Controls and observes proxy cache lifecycles ($S_{\text{cold}}, S_{\text{warm}}, S_{\text{purge}}$) via live Nginx reverse proxies or high-fidelity ASGI simulation.
4. **Security Oracle:** Evaluates access permissions independently of target application HTTP status codes.
5. **Leakage Detection Engine:** Scans response bodies for canary tokens, proving unauthorized disclosure with mathematical certainty.
6. **Benchmark Suite:** Computes precision, recall, F1, and execution throughput against baseline scanners.

---

## 5. Experimental Evaluation

### 5.1 Experimental Configuration Archetypes
We evaluated eight configuration archetypes:
- **$V_1$ (Missing Tenant Key):** Cache key is `$scheme$request_method$host$request_uri`.
- **$V_2$ (Missing User Context):** Cache key includes tenant, but omits user identity.
- **$V_3$ (Unvalidated Header Key):** Cache key includes untrusted client header `$http_x_tenant_id`.
- **$V_4$ (Stale Revocation):** Prolonged cache TTL without dynamic invalidation hooks.
- **$V_5$ (Erroneous Public Cache Policy):** Shared caching applied across private endpoints.
- **$V_6$ (Normalization Discrepancy):** Inconsistent URI path stripping and case folding.
- **$S_1$ (Strict Private Cache Bypass):** Any authenticated request unconditionally bypasses cache (`proxy_cache_bypass $http_authorization`).
- **$S_2$ (Identity-Keyed with Purge):** Cryptographically bound cache keys combined with dynamic cache purge hooks upon permission revocation.

### 5.2 Experimental Results
The table below presents the quantitative evaluation across 9 controlled scenarios per archetype:

| System / Archetype | TP | FP | TN | FN | Precision | Recall | F1 Score | Accuracy | Duration |
|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|
| **Baseline A** ($V_1$) | 0 | 0 | 2 | 7 | 1.0000 | **0.0000** | **0.0000** | 0.2222 | 0.127s |
| **Baseline B** ($V_1$) | 5 | 0 | 2 | 2 | 1.0000 | **0.7143** | **0.8333** | 0.7778 | 0.014s |
| **TenantCache** ($V_1$) | 7 | 0 | 2 | 0 | **1.0000** | **1.0000** | **1.0000** | **1.0000** | 0.025s |
| **TenantCache** ($V_2$) | 4 | 0 | 5 | 0 | **1.0000** | **1.0000** | **1.0000** | **1.0000** | 0.031s |
| **TenantCache** ($V_3$) | 4 | 0 | 5 | 0 | **1.0000** | **1.0000** | **1.0000** | **1.0000** | 0.033s |
| **TenantCache** ($V_4$) | 1 | 0 | 8 | 0 | **1.0000** | **1.0000** | **1.0000** | **1.0000** | 0.040s |
| **TenantCache** ($V_5$) | 7 | 0 | 2 | 0 | **1.0000** | **1.0000** | **1.0000** | **1.0000** | 0.022s |
| **TenantCache** ($V_6$) | 7 | 0 | 2 | 0 | **1.0000** | **1.0000** | **1.0000** | **1.0000** | 0.022s |
| **TenantCache** ($S_1$) | 0 | 0 | 9 | 0 | **1.0000** | **1.0000** | **1.0000** | **1.0000** | 0.042s |
| **TenantCache** ($S_2$) | 0 | 0 | 9 | 0 | **1.0000** | **1.0000** | **1.0000** | **1.0000** | 0.045s |

---

## 6. Discussion and Research Findings

### 6.1 Validating Research Questions
1. **RQ1 (Detection Efficacy):** Identity-aware differential testing discovered 100% of injected cache isolation failures, whereas single-endpoint DAST (Baseline A) discovered 0%.
2. **RQ2 (Vulnerability Susceptibility):** Relying on client-supplied headers (`X-Tenant-ID`) fails to guarantee isolation; adversaries can forge headers to extract cached responses across tenants ($V_3$).
3. **RQ3 (Temporal Revocation Lag):** Baseline B missed authorization revocation failures. Modeling dynamic state transitions between request steps is mandatory for evaluating temporal isolation ($V_4$).
4. **RQ4 (Invariant Precision):** On public documentation and legitimate intra-tenant resources, TenantCache recorded $FPR = 0.0000$, validating canary taint attribution over naive response diffing.

### 6.2 Defensive Recommendations
1. **Default Deny Shared Caching:** Authenticated endpoints MUST emit `Cache-Control: private, no-store`.
2. **Never Key on Untrusted Headers:** Reverse proxy cache keys must never incorporate unvalidated client headers.
3. **Dynamic Surrogate-Key Purging:** Origin database updates affecting authorization must actively purge upstream proxy caches.

---

## 7. Conclusion

This paper presented TenantCache, an automated differential verification framework for web cache isolation in multi-tenant systems. By combining identity-aware request sequences, stateful cache control, an independent ground-truth security oracle, and canary invariant tracking, TenantCache overcomes the fundamental blindness of conventional security scanners. Our empirical evaluation demonstrated $1.0000$ Precision and $1.0000$ Recall across diverse vulnerable and secure proxy configurations, establishing a principled foundation for automated multi-tenant cache security verification.

---

## References

Available in `paper/references.bib`.
