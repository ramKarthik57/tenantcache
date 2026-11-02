---
marp: true
theme: default
paginate: true
header: "TenantCache: Differential Verification of Cache Isolation"
footer: "Ramkumar V. | Advanced Systems & Cybersecurity Research Group"
style: |
  section {
    font-family: 'Helvetica Neue', Arial, sans-serif;
    font-size: 24px;
    padding: 40px;
  }
  h1 {
    color: #1a365d;
  }
  h2 {
    color: #2b6cb0;
  }
  table {
    font-size: 20px;
  }
  .highlight {
    background-color: #ebf8ff;
    border-left: 6px solid #3182ce;
    padding: 10px;
  }
---

# Automated Differential Verification of Cache Isolation in Multi-Tenant Web Applications

**Ramkumar V.**  
*Advanced Systems & Cybersecurity Research Group*  
Canonical Artifact: `v1.1.0` | GitHub: `ramKarthik57/tenantcache`

---

## 1. Executive Problem Statement

* Modern cloud Software-as-a-Service (SaaS) applications host multiple corporate entities (**tenants**) on shared infrastructure.
* To meet sub-millisecond latency requirements, applications place **HTTP reverse-proxy caches** (e.g. Nginx, Varnish, Cloudflare) at the network edge.
* **The Collision:**
  * Application authorization is **origin-centric** (RBAC, row-level database filters).
  * Reverse proxies evaluate cache hits **edge-centrically** using minimal synthetic keys:
    $$\text{CacheKey} = \text{hash}(\text{Method}, \text{Scheme}, \text{Host}, \text{URI})$$
* **Result:** Tenant B requests `/api/v1/tenant/dashboard` and receives **Tenant A's confidential cached response** directly from the proxy cache.

---

## 2. Why Conventional Scanners Fail (100% Blind Spot)

* **Stateless DAST (e.g., ZAP, Burp Scanner):**
  * Evaluates individual endpoints without coordinating temporal cache lifecycles.
  * Requests do not prime the proxy cache prior to cross-tenant probing.
* **BOLA / IDOR Scanners (e.g., Autorize, AuthMatrix):**
  * Replay tokens on individual endpoints while explicitly instructing proxies to bypass caching (`Cache-Control: no-cache`).
* **Empirical Reality:**
  * Under equal request budgets (198 requests), stateless testing achieves **0.0000 Recall** ($[0.00, 0.08]$ CI).
  * Proxy-mediated isolation failures are completely invisible to origin-only tools.

---

## 3. Threat Model & Adversary Capabilities

Three distinct adversarial roles modeled in TenantCache:

1. **Cross-Tenant Malicious Principal ($P_{\text{Ext}}$):**
   * Authenticated user in Tenant B; attempts to access Tenant A's private records.
2. **Intra-Tenant Privilege Escalator ($P_{\text{Priv}}$):**
   * Standard user in Tenant A; attempts to access Tenant A administrative resources.
3. **Revoked Principal ($P_{\text{Rev}}$):**
   * Formerly authorized user whose database access was revoked; attempts to retrieve cached representations before TTL expiration.

*Adversary Capabilities:* Arbitrary HTTP requests, client-supplied header forgery (`X-Tenant-ID`), and arbitrary temporal ordering.

---

## 4. Coupled State Machine Formulation

We model the system as two asynchronous, interacting state machines:

1. **Origin Authorization State ($\Sigma_{\text{auth}}$):**
   $$\sigma_{\text{auth}} = \langle \mathcal{U}, \mathcal{T}, \mathcal{R}, \mathcal{M}, \mathcal{L} \rangle$$
   *Tracks database users, tenants, resources, permissions, and authoritative ledger.*

2. **Proxy Cache State ($\Sigma_{\text{cache}}$):**
   $$\sigma_{\text{cache}} = \langle \mathcal{K}, \mathcal{V}, \tau \rangle$$
   *Maps synthetic keys $\kappa(req)$ to stored response representations and TTL expirations.*

A vulnerability occurs when a transition sequence leads to:
$$\mathcal{A}(P, R, Q) = \text{DENY} \quad \land \quad \mathcal{C}_R \cap \text{Tokens}(\text{Resp}(P, Q, S)) \neq \emptyset$$

---

## 5. System Architecture: TenantCache

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

---

## 6. Three-Phase Differential Sequence Orchestration

TenantCache coordinates state transitions across three distinct phases:

1. **Phase 1: Prime State ($S_{\text{cold}} \to S_{\text{warm}}$)**
   * Authorized Principal $P_1$ requests resource $R$.
   * Origin processes request, returns confidential payload with embedded canary $\mathcal{C}_R$.
   * Reverse proxy caches representation under synthetic key $\kappa(req)$.

2. **Phase 2: State Mutation (Optional)**
   * Administrative event revokes $P_1$'s permissions or alters resource ACL in $\Sigma_{\text{auth}}$.

3. **Phase 3: Probe & Invariant Verification ($S_{\text{warm}}$)**
   * Target Principal $P_2$ requests resource $R$.
   * Leakage detector verifies canary token $\mathcal{C}_R$ against independent oracle $\mathcal{A}(P_2, R)$.

---

## 7. Evaluated Reverse-Proxy Archetypes ($V_1$–$V_6$)

| Archetype | Vulnerability Mechanism | Failure Scenario |
| :--- | :--- | :--- |
| **$V_1$** | Missing Tenant Key | Cache key omits tenant ID; cross-tenant collision |
| **$V_2$** | Missing User Context | Key partitions by tenant, but omits user identity |
| **$V_3$** | Unvalidated Header Key | Key relies on untrusted client header (`X-Tenant-ID`) |
| **$V_4$** | Stale Revocation | Cached representation persists after origin revocation |
| **$V_5$** | Erroneous Public Policy | Shared caching applied across private endpoints |
| **$V_6$** | Path-Normalization Alias | Key uses unnormalized URI; `//` collapses to `/` |

---

## 8. Defensible Caching Archetypes ($S_1$ and $S_2$)

* **$S_1$: Strict Private Bypass**
  * Authenticated requests unconditionally bypass cache:
    ```nginx
    proxy_cache_bypass $http_authorization;
    proxy_no_cache     $http_authorization;
    ```
  * Zero leakage; simple; sacrifices caching benefits for authenticated users.

* **$S_2$: Identity-Keyed Caching with Subrequest Auth Verification**
  * Nginx executes `auth_request /api/v1/auth/verify` on every request.
  * Server-verified variables (`$auth_tenant|$auth_user`) partition the cache key.
  * Deleted/inaccessible resources map to HTTP 403 in subrequest, enforcing fail-closed edge abort.

---

## 9. Matched-Budget Evaluation (198 Requests per Tool)

Evaluated on **Dataset v1.1** (66 scenarios: 46 vulnerable, 20 balanced controls):

| Testing Tool | Budget | TP | FP | TN | FN | Precision (95% CI) | Recall (95% CI) | Specificity |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Baseline A (Stateless DAST)** | 198 | 0 | 0 | 20 | 46 | *N/A* | **0.0000** `[0.00, 0.08]` | **1.0000** |
| **Baseline B (Naive Diffing)** | 198 | 38 | 12 | 8 | 8 | 0.7600 `[0.63, 0.86]` | 0.8261 `[0.69, 0.91]` | 0.4000 |
| **TenantCache (Proposed)** | 198 | **46** | **0** | **20** | **0** | **1.0000** `[0.92, 1.00]` | **1.0000** `[0.92, 1.00]` | **1.0000** |

*Takeaway:* Under an identical request budget, TenantCache detects 100% of leaks with zero false positives.

---

## 10. Live Native Nginx (1.26.2 / 1.26.3) Integration

* All eight archetypes ($V_1$–$V_6$, $S_1$, $S_2$) were executed directly against live Nginx binaries.
* **Findings:**
  * $V_1$–$V_6$ reproduced in real Nginx with actual `X-Cache-Status: HIT` headers containing canary tokens.
  * $S_1$ confirmed `BYPASS` status with 0 leakage.
  * $S_2$ confirmed segregated `MISS`/`HIT` behavior under verified identity keying.
* Proves that simulation results translate with 100% fidelity to real-world edge proxies.

---

## 11. Component Ablation Study (V1 Archetype, v1.1 Corpus)

| Variant | Identity Aware | Cache Sequenced | Ground Oracle | Precision | Recall | F1 Score | FPR |
| :--- | :---: | :---: | :---: | :---: | :---: | :---: | :---: |
| **Full TenantCache** | **YES** | **YES** | **YES** | **1.0000** | **1.0000** | **1.0000** | **0.0000** |
| **Ablation 1: No Sequencing** | YES | **NO** | YES | *N/A* | **0.0000** | *N/A* | 0.0000 |
| **Ablation 2: No Oracle** | YES | YES | **NO** | 0.7600 | 0.8261 | 0.7917 | **0.6000** |
| **Control: Single Identity** | **NO** | YES | YES | *N/A* | **0.0000** | *N/A* | 0.0000 |

*Causal Insights:*
* Cache sequencing is **strictly necessary** to uncover leaks (Recall: $0.00 \to 1.00$).
* Ground-truth oracle is **strictly necessary** to prevent false alarms on public data ($FPR: 0.60 \to 0.00$).

---

## 12. Multi-Seed Deterministic Reproducibility

* Evaluated across 5 independent deterministic seeds (`[42, 43, 44, 45, 46]`):
  * **Mean Recall:** $1.0000$ ($\sigma = 0.0000$)
  * **Mean Precision:** $1.0000$ ($\sigma = 0.0000$)
  * **Mean Specificity:** $1.0000$ ($\sigma = 0.0000$)
  * **Mean Throughput:** $348.0 \text{ req/s}$ ($\sigma = 39.8$)
* Verifies complete test harness stability and zero algorithmic jitter.

---

## 13. Threats to Validity & Generalization Bounds

1. **Synthetic Corpus Calibration:**
   * Precision/recall evaluated on 66-scenario corpus (Dataset v1.1); provides deterministic benchmark bounds, not universal in-the-wild guarantees.
2. **Baseline Scoping:**
   * Baselines A and B represent custom reference implementations designed to isolate algorithmic properties, not commercial DAST suites.
3. **Statistical Confidence:**
   * All claims bound by 95% Wilson confidence intervals ($[0.92, 1.00]$ for $V_1$; $[0.68, 1.00]$ for $V_4$; $[0.84, 1.00]$ for benign controls).

---

## 14. Conclusion & Open-Source Artifacts

* **Summary:**
  * Discovered and formalized the edge-origin authorization disconnect.
  * Formulated coupled state machines ($\Sigma_{\text{auth}} \times \Sigma_{\text{cache}}$).
  * Implemented and validated TenantCache against native Nginx with 100% precision and recall.
* **Open-Source Availability:**
  * **Repository:** `https://github.com/ramKarthik57/tenantcache`
  * **Release:** `v1.1.0` (Canonical archive: `tenantcache.zip`)
  * **Checksum:** Verified via companion `tenantcache.zip.sha256`
