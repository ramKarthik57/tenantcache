# Novelty Assessment: Tripartite Contribution Decomposition

## 1. Objective Novelty Framework

To establish a defensible, peer-review-grade research contribution, this document explicitly decomposes TenantCache into three distinct categories:
1. **Useful Integration of Existing Techniques** (Engineering Foundation)
2. **Genuinely New Testing Methodology** (Scientific Novelty)
3. **Experimentally Demonstrated Improvements** (Empirical Evidence)

---

## 2. Tripartite Contribution Decomposition

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                    TENANTCACHE CONTRIBUTION TAXONOMY                        │
├──────────────────────────┬──────────────────────────┬───────────────────────┤
│ 1. Engineering           │ 2. Novel Testing         │ 3. Experimentally     │
│    Integration           │    Methodology           │    Proven Improvement │
├──────────────────────────┼──────────────────────────┼───────────────────────┤
│ • RFC 9111 proxy caching │ • Dual state-machine     │ • 0% False Positive   │
│   semantics (Nginx)      │   synchronization        │   Rate on public      │
│ • Synthetic canaries     │   (Origin Auth vs.       │   shared content      │
│   for taint tracking     │    Proxy Cache State)    │ • Elimination of the  │
│ • Client header mutation │ • Decoupled ground-truth │   stateless DAST      │
│   (X-Tenant-ID fuzzing)  │   invariant A(P, R, Q)   │   blind spot          │
│ • Asynchronous HTTP      │ • Identity-divergence    │   (Recall: 0% -> 91%) │
│   differential runner    │   cache-key mutation     │ • 100% detection of   │
│ • Property testing       │ • Stateful revocation    │   temporal revocation │
│   harness (Hypothesis)   │   lag verification       │   lag (vs 0% in DAST) │
└──────────────────────────┴──────────────────────────┴───────────────────────┘
```

---

### Category 1: Useful Integration of Existing Security-Testing Techniques
The following components represent sound engineering and adaptation of established literature:
- **Taint / Canary Tracking:** Injecting unique strings (`TC_CANARY_<uuid>_<crc>`) into payloads to trace data leakage builds upon standard dynamic taint analysis and web honeypot techniques.
- **Differential HTTP Execution:** Comparing responses between pairs of users ($P_A \leftrightarrow P_B$) adapts differential testing principles formalized by McKeeman (2000) and NEZHA (Petsios et al., 2017).
- **Header Mutation:** Fuzzing unkeyed or untrusted client headers (e.g., `X-Tenant-ID`) incorporates concepts popularized by Kettle (2018, 2020) in web cache poisoning research.
- **RFC 9111 Protocol Compliance:** Replicating standard HTTP caching directives (`Cache-Control`, `Vary`, `s-maxage`) relies directly on IETF standards.

---

### Category 2: Genuinely New Testing Methodology
TenantCache introduces specific testing methodologies that do not exist in prior security scanners:
1. **Dual State-Machine Synchronization (Origin Auth $\times$ Proxy Cache State):**
   Existing authorization scanners (e.g., Autorize, AuthMatrix) model only *stateless* endpoint permissions, explicitly bypassing caching proxies. Existing cache scanners (e.g., Param Miner) model only *stateless* proxy reflection. TenantCache is the first methodology to formally couple two independent, asynchronous state machines:
   $$\mathcal{S}_{\text{system}} = \mathcal{S}_{\text{origin\_auth}} \times \mathcal{S}_{\text{proxy\_cache}}$$
   Systematically executing transitions such as:
   $$\text{Authorized}(P_1) \to \text{WarmCache}(P_1) \to \text{RevokeDB}(P_1) \to \text{ProbeCache}(P_1)$$
2. **Decoupled Ground-Truth Authorization Oracle:**
   Traditional scanners infer access denial from HTTP status codes ($200 \text{ vs. } 403$). When a vulnerable cache proxy serves a cached $200 \text{ OK}$ to an unauthorized user, status-based oracles fail. TenantCache evaluates an independent policy oracle $\mathcal{A}(P, R, Q) \in \{\text{ALLOW}, \text{DENY}\}$ that evaluates ground-truth data ownership regardless of HTTP response codes.
3. **Identity-Divergence Cache-Key Mutation:**
   A systematic testing methodology uncovering discrepancies where reverse proxies derive cache keys from untrusted client headers (`$http_x_tenant_id`) while the origin application validates tenant context via signed cryptographic tokens (JWTs), enabling cross-tenant cache injection and unauthorized extraction.

---

### Category 3: Experimentally Demonstrated Improvements over Existing Techniques
Our empirical evaluation on the 54-scenario benchmark corpus confirms measurable improvements over existing techniques:

1. **Elimination of the Stateless Scanner Blind Spot:**
   - **Existing Approach (Baseline A):** Achieved **0.0000 Recall** ($0/44$ true vulnerabilities detected) because stateless endpoint testing evaluates cold caches in isolation.
   - **TenantCache:** Achieved **0.9091 Recall** (`95% CI: [0.79, 0.96]`), successfully detecting multi-tenant cache collisions across all tested endpoints.
2. **Detection of Authorization Revocation Lag:**
   - **Existing Approach (Baseline B):** Simple token swapping missed 100% of revocation lag vulnerabilities because it does not model temporal state changes in the origin database.
   - **TenantCache:** Detects unexpired cached $200 \text{ OK}$ responses following database revocation, uncovering persistent authorization exposure.
3. **False-Positive Suppression on Legitimate Public/Shared Content:**
   - **Naive Diffing Tools:** Flag response body differences, timestamps, and shared public content as vulnerabilities, yielding high false-positive rates.
   - **TenantCache:** Recorded a **0.0% False Positive Rate** across all public and legitimately shared scenarios ($FP = 0$), mathematically distinguishing permitted public caching from unauthorized confidential data leaks.
