# Research Questions and Experimental Hypotheses

## 1. Formal Research Questions

TenantCache is guided by four primary research questions designed to investigate the systemic causes, detection efficacy, and mitigation strategies for cache isolation failures in multi-tenant environments.

---

### RQ1: Detection Efficacy of Identity-Aware Differential Testing
> **RQ1:** Can identity-aware differential testing automatically identify cross-tenant and cross-user information leakage caused by HTTP reverse-proxy cache misconfiguration with high precision and recall?

- **Investigation Focus:** Assessing whether automated permutation of tenant identities ($T_A \to T_B$) and user roles ($U_{\text{admin}} \to U_{\text{std}}$) across warm and cold cache states can reliably uncover data leakage without generating excessive false alarms.
- **Metric of Success:** Empirical Recall $\ge 95\%$ on known vulnerable cache configurations, and Precision $\ge 95\%$ across mixed test suites containing both private and public resources.

---

### RQ2: Vulnerability Susceptibility of Cache Configurations
> **RQ2:** Which cache-key architectures and authorization-handling strategies exhibit the highest susceptibility to cross-tenant information disclosure?

- **Investigation Focus:** Comparing the vulnerability surface of:
  - Default URI-only cache keys (`$scheme$request_method$host$request_uri`).
  - Client-controlled header keys (`$http_x_tenant_id`).
  - Missing or misconfigured `Vary` headers (`Vary: Cookie` vs. missing).
  - RFC 9111 `Authorization` caching exceptions (`Cache-Control: public` on private endpoints).
  - Normalization discrepancies (case sensitivity, trailing slashes, query parameter ordering).
- **Metric of Success:** Systematic categorization of failure modes and empirical verification of attack surfaces across diverse configuration archetypes.

---

### RQ3: Stateful vs. Stateless Testing Coverage
> **RQ3:** Can stateful request sequences identify critical cache isolation failures—specifically authorization revocation lag—that conventional single-user endpoint testing and stateless DAST tools miss?

- **Investigation Focus:** Measuring the delta in vulnerability discovery between:
  - **Stateless Single-User Scanners:** Querying an endpoint with a revoked token directly.
  - **Stateful Differential Sequence:** Generating access, caching the response, revoking access in the origin database, and re-executing the request against the proxy cache.
- **Metric of Success:** Demonstration that stateful temporal testing detects $100\%$ of authorization revocation lag vulnerabilities where stateless baselines achieve $0\%$.

---

### RQ4: Precision and Invariant-Based False Positive Suppression
> **RQ4:** How effectively can security-invariant-based verification (using ground-truth access oracles and confidential canaries) distinguish actual confidentiality violations from harmless HTTP response variance and legitimate public resource caching?

- **Investigation Focus:** Comparing naive differential diffing (which flags response body/length/header differences) against TenantCache's Invariant & Canary Oracle.
- **Metric of Success:** Demonstrating that TenantCache achieves a False Positive Rate (FPR) of $0\%$ on public shared resources, whereas naive differential diffing yields an FPR approaching $100\%$.

---

## 2. Testable Scientific Hypotheses

| Hypothesis | Description | Falsification Condition |
|---|---|---|
| **$H_1$ (Sequence Superiority)** | Identity-aware request sequences across cache states detect isolation failures completely undetectable by isolated endpoint requests. | If conventional endpoint scans detect the same rate of cache-borne leaks as sequence-based scans, $H_1$ is rejected. |
| **$H_2$ (Key Vulnerability)** | Reverse proxy cache keys constructed from unvalidated client headers (`$http_x_tenant_id`) introduce cross-tenant poisoning and extraction risks. | If client-supplied tenant headers are shown to maintain complete isolation despite identity forgery, $H_2$ is rejected. |
| **$H_3$ (Revocation Blind Spot)** | Upstream HTTP caching without proactive surrogate-key invalidation renders instantaneous origin authorization revocation ineffective. | If revoked users are denied access by standard proxy caches without explicit cache purging, $H_3$ is rejected. |
| **$H_4$ (Invariant Specificity)** | Invariant-based canary verification produces strictly lower false-positive rates than response-difference diffing on public endpoints. | If the invariant oracle flags public content as unauthorized leaks at a rate comparable to naive diffing, $H_4$ is rejected. |
