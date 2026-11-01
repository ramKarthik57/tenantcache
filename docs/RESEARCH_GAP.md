# Research Gap: The Blind Spot at the Intersection of Multi-Tenancy and HTTP Caching

## 1. The Core Problem Statement

Modern web applications increasingly adopt multi-tenant architectures where shared computational, caching, and storage resources serve multiple distinct corporate or organizational entities (tenants). Simultaneously, high-throughput systems deploy HTTP reverse-proxy caching layers (e.g., Nginx, Varnish, Cloudflare, Fastly, AWS CloudFront) to reduce database load and minimize response latencies.

However, an acute, systemic architectural friction exists between **multi-tenancy** and **shared HTTP caching**:

1. **Authorization Logic is Origin-Centric:** Access control policies (RBAC, ABAC, multi-tenant row-level isolation) reside within application code and database queries.
2. **Caching Logic is Edge/Proxy-Centric:** Reverse proxies determine whether to serve a cached response using a synthetic **Cache Key**, conventionally constructed from a minimal subset of the request:
   $$\text{CacheKey} = \text{hash}(\text{Method}, \text{Scheme}, \text{Host}, \text{URI})$$
3. **The Semantic Disconnect:** If an authenticated application endpoint returns confidential tenant data without explicitly instructing the reverse proxy to include the tenant/user identity in the cache key (or to disallow shared caching entirely via `Cache-Control: private, no-store`), the proxy will treat requests from different tenants with identical URI paths as identical. Consequently, **Tenant B receives Tenant A's confidential response directly from the proxy cache without the application server ever being consulted**.

---

## 2. Identified Scientific and Engineering Gaps

### Gap 1: Absence of Cache-State Awareness in Authorization Testing Tools
Conventional authorization vulnerability scanners (e.g., Autorize, SecLists, OWASP BOLA testing frameworks) evaluate endpoints statelessly. They execute requests directly against origin servers (frequently utilizing cache-busting headers to bypass intermediate infrastructure). As a result:
- They confirm that the origin application correctly denies unauthorized access when queried directly.
- **They fail to identify when a cached response from an authorized session bypasses origin access control for subsequent unauthorized principals.**

### Gap 2: Blindness to Stateful Temporal Transitions (Revocation Lag)
Authorization is not static; permissions are granted, modified, and revoked dynamically. When Tenant A revokes User 1's access to a private document:
- The origin database immediately reflects the revoked permission ($403 \text{ Forbidden}$).
- If a reverse proxy maintains an unexpired cached representation ($200 \text{ OK}$) without dynamic invalidation hooks (e.g., cache purging or `must-revalidate`), the revoked user continues to access the document until the TTL expires.
- **Existing security testing frameworks possess no methodology for verifying authorization revocation in the presence of caching proxies.**

### Gap 3: False-Positive Vulnerability in Naive Differential Testing
Simple differential testing (comparing byte-for-byte responses or HTTP status codes between two users) suffers from severe false-positive rates when applied to web caches:
- Dynamic timestamps, CSRF tokens, nonces, and cache-status headers (`X-Cache: HIT` vs. `MISS`) produce response differences even when no leakage occurs.
- Conversely, public resources (e.g., standard documentation, legal agreements, static terms of service) are *supposed* to be cached and shared across tenants; a naive scanner would flag this legitimate sharing as a critical cross-tenant data breach.
- **There is a lack of formal security invariants and canary-based ground-truth verification that can definitively distinguish authentic confidentiality violations from benign caching of public assets.**

### Gap 4: Semantic Ambiguity in Client-Supplied Tenant Headers
Many multi-tenant architectures pass tenant context via custom HTTP headers (such as `X-Tenant-ID` or `X-Organization-Slug`). When developers configure proxies to include `$http_x_tenant_id` in the Nginx `proxy_cache_key`, they inadvertently introduce a critical vulnerability:
- A malicious client in Tenant B can forge `X-Tenant-ID: tenant-a`. If the backend authenticates the user via JWT session cookies but the cache key uses the client-supplied header, cache poisoning and cross-tenant pollution occur.
- **Current testing tools do not systematically test the divergence between client-supplied headers and server-validated session identities.**

---

## 3. The TenantCache Solution

TenantCache addresses these gaps directly by formulating:
1. An **Identity-Aware Request Generator** that models multi-tier tenant, user, and role contexts.
2. A **Cache-State Controller** capable of deterministically managing proxy cache lifecycles ($S_{\text{cold}}, S_{\text{warm}}, S_{\text{purged}}, S_{\text{expired}}$).
3. An **Independent Security Oracle** defining ground-truth access permissions $A(P, R, Q) \in \{\text{ALLOW}, \text{DENY}\}$.
4. A **Canary-Based Invariant Verifier** that tracks unique synthetic secrets across resource payloads, mathematically proving cross-tenant and cross-user data leakage with zero false positives on public content.
