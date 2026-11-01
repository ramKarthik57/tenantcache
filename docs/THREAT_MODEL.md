# Threat Model: Multi-Tenant Web Cache Isolation

## 1. System Overview and Asset Classification

In multi-tenant web applications, shared infrastructure components process, transmit, and cache data belonging to multiple logically segregated organizations (Tenants). 

### 1.1 Critical Assets
1. **Confidential Tenant Data:** Internal documents, financial records, customer PII, tenant-specific configuration, and operational logs.
2. **Confidential User Data:** Private user profiles, private drafts, authentication credentials, and user-level authorization tokens.
3. **Cache Storage Integrity & Confidentiality:** The state of the reverse proxy cache memory/disk, preventing cache poisoning and unauthorized cache hits.
4. **Access Control Decisions:** The temporal validity of authorization state changes (e.g., immediate revocation of compromised credentials or terminated employee access).

---

## 2. Threat Actors and Capabilities

We model three distinct threat actors operating within or outside the multi-tenant perimeter:

```
┌────────────────────────────────────────────────────────────────────────┐
│                        THREAT ACTOR SPECTRUM                           │
├────────────────────┬────────────────────┬──────────────────────────────┤
│ Actor A:           │ Actor B:           │ Actor C:                     │
│ Cross-Tenant       │ Intra-Tenant       │ Revoked / Stale              │
│ Malicious Principal│ Privilege Escalator│ Principal                    │
├────────────────────┼────────────────────┼──────────────────────────────┤
│ • Valid user in    │ • Valid standard   │ • Formerly authorized user   │
│   Tenant B         │   user in Tenant A │ • Access recently revoked    │
│ • No permissions   │ • No admin role in │   in origin database         │
│   in Tenant A      │   Tenant A         │ • Session tokens invalidated │
│ • Can send valid   │ • Attempts to read │ • Attempts to read cached    │
│   HTTP requests    │   admin resources  │   resources before TTL expiry│
└────────────────────┴────────────────────┴──────────────────────────────┘
```

### Actor Capabilities & Assumptions:
- **Network Position:** The adversary cannot intercept or alter TLS traffic between the user and the reverse proxy (no Man-in-the-Middle on transport).
- **Application Access:** The adversary holds valid credentials for their own tenant/account.
- **Header Manipulation:** The adversary can arbitrarily forge client-supplied HTTP request headers (e.g., `X-Tenant-ID`, `X-Forwarded-For`, `User-Agent`, `Cache-Control`).
- **Timing Control:** The adversary can execute requests in arbitrary temporal order (before, during, or after a victim user's interaction).

---

## 3. Trust Boundaries and Attack Surfaces

```
                     [ Adversary / Client ]
                               │
                (Boundary 1: Untrusted Network)
                               ▼
               ┌───────────────────────────────┐
               │    Reverse Proxy / Cache      │
               │   (Nginx / CDN / Edge Proxy)  │
               └───────────────┬───────────────┘
                               │
               (Boundary 2: Proxy-to-Origin)
                               ▼
               ┌───────────────────────────────┐
               │   Application Backend API     │
               │         (FastAPI)             │
               └───────────────┬───────────────┘
                               │
               (Boundary 3: Storage Isolation)
                               ▼
               ┌───────────────────────────────┐
               │      Multi-Tenant Database    │
               │     (Row-Level Isolation)     │
               └───────────────────────────────┘
```

### Attack Surfaces:
1. **Cache Key Collision Surface:** Reverse proxy constructs cache keys without partitioning by validated tenant/user identity. An adversary requesting a generic endpoint path (`/api/v1/tenant/dashboard` or `/api/v1/invoices/latest`) receives a cached response previously fetched by a victim in another tenant.
2. **Client Header Spoofing Surface:** Reverse proxy includes `$http_x_tenant_id` in the cache key. An adversary sets `X-Tenant-ID: victim_tenant` while authenticated as an attacker. If the backend fails to validate the header against the session token or the cache key gets poisoned, cross-tenant pollution occurs.
3. **Revocation Lag Surface:** When permissions are revoked in the database (Boundary 3), the application backend (Boundary 2) rejects subsequent direct requests. However, the reverse proxy (Boundary 1) remains unaware of the revocation and serves cached $200 \text{ OK}$ responses until TTL expiration.
4. **Cache-Control Misconfiguration Surface:** Origin backend omits `Cache-Control: private, no-store` or erroneously sets `Cache-Control: public` on sensitive endpoints, explicitly instructing intermediate proxies to store confidential payloads.

---

## 4. Threat Scenarios and Vulnerability Classes

| Vulnerability ID | Vulnerability Class | Mechanism | Impact |
|---|---|---|---|
| **V1** | Missing Tenant Context in Cache Key | Proxy caches URI without tenant scoping. Tenant B queries the same path as Tenant A and receives Tenant A's private data. | Critical: Unauthenticated cross-tenant data breach. |
| **V2** | Missing User Authorization Context | Private user profile cached without user-id or session binding in cache key. Standard user reads Admin's private profile. | High: Intra-tenant privilege boundary collapse. |
| **V3** | Unvalidated Header in Cache Key | Proxy relies on client-supplied `X-Tenant-ID` for cache key partitioning without server authentication check. | High: Cache key spoofing, injection, and deception. |
| **V4** | Stale Authorization after Revocation | Revoked user queries proxy cache. Unexpired cached 200 response returned despite origin 403. | High: Broken revocation enforcement and temporal leakage. |
| **V5** | Erroneous Public Cache Policy | Backend emits `Cache-Control: public, max-age=300` on confidential invoice endpoint. Shared proxy caches it globally. | Critical: Wide-scale confidential document disclosure. |
| **V6** | Normalization & Suffix Discrepancy | Path normalization discrepancy (`/document/1` vs `/document/1/` or query param reordering). | Medium: Cache partitioning bypass via unnormalized keys. |

---

## 5. Security Mitigations and Defense-in-Depth

1. **Default Deny Shared Caching:** All authenticated endpoints MUST return `Cache-Control: no-store, private` unless public caching is explicitly verified and required.
2. **Server-Validated Surrogate Keys:** If caching of authenticated content is strictly necessary, cache keys MUST be derived exclusively from cryptographic tokens (e.g., hash of verified tenant ID from signed JWT) and MUST use `Vary: Authorization, Cookie`.
3. **Surrogate Key Invalidation (Purge on Revocation):** Dynamic permission changes (role changes, tenant unlinking) MUST emit immediate cache-purge/ban events targeting the principal's surrogate keys.
