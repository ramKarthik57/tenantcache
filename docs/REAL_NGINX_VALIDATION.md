# Real Nginx Empirical Validation Report: Live Native Execution

## 1. Executive Summary

To address the empirical necessity of validating cache isolation failures against production-grade reverse-proxy software rather than solely relying on an in-process simulator, **TenantCache was directly executed and verified against native Nginx (version 1.26.2)** running on Windows `localhost:8080` reverse-proxying live traffic to the FastAPI backend on `127.0.0.1:8000`.

The automated integration tests (`tests/integration/test_real_nginx.py`) confirm:
1. **Vulnerable Archetype $V_1$ (Missing Tenant Key):** Real Nginx serves cached responses across tenants (`X-Cache-Status: HIT`), leaking confidential canary tokens from Alice (Acme) to Bob (Beta).
2. **Secure Control Archetype $S_1$ (Strict Private Bypass):** Real Nginx with `proxy_cache_bypass $http_authorization` unconditionally bypasses cache (`X-Cache-Status: BYPASS`) on authenticated requests, preserving tenant isolation with zero leakage.

---

## 2. Real Nginx Live HTTP Verification Traces

### 2.1 Archetype V1: Vulnerable Cross-Tenant Cache Collision
Captured live from `tests/integration/test_real_nginx.py::test_real_nginx_v1_live_cross_tenant_leak`:

```http
Request 1 (Alice - Tenant Acme):
GET /api/v1/tenant/dashboard HTTP/1.1
Host: 127.0.0.1:8080
Authorization: Bearer TOKEN_tenant_acme_ALICE_SECURE_SIG
X-Tenant-ID: tenant_acme

Response 1:
HTTP/1.1 200 OK
Server: nginx/1.26.2
Content-Type: application/json
X-Cache-Status: MISS
X-TenantCache-Config: REAL_NGINX_V1_MISSING_TENANT_KEY
{"tenant":"tenant_acme","kpi_metric":"TC_CANARY_1803654870C3_33CC14EF"}

--------------------------------------------------------------------------------

Request 2 (Bob - Tenant Beta):
GET /api/v1/tenant/dashboard HTTP/1.1
Host: 127.0.0.1:8080
Authorization: Bearer TOKEN_tenant_beta_BOB_SECURE_SIG
X-Tenant-ID: tenant_beta

Response 2:
HTTP/1.1 200 OK
Server: nginx/1.26.2
Content-Type: application/json
X-Cache-Status: HIT
X-TenantCache-Config: REAL_NGINX_V1_MISSING_TENANT_KEY
{"tenant":"tenant_acme","kpi_metric":"TC_CANARY_1803654870C3_33CC14EF"}
```

**Result:** Confirmed critical cross-tenant data breach on actual Nginx binary execution ($V_1$).

---

### 2.2 Archetype S1: Secure Cache Bypass for Authenticated Sessions
Captured live from `tests/integration/test_real_nginx.py::test_real_nginx_s1_strict_private_bypass`:

```http
Request 1 (Alice - Tenant Acme):
GET /api/v1/tenant/dashboard HTTP/1.1
Host: 127.0.0.1:8080
Authorization: Bearer TOKEN_tenant_acme_ALICE_SECURE_SIG
X-Tenant-ID: tenant_acme

Response 1:
HTTP/1.1 200 OK
Server: nginx/1.26.2
X-Cache-Status: BYPASS
X-TenantCache-Config: REAL_NGINX_SECURE_S1
{"tenant":"tenant_acme","kpi_metric":"TC_CANARY_1803654870C3_33CC14EF"}

--------------------------------------------------------------------------------

Request 2 (Bob - Tenant Beta):
GET /api/v1/tenant/dashboard HTTP/1.1
Host: 127.0.0.1:8080
Authorization: Bearer TOKEN_tenant_beta_BOB_SECURE_SIG
X-Tenant-ID: tenant_beta

Response 2:
HTTP/1.1 200 OK
Server: nginx/1.26.2
X-Cache-Status: BYPASS
X-TenantCache-Config: REAL_NGINX_SECURE_S1
{"tenant":"tenant_beta","kpi_metric":"TC_CANARY_3F932F1FD8E4_0F681C3D"}
```

**Result:** Zero leakage; Real Nginx bypasses cache on authenticated requests, preserving tenant isolation ($S_1$).
