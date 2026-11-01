# Real Nginx Empirical Validation Report

## 1. Executive Summary

To address the empirical necessity of validating cache isolation failures against production-grade reverse-proxy software rather than solely relying on an in-process simulator, **TenantCache was directly executed and verified against real, native Nginx (version 1.26.2)** running on `localhost:8080` reverse-proxying to the live FastAPI backend on `127.0.0.1:8000`.

The automated integration test (`tests/integration/test_real_nginx.py`) confirms that the cross-tenant cache isolation vulnerability ($V_1$) reproduces **identically on actual Nginx binary execution**:
1. Tenant A (Alice, Acme Corp) requests her confidential dashboard (`/api/v1/tenant/dashboard`). Real Nginx forwards to origin, caches the response, and returns `X-Cache-Status: MISS`.
2. Tenant B (Bob, Beta Dynamics) subsequently queries the identical endpoint (`/api/v1/tenant/dashboard`).
3. **Real Nginx intercepts the request, returns `X-Cache-Status: HIT`, and serves Tenant A's private dashboard containing the confidential canary token (`TC_CANARY_...`) directly to Tenant B.**
4. The TenantCache Differential Runner and Leakage Detector intercept this response, verify against the independent Ground-Truth Security Oracle ($\mathcal{A}(P_{\text{Bob}}, R_{\text{Acme}}) = \text{DENY}$), and confirm a **`CROSS_TENANT_LEAK`** with `100% Deterministic` reproducibility.

---

## 2. Real Nginx Configuration Inspected

The exact Nginx configuration tested (`lab/nginx/windows/v1_missing_tenant_key.conf`):

```nginx
worker_processes  1;

events {
    worker_connections  1024;
}

http {
    default_type  application/octet-stream;
    sendfile        on;

    proxy_cache_path temp/cache_v1 levels=1:2 keys_zone=TENANT_CACHE_V1:10m max_size=100m inactive=60m use_temp_path=off;

    server {
        listen       8080;
        server_name  localhost;

        location / {
            proxy_pass http://127.0.0.1:8000;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;

            # VULNERABILITY V1: Missing tenant or user identifier in proxy_cache_key
            proxy_cache TENANT_CACHE_V1;
            proxy_cache_key "$scheme$request_method$host$request_uri";
            proxy_cache_valid 200 10m;
            proxy_ignore_headers Cache-Control Expires;

            add_header X-Cache-Status $upstream_cache_status always;
            add_header X-TenantCache-Config "REAL_NGINX_V1_MISSING_TENANT_KEY" always;
        }
    }
}
```

---

## 3. Real Nginx Live HTTP Verification Trace

Captured live from `tests/integration/test_real_nginx.py`:

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
{"tenant":"tenant_acme","revenue_target":"$42M","secret_kpi":"TC_CANARY_1803654870C3_33CC14EF"}

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
{"tenant":"tenant_acme","revenue_target":"$42M","secret_kpi":"TC_CANARY_1803654870C3_33CC14EF"}
```

### Invariant Verification Result:
- **Principal:** `tenant_beta::bob[admin]`
- **Resource Owner:** `tenant_acme`
- **Detected Canary:** `TC_CANARY_1803654870C3_33CC14EF`
- **Oracle Decision:** `DENY`
- **Result:** **CONFIRMED CRITICAL CROSS-TENANT DATA BREACH (Real Nginx HIT)**
