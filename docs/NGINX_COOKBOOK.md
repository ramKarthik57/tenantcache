# Nginx Multi-Tenant Cache Hardening Cookbook

This guide provides concrete, production-ready reverse-proxy configurations to enforce strict HTTP cache isolation in multi-tenant Software-as-a-Service (SaaS) environments.

---

## 1. The Core Threat: Why Default Caching Breaks Multi-Tenancy

In standard Nginx configurations, the `proxy_cache_key` directive defaults to:

```nginx
proxy_cache_key $scheme$proxy_host$request_uri;
```

In a multi-tenant application where multiple corporate entities share uniform REST API routes (e.g., `/api/v1/tenant/dashboard`, `/api/v1/invoices`):
1. **Tenant A** requests `/api/v1/tenant/dashboard` with authorization token $T_A$.
2. The origin application returns Tenant A's private dashboard with HTTP `200 OK`.
3. Nginx computes `CacheKey = hash("httporigin/api/v1/tenant/dashboard")` and caches the representation.
4. **Tenant B** requests `/api/v1/tenant/dashboard` with authorization token $T_B$.
5. Nginx matches the identical CacheKey and **delivers Tenant A's private data to Tenant B directly from cache**, without ever querying the application server.

---

## 2. Secure Defense Strategy 1 ($S_1$): Strict Private Bypass

### Best For
Applications where latency constraints permit authenticated requests to always consult the origin server, while caching is reserved strictly for public, anonymous assets.

### Architecture
Every request containing an `Authorization` header, a session cookie, or an API key unconditionally bypasses and refuses to store cache representations.

```nginx
# /etc/nginx/conf.d/s1_strict_private.conf

proxy_cache_path /var/cache/nginx/s1 levels=1:2 keys_zone=s1_cache:10m max_size=1g inactive=60m;

server {
    listen 80;
    server_name api.saas-platform.com;

    # Track presence of authorization credentials
    set $bypass_cache 0;
    if ($http_authorization != "") {
        set $bypass_cache 1;
    }
    if ($http_cookie ~* "session_token|auth_token") {
        set $bypass_cache 1;
    }

    location / {
        proxy_pass http://origin_backend:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;

        # Shared caching rules
        proxy_cache s1_cache;
        proxy_cache_key "$scheme$request_method$host$request_uri";

        # Enforce unconditional bypass on authentication
        proxy_cache_bypass $bypass_cache;
        proxy_no_cache     $bypass_cache;

        # Honor origin Cache-Control directives
        proxy_ignore_headers Expires;
        
        # Diagnostic response header for auditing
        add_header X-Cache-Status $upstream_cache_status always;
    }
}
```

---

## 3. Secure Defense Strategy 2 ($S_2$): Identity-Keyed Caching with Subrequest Auth Verification

### Best For
High-throughput SaaS applications that require low-latency response delivery for authenticated endpoints, but must guarantee **zero cross-tenant leakage**, **zero privilege escalation**, and **instant permission revocation**.

### Architecture
1. Nginx intercepts the incoming request.
2. An internal subrequest (`auth_request /api/v1/auth/verify`) evaluates token validity, tenant membership, and resource ACLs.
3. The auth endpoint extracts server-verified headers (`X-Auth-Tenant-ID`, `X-Auth-User-ID`, `X-Auth-Scope`).
4. Nginx injects verified variables into the cache key:
   $$\text{CacheKey} = \text{hash}(\text{Method}, \text{Host}, \text{URI}, \text{ServerVerifiedTenant}, \text{ServerVerifiedUser})$$
5. Untrusted client-supplied identity headers (e.g. `X-Tenant-ID`) are explicitly stripped.
6. Inaccessible or deleted resources are deliberately mapped to HTTP `403 Forbidden` in the subrequest to guarantee immediate fail-closed abort.

```nginx
# /etc/nginx/conf.d/s2_identity_keyed.conf

proxy_cache_path /var/cache/nginx/s2 levels=1:2 keys_zone=s2_cache:20m max_size=5g inactive=120m;

server {
    listen 80;
    server_name api.saas-platform.com;

    # Internal authorization subrequest location
    location = /_auth_verify {
        internal;
        proxy_pass http://origin_backend:8000/api/v1/auth/verify;
        proxy_pass_request_body off;
        proxy_set_header Content-Length "";
        proxy_set_header X-Original-URI $request_uri;
        proxy_set_header X-Original-Method $request_method;
        proxy_set_header Authorization $http_authorization;
    }

    location / {
        # 1. Enforce per-request authorization verification
        auth_request /_auth_verify;

        # 2. Capture server-verified identity variables from subrequest
        auth_request_set $auth_tenant $upstream_http_x_auth_tenant_id;
        auth_request_set $auth_user   $upstream_http_x_auth_user_id;

        # 3. Strip untrusted client-supplied headers
        proxy_set_header X-Tenant-ID "";
        proxy_set_header X-User-ID "";

        # 4. Proxy to origin backend
        proxy_pass http://origin_backend:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Tenant-ID $auth_tenant;
        proxy_set_header X-User-ID $auth_user;

        # 5. Partition cache key by verified tenant and user identity
        proxy_cache s2_cache;
        proxy_cache_key "$scheme$request_method$host$request_uri|$auth_tenant|$auth_user";

        # 6. Cache validation directives
        proxy_cache_valid 200 5m;
        proxy_cache_valid 403 404 0s;  # Never cache error states
        proxy_cache_use_stale error timeout updating;
        proxy_cache_lock on;           # Thundering herd protection

        # Diagnostic response header
        add_header X-Cache-Status $upstream_cache_status always;
        add_header X-Cache-Partition "$auth_tenant:$auth_user" always;
    }
}
```

---

## 4. Production Checklist & Pitfalls to Avoid

| Anti-Pattern | Description | Vulnerability Archetype | Recommended Fix |
| :--- | :--- | :---: | :--- |
| **Omitting Tenant in Key** | Using generic `$request_uri` without tenant partition | $V_1$ | Use $S_1$ bypass or partition by verified tenant ID |
| **Omitting User in Key** | Partitioning only by tenant on private user endpoints | $V_2$ | Append `$auth_user` to the cache key |
| **Trusting Client Headers** | Using `$http_x_tenant_id` directly in `proxy_cache_key` | $V_3$ | Strip incoming `$http_x_tenant_id` and rely only on server-verified tokens |
| **Stale Revocation Window** | Caching private responses for hours without invalidation | $V_4$ | Enforce per-request `auth_request` check or active purge webhooks |
| **Overriding Private Headers** | `proxy_ignore_headers Cache-Control` caching private pages | $V_5$ | Allow origin `Cache-Control: private` to dictate cacheability |
| **Unnormalized Paths** | Using `$uri` instead of `$request_uri` in cache key | $V_6$ | Use `$request_uri` to avoid directory delimiter collapsing |
