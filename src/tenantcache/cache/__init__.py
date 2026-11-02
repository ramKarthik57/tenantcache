"""Cache State Controller and High-Fidelity Reverse Proxy Cache Simulator."""

import time
import hashlib
from typing import Dict, Optional, Tuple, Any
from tenantcache.models import CacheStatus, RequestSpec, ResponseRecord


class ProxyCacheEntry:
    def __init__(self, key: str, status_code: int, headers: Dict[str, str], body_text: str, ttl_seconds: float = 600.0):
        self.key = key
        self.status_code = status_code
        self.headers = headers.copy()
        self.body_text = body_text
        self.created_at = time.time()
        self.ttl_seconds = ttl_seconds

    def is_expired(self) -> bool:
        return (time.time() - self.created_at) > self.ttl_seconds


class ProxyCacheSimulator:
    """Simulates Nginx proxy_cache behavior with configurable key algorithms and policies."""

    def __init__(self, config_archetype: str = "V1_MISSING_TENANT_KEY"):
        self.config_archetype = config_archetype
        self.cache_storage: Dict[str, ProxyCacheEntry] = {}
        self.hit_count = 0
        self.miss_count = 0
        self.bypass_count = 0

    def compute_cache_key(self, request: RequestSpec, host: str = "localhost", scheme: str = "http") -> str:
        """Computes the proxy cache key based on configuration archetype."""
        method = request.method.upper()
        uri = request.url_path
        auth_header = request.headers.get("Authorization", "")
        tenant_header = request.headers.get("X-Tenant-ID", "")

        if self.config_archetype == "V1_MISSING_TENANT_KEY":
            # Vulnerability 1: Missing tenant or user context in cache key
            raw_key = f"{scheme}{method}{host}{uri}"

        elif self.config_archetype == "V2_MISSING_USER_AUTH":
            # Vulnerability 2: Key partitions by tenant header, but omits user identity
            raw_key = f"{scheme}{method}{host}{uri}{tenant_header}"

        elif self.config_archetype == "V3_UNVALIDATED_HEADER":
            # Vulnerability 3: Key relies on untrusted client header
            raw_key = f"{scheme}{method}{host}{uri}|{tenant_header}"

        elif self.config_archetype == "V4_STALE_REVOCATION":
            # Vulnerability 4: Key includes auth token, but prolonged TTL with no invalidation
            raw_key = f"{scheme}{method}{host}{uri}|{auth_header}"

        elif self.config_archetype == "V5_ERRONEOUS_PUBLIC":
            # Vulnerability 5: Shared caching forced across all clients
            raw_key = f"{scheme}{method}{host}{uri}"

        elif self.config_archetype == "V6_NORMALIZATION":
            # Vulnerability 6: Path-normalization aliasing (e.g. duplicate slashes collapsed)
            import re
            normalized_path = re.sub(r"/+", "/", uri).rstrip("/").lower()
            raw_key = f"{scheme}{method}{host}{normalized_path}"

        elif self.config_archetype == "SECURE_S1_STRICT_PRIVATE":
            # Secure 1: Strict bypass when authenticated
            raw_key = f"{scheme}{method}{host}{uri}"

        elif self.config_archetype == "SECURE_S2_IDENTITY_KEYED":
            # Secure 2: Server-validated identity keying from auth_request subrequest variables ($auth_tenant, $auth_user)
            # Untrusted client-supplied identity headers (X-Tenant-ID, X-User-ID) are stripped completely
            tenant_id = request.principal.tenant_id
            user_id = request.principal.user_id
            raw_key = f"{scheme}{method}{host}{uri}|{tenant_id}|{user_id}"

        else:
            raw_key = f"{scheme}{method}{host}{uri}"

        return hashlib.sha256(raw_key.encode("utf-8")).hexdigest()

    def should_bypass(self, request: RequestSpec) -> bool:
        """Evaluates proxy_cache_bypass directives."""
        if self.config_archetype == "SECURE_S1_STRICT_PRIVATE":
            # In S1, any request with Authorization or session cookie bypasses cache
            if "Authorization" in request.headers or "session_id" in request.principal.cookies:
                return True
        return False

    def lookup(self, request: RequestSpec) -> Optional[ResponseRecord]:
        """Performs cache lookup."""
        if self.should_bypass(request):
            self.bypass_count += 1
            return None

        cache_key = self.compute_cache_key(request)
        entry = self.cache_storage.get(cache_key)

        if not entry:
            self.miss_count += 1
            return None

        if entry.is_expired():
            self.miss_count += 1
            del self.cache_storage[cache_key]
            return None

        self.hit_count += 1
        headers = entry.headers.copy()
        headers["X-Cache-Status"] = "HIT"
        headers["X-TenantCache-Config"] = self.config_archetype
        headers["X-Cache-Key"] = cache_key[:12]

        return ResponseRecord(
            status_code=entry.status_code,
            headers=headers,
            body_text=entry.body_text,
            cache_status=CacheStatus.HIT
        )

    def store(self, request: RequestSpec, status_code: int, headers: Dict[str, str], body_text: str):
        """Stores response in cache if eligible."""
        if self.should_bypass(request):
            return

        # Do not cache error responses unless configured
        if status_code != 200:
            return

        cache_control = headers.get("Cache-Control", "").lower()
        if self.config_archetype == "SECURE_S1_STRICT_PRIVATE":
            if "no-store" in cache_control or "private" in cache_control:
                return

        # For V4, prolonged TTL
        ttl = 1800.0 if self.config_archetype == "V4_STALE_REVOCATION" else 600.0

        cache_key = self.compute_cache_key(request)
        entry = ProxyCacheEntry(
            key=cache_key,
            status_code=status_code,
            headers=headers,
            body_text=body_text,
            ttl_seconds=ttl
        )
        self.cache_storage[cache_key] = entry

    def purge_all(self):
        """Purges all entries from cache (cold reset)."""
        self.cache_storage.clear()

    def purge_key_pattern(self, pattern: str):
        """Purges keys matching pattern."""
        to_del = [k for k in self.cache_storage if pattern in k]
        for k in to_del:
            del self.cache_storage[k]
