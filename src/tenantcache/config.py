"""Configuration and target URL validation safeguards."""

import re
from urllib.parse import urlparse
from pydantic import BaseModel, Field, field_validator


class TargetSecurityGuard:
    """Safeguards preventing unintentional scans against external or production targets."""

    ALLOWED_HOSTS = {
        "localhost",
        "127.0.0.1",
        "0.0.0.0",  # nosec: B104
        "testserver",
        "tenantcache_app",
        "tenantcache_proxy",
        "app",
        "proxy"
    }

    @classmethod
    def validate_target_url(cls, url: str) -> bool:
        if not url:
            return True
        parsed = urlparse(url)
        hostname = (parsed.hostname or "").lower()

        if hostname not in cls.ALLOWED_HOSTS:
            raise ValueError(
                f"Security Safeguard Violation: Target '{url}' with host '{hostname}' is not in the allowed "
                f"isolated laboratory domain list {cls.ALLOWED_HOSTS}. External testing is strictly prohibited."
            )
        return True


class TenantCacheConfig(BaseModel):
    target_base_url: str = Field(default="http://localhost:8080")
    cache_archetype: str = Field(default="V1_MISSING_TENANT_KEY")
    request_timeout: float = Field(default=5.0)
    seed: int = Field(default=42)

    @field_validator("target_base_url")
    def check_url(cls, v):
        TargetSecurityGuard.validate_target_url(v)
        return v
