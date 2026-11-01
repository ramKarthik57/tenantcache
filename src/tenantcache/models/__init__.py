"""Core data models for TenantCache framework."""

from __future__ import annotations
from enum import Enum
from typing import Dict, List, Optional, Any, Set
from pydantic import BaseModel, Field
import uuid


class Role(str, Enum):
    ADMIN = "admin"
    STANDARD_USER = "standard_user"
    GUEST = "guest"


class Visibility(str, Enum):
    PUBLIC = "public"
    TENANT_SHARED = "tenant_shared"
    USER_PRIVATE = "user_private"


class CacheStatus(str, Enum):
    HIT = "HIT"
    MISS = "MISS"
    BYPASS = "BYPASS"
    EXPIRED = "EXPIRED"
    UNKNOWN = "UNKNOWN"


class LeakageType(str, Enum):
    CROSS_TENANT_LEAK = "CROSS_TENANT_LEAK"
    CROSS_USER_LEAK = "CROSS_USER_LEAK"
    PRIVILEGE_ESCALATION_LEAK = "PRIVILEGE_ESCALATION_LEAK"
    STALE_REVOCATION_LEAK = "STALE_REVOCATION_LEAK"
    CACHE_KEY_SPOOFING_LEAK = "CACHE_KEY_SPOOFING_LEAK"
    NORMALIZATION_LEAK = "NORMALIZATION_LEAK"
    BENIGN_PUBLIC_CACHE_HIT = "BENIGN_PUBLIC_CACHE_HIT"


class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


class Principal(BaseModel):
    """Represents an active security identity executing requests."""
    user_id: str
    username: str
    tenant_id: str
    role: Role = Role.STANDARD_USER
    auth_token: Optional[str] = None
    headers: Dict[str, str] = Field(default_factory=dict)
    cookies: Dict[str, str] = Field(default_factory=dict)

    def identifier(self) -> str:
        return f"{self.tenant_id}::{self.username}[{self.role.value}]"


class Tenant(BaseModel):
    id: str
    name: str
    slug: str
    description: Optional[str] = None


class User(BaseModel):
    id: str
    tenant_id: str
    username: str
    role: Role
    email: str


class Resource(BaseModel):
    id: str
    tenant_id: str
    owner_id: str
    name: str
    endpoint_path: str
    visibility: Visibility
    canary_token: str
    payload: Dict[str, Any] = Field(default_factory=dict)
    allowed_user_ids: Set[str] = Field(default_factory=set)
    allowed_roles: Set[Role] = Field(default_factory=set)
    is_revoked_for: Set[str] = Field(default_factory=set)


class RequestSpec(BaseModel):
    method: str = "GET"
    url_path: str
    principal: Principal
    headers: Dict[str, str] = Field(default_factory=dict)
    query_params: Dict[str, str] = Field(default_factory=dict)
    body: Optional[Any] = None
    step_name: str = "request"


class ResponseRecord(BaseModel):
    status_code: int
    headers: Dict[str, str] = Field(default_factory=dict)
    body_text: str = ""
    cache_status: CacheStatus = CacheStatus.UNKNOWN
    latency_ms: float = 0.0
    matched_canaries: List[str] = Field(default_factory=list)


class Finding(BaseModel):
    id: str = Field(default_factory=lambda: f"FINDING-{uuid.uuid4().hex[:8].upper()}")
    leakage_type: LeakageType
    severity: Severity
    title: str
    description: str
    target_path: str
    resource_id: str
    resource_owner_tenant: str
    resource_owner_user: str
    victim_principal: str
    adversary_principal: str
    detected_canary: str
    response_cache_status: CacheStatus
    reproducibility: str = "100% Deterministic"
    evidence_headers: Dict[str, str] = Field(default_factory=dict)
    timestamp: str = ""


class BenchmarkResult(BaseModel):
    framework_name: str
    mode: str
    total_scenarios: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    accuracy: float
    total_requests: int
    duration_seconds: float
    requests_per_second: float
    findings_count: int
    findings: List[Finding] = Field(default_factory=list)
