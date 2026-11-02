"""Unit tests for TenantCache core data models."""

import pytest
from tenantcache.models import Principal, Resource, Role, Visibility, CacheStatus, Finding, LeakageType, Severity


def test_principal_model():
    p = Principal(
        user_id="u_alice",
        username="alice",
        tenant_id="t_acme",
        role=Role.ADMIN,
        auth_token="TOK_123"
    )
    assert p.identifier() == "t_acme::alice[admin]"
    assert p.role == Role.ADMIN


def test_resource_model():
    r = Resource(
        id="res_doc_1",
        tenant_id="t_acme",
        owner_id="u_alice",
        name="Quarterly Report",
        endpoint_path="/api/v1/docs/1",
        visibility=Visibility.USER_PRIVATE,
        canary_token="TC_CANARY_TEST123_ABCD",
        allowed_user_ids={"u_alice"}
    )
    assert r.visibility == Visibility.USER_PRIVATE
    assert "u_alice" in r.allowed_user_ids
    assert "TC_CANARY_TEST123_ABCD" in r.canary_token


def test_finding_model():
    f = Finding(
        leakage_type=LeakageType.CROSS_TENANT_LEAK,
        severity=Severity.CRITICAL,
        title="Cross Tenant Leak",
        description="Tenant B received Tenant A canary",
        target_path="/api/v1/tenant/dash",
        resource_id="res_dash",
        resource_owner_tenant="t_acme",
        resource_owner_user="u_alice",
        victim_principal="u_alice",
        adversary_principal="u_bob",
        detected_canary="TC_CANARY_123",
        response_cache_status=CacheStatus.HIT
    )
    assert f.severity == Severity.CRITICAL
    assert f.leakage_type == LeakageType.CROSS_TENANT_LEAK
    assert f.id.startswith("FINDING-")
