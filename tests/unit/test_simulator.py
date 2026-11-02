"""Unit tests for TenantSimulator."""

from tenantcache.simulator import TenantSimulator
from tenantcache.models import Role, Visibility


def test_tenant_simulator_universe():
    sim = TenantSimulator(seed=42)
    assert len(sim.tenants) >= 3
    assert "tenant_acme" in sim.tenants
    assert "tenant_beta" in sim.tenants
    assert "tenant_gamma" in sim.tenants

    assert len(sim.users) >= 5
    alice = sim.get_principal("user_alice")
    bob = sim.get_principal("user_bob")

    assert alice.tenant_id == "tenant_acme"
    assert alice.role == Role.ADMIN
    assert bob.tenant_id == "tenant_beta"

    # Verify canary generation consistency
    assert len(sim.canary_registry) >= 5
    for canary, res_id in sim.canary_registry.items():
        assert canary.startswith("TC_CANARY_") or canary.startswith("TC_PUBLIC_")
        assert res_id in sim.resources


def test_simulator_revocation():
    sim = TenantSimulator(seed=42)
    proj = sim.get_resource("res_acme_project_alpha")
    assert "user_alex" in proj.allowed_user_ids

    sim.revoke_access("res_acme_project_alpha", "user_alex")
    assert "user_alex" not in proj.allowed_user_ids
    assert "user_alex" in proj.is_revoked_for
