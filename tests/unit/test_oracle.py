"""Unit tests for Ground-Truth Security Oracle."""

from src.tenantcache.simulator import TenantSimulator
from src.tenantcache.oracle import SecurityOracle, AuthDecision


def test_oracle_authorizations():
    sim = TenantSimulator(seed=42)
    oracle = SecurityOracle(sim.resources)

    alice = sim.get_principal("user_alice")
    alex = sim.get_principal("user_alex")
    bob = sim.get_principal("user_bob")

    acme_dash = sim.get_resource("res_acme_dashboard")
    public_doc = sim.get_resource("res_pub_guideline")
    alice_profile = sim.get_resource("res_alice_profile")
    admin_logs = sim.get_resource("res_acme_admin_logs")

    # 1. Public document allowed for all
    assert oracle.evaluate(alice, public_doc) == AuthDecision.ALLOW
    assert oracle.evaluate(bob, public_doc) == AuthDecision.ALLOW

    # 2. Tenant dashboard allowed for tenant users, denied for other tenants
    assert oracle.evaluate(alice, acme_dash) == AuthDecision.ALLOW
    assert oracle.evaluate(alex, acme_dash) == AuthDecision.ALLOW
    assert oracle.evaluate(bob, acme_dash) == AuthDecision.DENY

    # 3. Private profile allowed only for owner
    assert oracle.evaluate(alice, alice_profile) == AuthDecision.ALLOW
    assert oracle.evaluate(alex, alice_profile) == AuthDecision.DENY
    assert oracle.evaluate(bob, alice_profile) == AuthDecision.DENY

    # 4. Admin logs allowed only for Admin
    assert oracle.evaluate(alice, admin_logs) == AuthDecision.ALLOW
    assert oracle.evaluate(alex, admin_logs) == AuthDecision.DENY

    # 5. Revocation dynamically reflects in Oracle
    sim.revoke_access("res_acme_project_alpha", "user_alex")
    proj = sim.get_resource("res_acme_project_alpha")
    assert oracle.evaluate(alex, proj) == AuthDecision.DENY
    assert oracle.evaluate(alice, proj) == AuthDecision.ALLOW
