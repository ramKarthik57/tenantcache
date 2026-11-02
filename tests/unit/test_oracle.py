"""Unit tests for Ground-Truth Security Oracle."""

from tenantcache.simulator import TenantSimulator
from tenantcache.oracle import SecurityOracle, AuthDecision


def test_oracle_authorizations():
    sim = TenantSimulator(seed=42)
    oracle = SecurityOracle(sim.resources, sim.principals)

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

    # 5. Revocation dynamically reflects in Oracle via explicit reference event
    sim.revoke_access("res_acme_project_alpha", "user_alex")
    oracle.record_revocation("res_acme_project_alpha", "user_alex")
    proj = sim.get_resource("res_acme_project_alpha")
    assert oracle.evaluate(alex, proj) == AuthDecision.DENY
    assert oracle.evaluate(alice, proj) == AuthDecision.ALLOW


def test_oracle_immunity_to_external_mutation():
    """Verifies that mutating the target application's resource object never alters the Oracle's reference ledger."""
    from tenantcache.models import Visibility
    import copy

    sim = TenantSimulator(seed=42)
    oracle = SecurityOracle(sim.resources, sim.principals)
    alex = sim.get_principal("user_alex")
    alice_profile = sim.get_resource("res_alice_profile")

    # Baseline: Alex accessing Alice's private profile must DENY
    assert oracle.evaluate(alex, alice_profile) == AuthDecision.DENY

    # Malicious or buggy target code mutates every attribute on external resource object
    tampered = copy.deepcopy(alice_profile)
    tampered.visibility = Visibility.PUBLIC
    tampered.tenant_id = alex.tenant_id
    tampered.owner_id = alex.user_id
    tampered.allowed_roles = {alex.role}
    tampered.allowed_user_ids = {alex.user_id}
    tampered.is_revoked_for.clear()

    # Oracle must evaluate exclusively against its internal reference ledger
    assert oracle.evaluate(alex, tampered) == AuthDecision.DENY
    assert oracle.resources["res_alice_profile"].visibility == Visibility.USER_PRIVATE

    # Test unknown resource ID fails closed (DENY)
    assert oracle.evaluate(alex, "res_non_existent") == AuthDecision.DENY


def test_oracle_immunity_to_principal_mutation():
    """Verifies that mutating caller-passed Principal attributes never alters Oracle evaluations when principal ledger is registered."""
    import copy
    from tenantcache.models import Role

    sim = TenantSimulator(seed=42)
    oracle = SecurityOracle(sim.resources, sim.principals)
    alex = sim.get_principal("user_alex")
    admin_logs = sim.get_resource("res_acme_admin_logs")

    # Baseline: Alex (standard user) accessing admin logs must DENY
    assert oracle.evaluate(alex, admin_logs) == AuthDecision.DENY

    # Tamper with caller-passed principal object (elevate to ADMIN and change tenant)
    tampered_alex = copy.deepcopy(alex)
    tampered_alex.role = Role.ADMIN
    tampered_alex.tenant_id = "tenant_beta"

    # Oracle resolves identity via internal principal ledger by user_id, ignoring external mutation
    assert oracle.evaluate(tampered_alex, admin_logs) == AuthDecision.DENY

    # Unknown principal ID fails closed
    assert oracle.evaluate("user_non_existent", admin_logs) == AuthDecision.DENY


def test_oracle_ghost_principal_fails_closed():
    """Verifies that an unregistered ghost principal claiming a valid tenant is strictly DENIED access to protected resources."""
    from tenantcache.models import Principal, Role

    sim = TenantSimulator(seed=42)
    oracle = SecurityOracle(sim.resources, sim.principals)
    acme_dash = sim.get_resource("res_acme_dashboard")
    public_doc = sim.get_resource("res_pub_guideline")

    # Unregistered ghost principal claiming Acme membership
    ghost = Principal(user_id="ghost_user_999", username="ghost", tenant_id="tenant_acme", role=Role.STANDARD_USER)

    # Public document remains accessible
    assert oracle.evaluate(ghost, public_doc) == AuthDecision.ALLOW

    # Protected tenant dashboard must FAIL CLOSED (DENY) despite claimed tenant_id matching
    assert oracle.evaluate(ghost, acme_dash) == AuthDecision.DENY


def test_oracle_empty_principal_ledger_rejects_all():
    """Verifies that an explicitly configured but empty principal ledger ({}) fails closed and rejects all principals."""
    from tenantcache.models import Principal, Role

    sim = TenantSimulator(seed=42)
    # Explicitly configure an empty principal ledger
    oracle_empty = SecurityOracle(sim.resources, principals={})
    acme_dash = sim.get_resource("res_acme_dashboard")
    public_doc = sim.get_resource("res_pub_guideline")

    alice = sim.get_principal("user_alice")

    # Public document remains accessible
    assert oracle_empty.evaluate(alice, public_doc) == AuthDecision.ALLOW

    # Non-public resource must be strictly DENIED for any principal because ledger is empty
    assert oracle_empty.evaluate(alice, acme_dash) == AuthDecision.DENY
    assert oracle_empty.evaluate("user_alice", acme_dash) == AuthDecision.DENY


def test_benchmark_cli_oracle_construction_rejects_unregistered_principal():
    """Verifies that the exact Oracle construction path used by the Benchmark CLI
    (BenchmarkSuite) rejects unregistered principals claiming valid tenant and role attributes.
    """
    from tenantcache.evaluation import BenchmarkSuite
    from tenantcache.models import Principal, Role

    # Exact construction used by CLI commands (benchmark, scan, etc.)
    suite = BenchmarkSuite(seed=42)
    oracle = suite.oracle
    acme_dash = suite.sim.get_resource("res_acme_dashboard")
    public_doc = suite.sim.get_resource("res_pub_guideline")

    # Unregistered intruder fabricating legitimate Acme tenant and Admin role
    intruder = Principal(
        user_id="unregistered_intruder_999",
        username="intruder",
        tenant_id="tenant_acme",
        role=Role.ADMIN
    )

    # 1. Protected resource fails closed (DENY) despite forged tenant and role attributes
    decision = oracle.evaluate(intruder, acme_dash)
    assert decision == AuthDecision.DENY

    # 2. String ID lookup for unregistered principal also fails closed
    assert oracle.evaluate("unregistered_intruder_999", acme_dash) == AuthDecision.DENY

    # 3. Legitimate registered user succeeds
    alice = suite.sim.get_principal("user_alice")
    assert oracle.evaluate(alice, acme_dash) == AuthDecision.ALLOW

    # 4. Public resource remains accessible to anyone
    assert oracle.evaluate(intruder, public_doc) == AuthDecision.ALLOW
