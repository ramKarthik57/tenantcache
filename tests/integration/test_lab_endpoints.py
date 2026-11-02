"""Integration tests verifying lab target application endpoints."""

from starlette.testclient import TestClient
from lab.application.main import app, evaluate_request_authorization
from lab.application.database import lab_db
from tenantcache.simulator import TenantSimulator

client = TestClient(app)


def setup_function():
    sim = TenantSimulator(seed=42)
    lab_db.reset(sim)


def test_public_guidelines_endpoint():
    res = client.get("/api/v1/public/docs/guidelines")
    assert res.status_code == 200
    assert "content" in res.json()
    assert "public" in res.headers.get("Cache-Control", "").lower()


def test_tenant_dashboard_authenticated():
    sim = lab_db.simulator
    alice = sim.get_principal("user_alice")

    # Unauthorized access fails
    res_unauth = client.get("/api/v1/tenant/dashboard")
    assert res_unauth.status_code == 401

    # Authorized access succeeds
    res_auth = client.get("/api/v1/tenant/dashboard", headers=alice.headers)
    assert res_auth.status_code == 200
    assert res_auth.json()["tenant"] == "tenant_acme"


def test_admin_revocation_endpoint():
    sim = lab_db.simulator
    alice = sim.get_principal("user_alice")
    alex = sim.get_principal("user_alex")

    # Pre-revocation: Alex can access shared project
    res_before = client.get("/api/v1/shared/projects/proj-alpha", headers=alex.headers)
    assert res_before.status_code == 200

    # Admin revokes Alex's access
    res_revoke = client.post(
        "/api/v1/admin/revoke-access",
        headers=alice.headers,
        json={"resource_id": "res_acme_project_alpha", "user_id": "user_alex"}
    )
    assert res_revoke.status_code == 200

    # Post-revocation: Direct query by Alex is denied (403 Forbidden)
    res_after = client.get("/api/v1/shared/projects/proj-alpha", headers=alex.headers)
    assert res_after.status_code == 403


def test_exact_route_matching_rejects_partial_identifiers():
    """Verify that route identifiers are matched by exact equality, not substring searches."""
    sim = lab_db.simulator
    alice = sim.get_principal("user_alice")

    # 1. Partial public document: /guid vs /guidelines
    r_part_doc = client.get("/api/v1/public/docs/guid")
    assert r_part_doc.status_code == 403  # Policy denies unmapped/partial doc

    # Verifier subrequest also denies
    r_part_doc_ver = client.get("/api/v1/auth/verify?uri=/api/v1/public/docs/guid")
    assert r_part_doc_ver.status_code == 403

    # 2. Partial invoice identifier: /inv vs /inv-101
    r_part_inv = client.get("/api/v1/tenant/invoices/inv", headers=alice.headers)
    assert r_part_inv.status_code == 404  # Not found

    r_part_inv_ver = client.get(
        "/api/v1/auth/verify?uri=/api/v1/tenant/invoices/inv",
        headers=alice.headers
    )
    assert r_part_inv_ver.status_code == 403  # Nginx verifier denies access

    # 3. Partial project identifier: /proj vs /proj-alpha
    r_part_proj = client.get("/api/v1/shared/projects/proj", headers=alice.headers)
    assert r_part_proj.status_code == 404  # Not found

    r_part_proj_ver = client.get(
        "/api/v1/auth/verify?uri=/api/v1/shared/projects/proj",
        headers=alice.headers
    )
    assert r_part_proj_ver.status_code == 403  # Nginx verifier denies access


def test_shared_policy_contract_and_deletion_lifecycle():
    """Verify contract symmetry between origin handlers and /api/v1/auth/verify,
    including resource deletion lifecycle for profile, dashboard, and audit logs.
    """
    sim = lab_db.simulator
    alice = sim.get_principal("user_alice")

    # 1. Profile Pre-Deletion: Both origin and verifier approve
    r_prof_orig = client.get("/api/v1/user/profile", headers=alice.headers)
    assert r_prof_orig.status_code == 200
    r_prof_ver = client.get("/api/v1/auth/verify?uri=/api/v1/user/profile", headers=alice.headers)
    assert r_prof_ver.status_code == 200

    # Delete Alice's profile
    lab_db.delete_resource("res_alice_profile")

    # Profile Post-Deletion: Origin returns 404, Verifier returns 403 (fail-closed for proxy)
    r_prof_orig_del = client.get("/api/v1/user/profile", headers=alice.headers)
    assert r_prof_orig_del.status_code == 404
    r_prof_ver_del = client.get("/api/v1/auth/verify?uri=/api/v1/user/profile", headers=alice.headers)
    assert r_prof_ver_del.status_code == 403

    # 2. Dashboard Lifecycle
    r_dash_orig = client.get("/api/v1/tenant/dashboard", headers=alice.headers)
    assert r_dash_orig.status_code == 200
    r_dash_ver = client.get("/api/v1/auth/verify?uri=/api/v1/tenant/dashboard", headers=alice.headers)
    assert r_dash_ver.status_code == 200

    # Delete Acme dashboard
    lab_db.delete_resource("res_acme_dashboard")

    r_dash_orig_del = client.get("/api/v1/tenant/dashboard", headers=alice.headers)
    assert r_dash_orig_del.status_code == 404
    r_dash_ver_del = client.get("/api/v1/auth/verify?uri=/api/v1/tenant/dashboard", headers=alice.headers)
    assert r_dash_ver_del.status_code == 403

    # 3. Audit Logs Lifecycle
    r_log_orig = client.get("/api/v1/admin/audit-logs", headers=alice.headers)
    assert r_log_orig.status_code == 200
    r_log_ver = client.get("/api/v1/auth/verify?uri=/api/v1/admin/audit-logs", headers=alice.headers)
    assert r_log_ver.status_code == 200

    # Delete Acme audit logs
    lab_db.delete_resource("res_acme_admin_logs")

    r_log_orig_del = client.get("/api/v1/admin/audit-logs", headers=alice.headers)
    assert r_log_orig_del.status_code == 404
    r_log_ver_del = client.get("/api/v1/auth/verify?uri=/api/v1/admin/audit-logs", headers=alice.headers)
    assert r_log_ver_del.status_code == 403


def test_exact_dashboard_resolution_rejects_decoy_fallback():
    """Verifies that the dashboard route resolves ONLY the canonical dashboard resource ID,
    and strictly denies authorization rather than falling back to decoy or backup resources.
    """
    from tenantcache.models import Resource, Visibility, Role

    sim = lab_db.simulator
    alice = sim.get_principal("user_alice")

    # 1. Baseline: Canonical dashboard exists and is authorized
    r_canon = client.get("/api/v1/tenant/dashboard", headers=alice.headers)
    assert r_canon.status_code == 200
    assert r_canon.json()["tenant"] == "tenant_acme"

    # 2. Delete canonical dashboard
    lab_db.delete_resource("res_acme_dashboard")

    # 3. Create a decoy resource for tenant_acme containing 'dashboard' in its ID
    decoy_resource = Resource(
        id="res_acme_dashboard_backup",
        tenant_id="tenant_acme",
        owner_id="user_alice",
        name="Acme Decoy Backup Dashboard",
        endpoint_path="/api/v1/tenant/dashboard_backup",
        visibility=Visibility.TENANT_SHARED,
        canary_token="TC_DECOY_CANARY_DO_NOT_SERVE",
        payload={"tenant": "tenant_acme", "decoy": True, "token": "TC_DECOY_CANARY_DO_NOT_SERVE"},
        allowed_roles={Role.ADMIN, Role.STANDARD_USER}
    )
    sim.resources["res_acme_dashboard_backup"] = decoy_resource

    # 4. Request canonical dashboard route /api/v1/tenant/dashboard
    # Direct origin must return 404 (Not Found), NOT substitute the decoy resource!
    r_origin_post_del = client.get("/api/v1/tenant/dashboard", headers=alice.headers)
    assert r_origin_post_del.status_code == 404
    assert "TC_DECOY_CANARY_DO_NOT_SERVE" not in r_origin_post_del.text

    # 5. Auth verifier subrequest must return 403 Forbidden (fail-closed for proxy)
    r_verifier_post_del = client.get(
        "/api/v1/auth/verify?uri=/api/v1/tenant/dashboard",
        headers=alice.headers
    )
    assert r_verifier_post_del.status_code == 403


def test_http_method_consistency_get_head_unsupported():
    """Verifies consistent HTTP method handling across GET, HEAD, and unsupported methods (POST, PUT, DELETE)
    between origin handlers and authorization policy verification.
    """
    sim = lab_db.simulator
    alice = sim.get_principal("user_alice")

    # 1. GET returns 200 with JSON payload
    r_get = client.get("/api/v1/tenant/dashboard", headers=alice.headers)
    assert r_get.status_code == 200
    assert len(r_get.text) > 0
    assert "private" in r_get.headers.get("Cache-Control", "").lower()

    # 2. HEAD returns 200 with headers but empty response body (RFC 9110)
    r_head = client.head("/api/v1/tenant/dashboard", headers=alice.headers)
    assert r_head.status_code == 200
    assert len(r_head.text) == 0
    assert "private" in r_head.headers.get("Cache-Control", "").lower()

    # 3. Unsupported methods (POST, PUT, DELETE) on read routes return 405 Method Not Allowed
    r_post = client.post("/api/v1/tenant/dashboard", headers=alice.headers)
    assert r_post.status_code == 405

    r_put = client.put("/api/v1/tenant/dashboard", headers=alice.headers)
    assert r_put.status_code == 405

    r_delete = client.delete("/api/v1/tenant/dashboard", headers=alice.headers)
    assert r_delete.status_code == 405

    # 4. Verifier subrequest allows GET and HEAD, denies unsupported methods
    r_ver_get = client.get(
        "/api/v1/auth/verify?uri=/api/v1/tenant/dashboard",
        headers={**alice.headers, "X-Original-Method": "GET"}
    )
    assert r_ver_get.status_code == 200

    r_ver_head = client.get(
        "/api/v1/auth/verify?uri=/api/v1/tenant/dashboard",
        headers={**alice.headers, "X-Original-Method": "HEAD"}
    )
    assert r_ver_head.status_code == 200

    r_ver_post = client.get(
        "/api/v1/auth/verify?uri=/api/v1/tenant/dashboard",
        headers={**alice.headers, "X-Original-Method": "POST"}
    )
    assert r_ver_post.status_code == 403  # Fails closed in proxy auth
