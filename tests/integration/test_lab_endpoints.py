"""Integration tests verifying lab target application endpoints."""

from starlette.testclient import TestClient
from lab.application.main import app
from lab.application.database import lab_db
from src.tenantcache.simulator import TenantSimulator

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
