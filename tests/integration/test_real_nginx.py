"""Integration tests executing against REAL native Nginx on localhost across all 8 archetypes.

Tests validate:
- V1: Missing Tenant Key in cache key
- V2: Missing User Context in cache key
- V3: Unvalidated Client Header in cache key
- V4: Stale Revocation Lag
- V5: Erroneous Public Caching
- V6: Path Normalization Divergence
- S1: Strict Private Bypass
- S2: Server-Validated Identity Keying
"""

import os
import subprocess
import time
import shutil
import httpx
import pytest
from src.tenantcache.simulator import TenantSimulator
from src.tenantcache.oracle import SecurityOracle, AuthDecision
from src.tenantcache.detection import LeakageDetector
from src.tenantcache.generator import RequestGenerator
from src.tenantcache.differential import DifferentialRunner
from src.tenantcache.models import CacheStatus, LeakageType
from lab.application.database import lab_db


NGINX_DIR = os.path.abspath("lab/nginx_runtime/nginx-1.26.2")
NGINX_EXE = os.path.join(NGINX_DIR, "nginx.exe")


def _start_nginx(conf_rel_path: str, cache_folder: str):
    subprocess.run(["taskkill.exe", "/F", "/IM", "nginx.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    cache_dir = os.path.join(NGINX_DIR, "temp", cache_folder)
    if os.path.exists(cache_dir):
        shutil.rmtree(cache_dir, ignore_errors=True)
    os.makedirs(cache_dir, exist_ok=True)

    conf_path = os.path.abspath(conf_rel_path)
    proc = subprocess.Popen([NGINX_EXE, "-c", conf_path], cwd=NGINX_DIR, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.2)
    return proc


@pytest.fixture(scope="module")
def live_lab_server():
    """Starts live FastAPI lab application on port 8000 for Nginx upstream proxying."""
    sim = TenantSimulator(seed=42)
    lab_db.reset(sim)
    app_proc = subprocess.Popen(
        ["python", "-m", "uvicorn", "lab.application.main:app", "--host", "127.0.0.1", "--port", "8000"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(1.5)
    yield sim
    subprocess.run(["taskkill.exe", "/F", "/IM", "nginx.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    app_proc.terminate()
    try:
        app_proc.wait(timeout=2.0)
    except Exception:
        app_proc.kill()


def test_real_nginx_v1_missing_tenant_key(live_lab_server):
    """V1: Real Nginx omits tenant key; cross-tenant dashboard leak."""
    sim = live_lab_server
    _start_nginx("lab/nginx/windows/v1_missing_tenant_key.conf", "cache_v1")
    try:
        with httpx.Client(base_url="http://127.0.0.1:8080", timeout=5.0) as client:
            p_alice = sim.get_principal("user_alice")
            p_bob = sim.get_principal("user_bob")
            res_acme_dash = sim.get_resource("res_acme_dashboard")

            # Alice warms cache
            r1 = client.get("/api/v1/tenant/dashboard", headers={"Authorization": f"Bearer {p_alice.auth_token}"})
            assert r1.status_code == 200
            assert res_acme_dash.canary_token in r1.text

            # Bob requests dashboard on same path
            r2 = client.get("/api/v1/tenant/dashboard", headers={"Authorization": f"Bearer {p_bob.auth_token}"})
            assert r2.status_code == 200
            assert r2.headers.get("X-Cache-Status") == "HIT"
            assert res_acme_dash.canary_token in r2.text
    finally:
        subprocess.run(["taskkill.exe", "/F", "/IM", "nginx.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def test_real_nginx_v2_missing_user_auth(live_lab_server):
    """V2: Real Nginx keys on tenant but omits user identity; cross-user profile leak."""
    sim = live_lab_server
    _start_nginx("lab/nginx/windows/v2_missing_user_auth.conf", "cache_v2")
    try:
        with httpx.Client(base_url="http://127.0.0.1:8080", timeout=5.0) as client:
            p_alice = sim.get_principal("user_alice")
            p_alex = sim.get_principal("user_alex")
            res_prof_alice = sim.get_resource("res_alice_profile")

            # Alice primes profile
            r1 = client.get("/api/v1/user/profile", headers={"Authorization": f"Bearer {p_alice.auth_token}", "X-Tenant-ID": p_alice.tenant_id})
            assert r1.status_code == 200
            assert res_prof_alice.canary_token in r1.text

            # Alex (same tenant) queries profile
            r2 = client.get("/api/v1/user/profile", headers={"Authorization": f"Bearer {p_alex.auth_token}", "X-Tenant-ID": p_alex.tenant_id})
            assert r2.status_code == 200
            assert r2.headers.get("X-Cache-Status") == "HIT"
            assert res_prof_alice.canary_token in r2.text  # Alex leaked Alice's profile!
    finally:
        subprocess.run(["taskkill.exe", "/F", "/IM", "nginx.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def test_real_nginx_v3_unvalidated_header(live_lab_server):
    """V3: Real Nginx trusts client X-Tenant-ID header; cross-tenant spoofing leak."""
    sim = live_lab_server
    _start_nginx("lab/nginx/windows/v3_unvalidated_header.conf", "cache_v3")
    try:
        with httpx.Client(base_url="http://127.0.0.1:8080", timeout=5.0) as client:
            p_alice = sim.get_principal("user_alice")
            p_bob = sim.get_principal("user_bob")
            res_acme_dash = sim.get_resource("res_acme_dashboard")

            # Alice primes with legitimate tenant header
            r1 = client.get("/api/v1/tenant/dashboard", headers={"Authorization": f"Bearer {p_alice.auth_token}", "X-Tenant-ID": "tenant_acme"})
            assert r1.status_code == 200

            # Bob from Beta requests dashboard spoofing X-Tenant-ID: tenant_acme
            r2 = client.get("/api/v1/tenant/dashboard", headers={"Authorization": f"Bearer {p_bob.auth_token}", "X-Tenant-ID": "tenant_acme"})
            assert r2.status_code == 200
            assert r2.headers.get("X-Cache-Status") == "HIT"
            assert res_acme_dash.canary_token in r2.text
    finally:
        subprocess.run(["taskkill.exe", "/F", "/IM", "nginx.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def test_real_nginx_v4_stale_revocation(live_lab_server):
    """V4: Real Nginx serves cached 200 OK after user authorization is revoked at origin."""
    sim = live_lab_server
    _start_nginx("lab/nginx/windows/v4_stale_revocation.conf", "cache_v4")
    try:
        with httpx.Client(base_url="http://127.0.0.1:8080", timeout=5.0) as client:
            p_alice = sim.get_principal("user_alice")
            p_alex = sim.get_principal("user_alex")
            r_proj = sim.get_resource("res_acme_project_alpha")
            endpoint = r_proj.endpoint_path

            # Step 1: Alex accesses project before revocation
            r1 = client.get(endpoint, headers={"Authorization": f"Bearer {p_alex.auth_token}"})
            assert r1.status_code == 200
            assert r_proj.canary_token in r1.text

            # Step 2: Admin revokes Alex's access at origin database
            rev = client.post("/api/v1/admin/revoke-access", json={"resource_id": r_proj.id, "user_id": p_alex.user_id}, headers={"Authorization": f"Bearer {p_alice.auth_token}"})
            assert rev.status_code == 200

            # Step 3: Alex requests project again through Nginx
            r2 = client.get(endpoint, headers={"Authorization": f"Bearer {p_alex.auth_token}"})
            assert r2.status_code == 200
            assert r2.headers.get("X-Cache-Status") == "HIT"
            assert r_proj.canary_token in r2.text  # Stale confidential response served!
    finally:
        subprocess.run(["taskkill.exe", "/F", "/IM", "nginx.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def test_real_nginx_v5_erroneous_public(live_lab_server):
    """V5: Real Nginx ignores Cache-Control: private; caches private profile across clients."""
    sim = live_lab_server
    _start_nginx("lab/nginx/windows/v5_erroneous_public.conf", "cache_v5")
    try:
        with httpx.Client(base_url="http://127.0.0.1:8080", timeout=5.0) as client:
            p_alice = sim.get_principal("user_alice")
            p_bob = sim.get_principal("user_bob")
            res_prof_alice = sim.get_resource("res_alice_profile")

            r1 = client.get("/api/v1/user/profile", headers={"Authorization": f"Bearer {p_alice.auth_token}"})
            assert r1.status_code == 200
            assert res_prof_alice.canary_token in r1.text

            r2 = client.get("/api/v1/user/profile", headers={"Authorization": f"Bearer {p_bob.auth_token}"})
            assert r2.status_code == 200
            assert r2.headers.get("X-Cache-Status") == "HIT"
            assert res_prof_alice.canary_token in r2.text
    finally:
        subprocess.run(["taskkill.exe", "/F", "/IM", "nginx.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def test_real_nginx_v6_normalization(live_lab_server):
    """V6: Real Nginx normalizes URI discarding query params; causes cross-tenant collision."""
    sim = live_lab_server
    _start_nginx("lab/nginx/windows/v6_normalization.conf", "cache_v6")
    try:
        with httpx.Client(base_url="http://127.0.0.1:8080", timeout=5.0) as client:
            p_alice = sim.get_principal("user_alice")
            p_bob = sim.get_principal("user_bob")
            res_acme_dash = sim.get_resource("res_acme_dashboard")

            r1 = client.get("/api/v1/tenant/dashboard", headers={"Authorization": f"Bearer {p_alice.auth_token}"})
            assert r1.status_code == 200

            # Bob requests with unkeyed query param
            r2 = client.get("/api/v1/tenant/dashboard?query=probe", headers={"Authorization": f"Bearer {p_bob.auth_token}"})
            assert r2.status_code == 200
            assert r2.headers.get("X-Cache-Status") == "HIT"
            assert res_acme_dash.canary_token in r2.text
    finally:
        subprocess.run(["taskkill.exe", "/F", "/IM", "nginx.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def test_real_nginx_s1_strict_private(live_lab_server):
    """S1: Real Nginx bypasses cache for all authenticated requests."""
    sim = live_lab_server
    _start_nginx("lab/nginx/windows/s1_strict_private.conf", "cache_s1")
    try:
        with httpx.Client(base_url="http://127.0.0.1:8080", timeout=5.0) as client:
            p_alice = sim.get_principal("user_alice")
            p_bob = sim.get_principal("user_bob")
            res_acme_dash = sim.get_resource("res_acme_dashboard")

            r1 = client.get("/api/v1/tenant/dashboard", headers={"Authorization": f"Bearer {p_alice.auth_token}"})
            assert r1.status_code == 200
            assert "BYPASS" in r1.headers.get("X-Cache-Status", "").upper()

            r2 = client.get("/api/v1/tenant/dashboard", headers={"Authorization": f"Bearer {p_bob.auth_token}"})
            assert r2.status_code == 200
            assert "BYPASS" in r2.headers.get("X-Cache-Status", "").upper()
            assert res_acme_dash.canary_token not in r2.text  # Bob gets own dashboard, no leak!
    finally:
        subprocess.run(["taskkill.exe", "/F", "/IM", "nginx.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def test_real_nginx_s2_identity_keyed(live_lab_server):
    """S2: Real Nginx partitions cache by verified token; Bob experiences MISS and receives own content."""
    sim = live_lab_server
    _start_nginx("lab/nginx/windows/s2_identity_keyed.conf", "cache_s2")
    try:
        with httpx.Client(base_url="http://127.0.0.1:8080", timeout=5.0) as client:
            p_alice = sim.get_principal("user_alice")
            p_bob = sim.get_principal("user_bob")
            res_acme_dash = sim.get_resource("res_acme_dashboard")

            r1 = client.get("/api/v1/tenant/dashboard", headers={"Authorization": f"Bearer {p_alice.auth_token}"})
            assert r1.status_code == 200

            # Bob requests with distinct token
            r2 = client.get("/api/v1/tenant/dashboard", headers={"Authorization": f"Bearer {p_bob.auth_token}"})
            assert r2.status_code == 200
            assert r2.headers.get("X-Cache-Status") in ("MISS", "BYPASS")
            assert res_acme_dash.canary_token not in r2.text  # No leak!
    finally:
        subprocess.run(["taskkill.exe", "/F", "/IM", "nginx.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
