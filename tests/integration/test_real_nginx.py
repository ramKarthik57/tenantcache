"""Integration tests executing against REAL native Nginx on localhost across all 8 archetypes.

Tests validate:
- V1: Missing Tenant Key in cache key
- V2: Missing User Context in cache key
- V3: Unvalidated Client Header in cache key
- V4: Stale Revocation Lag
- V5: Erroneous Public Caching
- V6: Unkeyed Query Parameter Omission
- S1: Strict Private Bypass
- S2: Server-Validated Identity Keying
"""

import os
import re
import sys
import socket
import subprocess
import time
import shutil
import httpx
import pytest
from tenantcache.simulator import TenantSimulator
from tenantcache.oracle import SecurityOracle, AuthDecision
from tenantcache.detection import LeakageDetector
from tenantcache.generator import RequestGenerator
from tenantcache.differential import DifferentialRunner
from tenantcache.models import CacheStatus, LeakageType
from lab.application.database import lab_db


IS_WINDOWS = sys.platform.startswith("win")
WINDOWS_NGINX_DIR = os.path.abspath("lab/nginx_runtime/nginx-1.26.2")
WINDOWS_NGINX_EXE = os.path.join(WINDOWS_NGINX_DIR, "nginx.exe")
SYSTEM_NGINX_EXE = shutil.which("nginx")


def _get_nginx_executable():
    if IS_WINDOWS and os.path.exists(WINDOWS_NGINX_EXE):
        return WINDOWS_NGINX_EXE, WINDOWS_NGINX_DIR
    elif SYSTEM_NGINX_EXE:
        return SYSTEM_NGINX_EXE, os.getcwd()
    return None, None


NGINX_EXE, NGINX_CWD = _get_nginx_executable()

def find_free_port(preferred: int) -> int:
    """Returns preferred port if free, otherwise binds ephemeral free port."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        try:
            s.bind(("127.0.0.1", preferred))
            return preferred
        except OSError:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]


class LiveLabContext:
    """Encapsulates running lab backend and dynamically assigned proxy ports."""
    def __init__(self, sim, backend_port: int, nginx_port: int):
        self.sim = sim
        self.backend_port = backend_port
        self.nginx_port = nginx_port
        self.base_url = f"http://127.0.0.1:{nginx_port}"

    def reset_backend(self):
        """Executes isolated test harness database reset directly against origin backend."""
        backend_url = f"http://127.0.0.1:{self.backend_port}"
        with httpx.Client(base_url=backend_url, timeout=5.0) as direct_client:
            r = direct_client.post(
                "/api/v1/lab/reset",
                headers={"X-TenantCache-Test-Control": "TC_LOCAL_TEST_CONTROL"}
            )
            assert r.status_code == 200

    def __getattr__(self, name):
        return getattr(self.sim, name)
pytestmark = pytest.mark.skipif(NGINX_EXE is None, reason="No native Nginx binary available in environment")


def _stop_process_safe(proc):
    """Safely terminates only the specific child process PID without affecting unrelated system processes."""
    if proc is None:
        return
    try:
        if IS_WINDOWS:
            subprocess.run(["taskkill.exe", "/F", "/T", "/PID", str(proc.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        else:
            subprocess.run(["pkill", "-9", "-P", str(proc.pid)], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            proc.kill()
            proc.wait(timeout=2.0)
    except Exception:
        try:
            proc.kill()
        except Exception:
            pass


def _start_nginx(conf_rel_path: str, cache_folder: str, ctx: LiveLabContext = None):
    # Ensure runtime temp and log directories exist under NGINX_CWD
    temp_root = os.path.join(NGINX_CWD, "temp")
    logs_root = os.path.join(NGINX_CWD, "logs")
    os.makedirs(temp_root, exist_ok=True)
    os.makedirs(logs_root, exist_ok=True)

    # Ensure unprivileged temp paths exist for non-root Linux runners
    for d in ["client_body", "proxy", "fastcgi", "uwsgi", "scgi"]:
        os.makedirs(os.path.join(temp_root, d), exist_ok=True)

    cache_dir = os.path.join(temp_root, cache_folder)
    if os.path.exists(cache_dir):
        shutil.rmtree(cache_dir, ignore_errors=True)
    os.makedirs(cache_dir, exist_ok=True)

    conf_abs = os.path.abspath(conf_rel_path)
    with open(conf_abs, "r", encoding="utf-8") as f:
        conf_content = f.read()

    # Dynamic port substitutions
    nginx_port = ctx.nginx_port if ctx else 8080
    backend_port = ctx.backend_port if ctx else 8000
    conf_content = re.sub(r"listen\s+\d+;", f"listen {nginx_port};", conf_content)
    conf_content = conf_content.replace(":8000", f":{backend_port}")

    # Inject relative temp paths into http block to ensure unprivileged execution on Linux
    temp_dirs_conf = (
        "    client_body_temp_path temp/client_body;\n"
        "    proxy_temp_path temp/proxy;\n"
        "    fastcgi_temp_path temp/fastcgi;\n"
        "    uwsgi_temp_path temp/uwsgi;\n"
        "    scgi_temp_path temp/scgi;\n"
    )
    conf_content = conf_content.replace("http {", f"http {{\n{temp_dirs_conf}")

    # Explicitly rewrite proxy_cache_path to isolated per-test cache directory (using forward slashes)
    conf_content = re.sub(r"proxy_cache_path\s+[^\s]+", f"proxy_cache_path temp/{cache_folder}", conf_content)

    # Explicit top-level pid and error_log directives for unprivileged execution (relative to -p NGINX_CWD)
    conf_content = f"pid temp/nginx_{cache_folder}.pid;\nerror_log logs/error_{cache_folder}.log info;\n" + conf_content

    runtime_conf = os.path.join(temp_root, f"runtime_{cache_folder}.conf")
    with open(runtime_conf, "w", encoding="utf-8") as f:
        f.write(conf_content)

    err_log_rel = f"logs/error_{cache_folder}.log"
    cmd = [
        NGINX_EXE,
        "-e", err_log_rel,
        "-p", NGINX_CWD,
        "-c", runtime_conf,
        "-g", "daemon off;"
    ]
    proc = subprocess.Popen(cmd, cwd=NGINX_CWD, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

    # Socket polling loop to ensure Nginx is accepting connections before test proceeds
    deadline = time.time() + 5.0
    while time.time() < deadline:
        if proc.poll() is not None:
            err_log_path = os.path.join(logs_root, f"error_{cache_folder}.log")
            err_content = ""
            if os.path.exists(err_log_path):
                with open(err_log_path, "r", encoding="utf-8", errors="ignore") as f:
                    err_content = f.read()
            stderr_out = ""
            if proc.stderr:
                try:
                    stderr_out = proc.stderr.read().decode("utf-8", errors="ignore")
                except Exception:
                    pass
            raise RuntimeError(f"Nginx terminated unexpectedly (code {proc.returncode}). Stderr:\n{stderr_out}\nError log:\n{err_content}")
        try:
            with socket.create_connection(("127.0.0.1", nginx_port), timeout=0.1):
                break
        except (OSError, ConnectionRefusedError):
            time.sleep(0.05)

    return proc


@pytest.fixture(scope="module")
def live_lab_server():
    """Starts live FastAPI lab application with dynamic port allocation."""
    sim = TenantSimulator(seed=42)
    lab_db.reset(sim)
    backend_port = find_free_port(8000)
    nginx_port = find_free_port(8080)
    ctx = LiveLabContext(sim, backend_port, nginx_port)

    app_proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "lab.application.main:app", "--host", "127.0.0.1", "--port", str(backend_port)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    # Socket polling readiness check for FastAPI backend
    deadline = time.time() + 5.0
    while time.time() < deadline:
        if app_proc.poll() is not None:
            raise RuntimeError(f"Backend app exited unexpectedly with code {app_proc.returncode}")
        try:
            with socket.create_connection(("127.0.0.1", backend_port), timeout=0.1):
                break
        except (OSError, ConnectionRefusedError):
            time.sleep(0.05)

    yield ctx
    _stop_process_safe(app_proc)


def test_real_nginx_v1_missing_tenant_key(live_lab_server):
    """V1: Real Nginx omits tenant key; cross-tenant dashboard leak."""
    lab_db.reset(live_lab_server.sim)
    sim = live_lab_server
    proc = _start_nginx("lab/nginx/windows/v1_missing_tenant_key.conf", "cache_v1", live_lab_server)
    try:
        with httpx.Client(base_url=live_lab_server.base_url, timeout=5.0) as client:
            live_lab_server.reset_backend()
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
        _stop_process_safe(proc)


def test_real_nginx_v2_missing_user_auth(live_lab_server):
    """V2: Real Nginx keys on tenant but omits user identity; cross-user profile leak."""
    lab_db.reset(live_lab_server.sim)
    sim = live_lab_server
    proc = _start_nginx("lab/nginx/windows/v2_missing_user_auth.conf", "cache_v2", live_lab_server)
    try:
        with httpx.Client(base_url=live_lab_server.base_url, timeout=5.0) as client:
            live_lab_server.reset_backend()
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
        _stop_process_safe(proc)


def test_real_nginx_v3_unvalidated_header(live_lab_server):
    """V3: Real Nginx trusts client X-Tenant-ID header; cross-tenant spoofing leak."""
    lab_db.reset(live_lab_server.sim)
    sim = live_lab_server
    proc = _start_nginx("lab/nginx/windows/v3_unvalidated_header.conf", "cache_v3", live_lab_server)
    try:
        with httpx.Client(base_url=live_lab_server.base_url, timeout=5.0) as client:
            live_lab_server.reset_backend()
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
        _stop_process_safe(proc)


def test_real_nginx_v4_stale_revocation(live_lab_server):
    """V4: Real Nginx serves cached 200 OK after user authorization is revoked at origin."""
    lab_db.reset(live_lab_server.sim)
    sim = live_lab_server
    proc = _start_nginx("lab/nginx/windows/v4_stale_revocation.conf", "cache_v4", live_lab_server)
    try:
        with httpx.Client(base_url=live_lab_server.base_url, timeout=5.0) as client:
            live_lab_server.reset_backend()
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
        _stop_process_safe(proc)


def test_real_nginx_v5_erroneous_public(live_lab_server):
    """V5: Real Nginx ignores Cache-Control: private; caches private profile across clients."""
    lab_db.reset(live_lab_server.sim)
    sim = live_lab_server
    proc = _start_nginx("lab/nginx/windows/v5_erroneous_public.conf", "cache_v5", live_lab_server)
    try:
        with httpx.Client(base_url=live_lab_server.base_url, timeout=5.0) as client:
            live_lab_server.reset_backend()
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
        _stop_process_safe(proc)


def test_real_nginx_v6_normalization(live_lab_server):
    """V6: Real Nginx key uses normalized $uri which collapses duplicate slashes into an alias collision."""
    lab_db.reset(live_lab_server.sim)
    sim = live_lab_server
    proc = _start_nginx("lab/nginx/windows/v6_normalization.conf", "cache_v6", live_lab_server)
    try:
        with httpx.Client(base_url=live_lab_server.base_url, timeout=5.0) as client:
            live_lab_server.reset_backend()
            p_alice = sim.get_principal("user_alice")
            p_bob = sim.get_principal("user_bob")
            res_acme_dash = sim.get_resource("res_acme_dashboard")

            # Alice warms cache on canonical path
            r1 = client.get("/api/v1/tenant/dashboard", headers={"Authorization": f"Bearer {p_alice.auth_token}"})
            assert r1.status_code == 200
            assert res_acme_dash.canary_token in r1.text

            # Bob requests aliased path with duplicate slashes (/api/v1/tenant//dashboard)
            # Due to Nginx normalizing $uri, it collapses '//' to '/' and serves Alice's cached dashboard!
            r2 = client.get("/api/v1/tenant//dashboard", headers={"Authorization": f"Bearer {p_bob.auth_token}"})
            assert r2.status_code == 200
            assert r2.headers.get("X-Cache-Status") == "HIT"
            assert res_acme_dash.canary_token in r2.text
    finally:
        _stop_process_safe(proc)


def test_real_nginx_s1_strict_private(live_lab_server):
    """S1: Real Nginx bypasses cache for all authenticated requests."""
    lab_db.reset(live_lab_server.sim)
    sim = live_lab_server
    proc = _start_nginx("lab/nginx/windows/s1_strict_private.conf", "cache_s1", live_lab_server)
    try:
        with httpx.Client(base_url=live_lab_server.base_url, timeout=5.0) as client:
            live_lab_server.reset_backend()
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
        _stop_process_safe(proc)


def test_real_nginx_s2_identity_keyed(live_lab_server):
    """S2: Real Nginx server-validated identity keying with per-request auth verification (auth_request).
    Comprehensive verification covering:
    1. Valid token, same-principal repeat (MISS then HIT)
    2. Different principals, separate cache partitions (strict isolation)
    3. Bob supplying Alice's X-Tenant-ID & X-User-ID (untrusted headers stripped)
    4. Missing identity headers (clean token-based operation)
    5. Invalid token (403 Forbidden, no cache hit)
    6. Missing token (401 Unauthorized, no cache hit)
    7. Resource permission revocation after cache priming (proves immunity to stale authorization)
    8. Direct origin status vs proxy status equivalence
    9. Denied responses never leak cached confidential canaries
    """
    lab_db.reset(live_lab_server.sim)
    sim = live_lab_server
    proc = _start_nginx("lab/nginx/windows/s2_identity_keyed.conf", "cache_s2", live_lab_server)
    try:
        with httpx.Client(base_url=live_lab_server.base_url, timeout=5.0) as client:
            live_lab_server.reset_backend()
            p_alice = sim.get_principal("user_alice")
            p_alex = sim.get_principal("user_alex")
            p_bob = sim.get_principal("user_bob")
            res_acme_dash = sim.get_resource("res_acme_dashboard")
            res_beta_dash = sim.get_resource("res_beta_dashboard")
            r_proj = sim.get_resource("res_acme_project_alpha")
            endpoint = r_proj.endpoint_path

            # -------------------------------------------------------------
            # 1. Valid token, same-principal repeat (MISS then HIT)
            # -------------------------------------------------------------
            r1 = client.get("/api/v1/tenant/dashboard", headers={"Authorization": f"Bearer {p_alice.auth_token}"})
            assert r1.status_code == 200
            assert r1.headers.get("X-Cache-Status") == "MISS"
            assert res_acme_dash.canary_token in r1.text

            r2 = client.get("/api/v1/tenant/dashboard", headers={"Authorization": f"Bearer {p_alice.auth_token}"})
            assert r2.status_code == 200
            assert r2.headers.get("X-Cache-Status") == "HIT"
            assert res_acme_dash.canary_token in r2.text

            # -------------------------------------------------------------
            # 2. Different principals, separate cache partitions
            # -------------------------------------------------------------
            r3 = client.get("/api/v1/tenant/dashboard", headers={"Authorization": f"Bearer {p_bob.auth_token}"})
            assert r3.status_code == 200
            assert r3.headers.get("X-Cache-Status") == "MISS"
            assert res_acme_dash.canary_token not in r3.text
            assert res_beta_dash.canary_token in r3.text

            r4 = client.get("/api/v1/tenant/dashboard", headers={"Authorization": f"Bearer {p_bob.auth_token}"})
            assert r4.status_code == 200
            assert r4.headers.get("X-Cache-Status") == "HIT"
            assert res_acme_dash.canary_token not in r4.text
            assert res_beta_dash.canary_token in r4.text

            # -------------------------------------------------------------
            # 3. Bob supplying Alice's X-Tenant-ID & X-User-ID (untrusted headers stripped)
            # -------------------------------------------------------------
            r_spoof = client.get(
                "/api/v1/tenant/dashboard",
                headers={
                    "Authorization": f"Bearer {p_bob.auth_token}",
                    "X-Tenant-ID": "tenant_acme",
                    "X-User-ID": "user_alice"
                }
            )
            assert r_spoof.status_code == 200
            assert res_acme_dash.canary_token not in r_spoof.text
            assert res_beta_dash.canary_token in r_spoof.text

            # -------------------------------------------------------------
            # 4. Invalid token
            # -------------------------------------------------------------
            r_bad_token = client.get("/api/v1/tenant/dashboard", headers={"Authorization": "Bearer invalid_token_12345"})
            assert r_bad_token.status_code == 403
            assert res_acme_dash.canary_token not in r_bad_token.text

            # -------------------------------------------------------------
            # 5. Missing token
            # -------------------------------------------------------------
            r_no_token = client.get("/api/v1/tenant/dashboard")
            assert r_no_token.status_code == 401
            assert res_acme_dash.canary_token not in r_no_token.text

            # -------------------------------------------------------------
            # 6. Resource permission revocation after cache priming
            # -------------------------------------------------------------
            # Step A: Alex requests private project -> 200 MISS (cached in S2)
            r_alex_prime = client.get(endpoint, headers={"Authorization": f"Bearer {p_alex.auth_token}"})
            assert r_alex_prime.status_code == 200
            assert r_alex_prime.headers.get("X-Cache-Status") == "MISS"
            assert r_proj.canary_token in r_alex_prime.text

            # Step B: Alex repeat request -> 200 HIT (confirms cached)
            r_alex_repeat = client.get(endpoint, headers={"Authorization": f"Bearer {p_alex.auth_token}"})
            assert r_alex_repeat.status_code == 200
            assert r_alex_repeat.headers.get("X-Cache-Status") == "HIT"
            assert r_proj.canary_token in r_alex_repeat.text

            # Step C: Administrator revokes Alex's project access at origin database
            rev = client.post(
                "/api/v1/admin/revoke-access",
                json={"resource_id": r_proj.id, "user_id": p_alex.user_id},
                headers={"Authorization": f"Bearer {p_alice.auth_token}"}
            )
            assert rev.status_code == 200

            # Step D: Verify direct origin request returns 403 Forbidden
            backend_url = f"http://127.0.0.1:{live_lab_server.backend_port}"
            with httpx.Client(base_url=backend_url, timeout=5.0) as direct_client:
                r_direct = direct_client.get(endpoint, headers={"Authorization": f"Bearer {p_alex.auth_token}"})
                assert r_direct.status_code == 403

            # Step E: Alex repeats request through Nginx with the SAME token
            # S2 auth_request subrequest validates against origin, receives 403, and aborts
            # Nginx serves 403 Forbidden, NOT 200 HIT! The confidential canary is NOT leaked!
            r_alex_post_rev = client.get(endpoint, headers={"Authorization": f"Bearer {p_alex.auth_token}"})
            assert r_alex_post_rev.status_code == 403
            assert r_proj.canary_token not in r_alex_post_rev.text
            assert r_alex_post_rev.status_code == r_direct.status_code

            # -------------------------------------------------------------
            # 7. Token invalidation/revocation after cache priming (Criterion 2)
            # -------------------------------------------------------------
            # Step A: Bob primes tenant dashboard -> 200 MISS, then 200 HIT
            r_bob_prime = client.get("/api/v1/tenant/dashboard", headers={"Authorization": f"Bearer {p_bob.auth_token}"})
            assert r_bob_prime.status_code == 200
            assert res_beta_dash.canary_token in r_bob_prime.text

            r_bob_hit = client.get("/api/v1/tenant/dashboard", headers={"Authorization": f"Bearer {p_bob.auth_token}"})
            assert r_bob_hit.status_code == 200
            assert r_bob_hit.headers.get("X-Cache-Status") == "HIT"
            assert res_beta_dash.canary_token in r_bob_hit.text

            # Step B: Admin explicitly revokes Bob's token at origin
            r_rev_tok = client.post(
                "/api/v1/admin/revoke-token",
                json={"token": p_bob.auth_token},
                headers={"Authorization": f"Bearer {p_alice.auth_token}"}
            )
            assert r_rev_tok.status_code == 200

            # Step C: Direct origin returns 403 Forbidden for Bob's revoked token
            with httpx.Client(base_url=backend_url, timeout=5.0) as direct_client:
                r_bob_direct = direct_client.get(
                    "/api/v1/tenant/dashboard",
                    headers={"Authorization": f"Bearer {p_bob.auth_token}"}
                )
                assert r_bob_direct.status_code == 403

            # Step D: Bob repeats request to Nginx with the revoked token
            # Nginx auth_request subrequest invokes origin /api/v1/auth/verify -> returns 403
            # Nginx denies access with 403 Forbidden without serving cached response
            r_bob_post_rev = client.get(
                "/api/v1/tenant/dashboard",
                headers={"Authorization": f"Bearer {p_bob.auth_token}"}
            )
            assert r_bob_post_rev.status_code == 403
            assert res_beta_dash.canary_token not in r_bob_post_rev.text

            # -------------------------------------------------------------
            # 8. Deny-by-default for unknown / undeclared routes (Criteria 3 & 4)
            # -------------------------------------------------------------
            # An authenticated user requests an unmapped or unknown route
            # The origin auth_request endpoint strictly denies with 403, and Nginx blocks it
            r_unmapped = client.get(
                "/api/v1/unknown/undeclared-route",
                headers={"Authorization": f"Bearer {p_alice.auth_token}"}
            )
            assert r_unmapped.status_code == 403

            # -------------------------------------------------------------
            # 9. Token Expiration Lifecycle Verification
            # -------------------------------------------------------------
            p_charlie = sim.get_principal("user_charlie")
            res_gamma_dash = sim.get_resource("res_gamma_dashboard")
            # Step A: Charlie primes gamma dashboard (200 MISS then 200 HIT)
            r_charlie_prime = client.get("/api/v1/tenant/dashboard", headers={"Authorization": f"Bearer {p_charlie.auth_token}"})
            assert r_charlie_prime.status_code == 200
            assert res_gamma_dash.canary_token in r_charlie_prime.text

            r_charlie_hit = client.get("/api/v1/tenant/dashboard", headers={"Authorization": f"Bearer {p_charlie.auth_token}"})
            assert r_charlie_hit.status_code == 200
            assert r_charlie_hit.headers.get("X-Cache-Status") == "HIT"

            # Step B: Admin expires Charlie's token at origin
            client.post(
                "/api/v1/admin/expire-token",
                json={"token": p_charlie.auth_token},
                headers={"Authorization": f"Bearer {p_alice.auth_token}"}
            )

            # Step C: Charlie repeat request through Nginx -> Nginx auth_request yields 403, zero cache hit
            r_charlie_post_exp = client.get("/api/v1/tenant/dashboard", headers={"Authorization": f"Bearer {p_charlie.auth_token}"})
            assert r_charlie_post_exp.status_code == 403
            assert res_gamma_dash.canary_token not in r_charlie_post_exp.text

            # -------------------------------------------------------------
            # 10. Role Downgrade Lifecycle Verification
            # -------------------------------------------------------------
            res_admin_logs = sim.get_resource("res_acme_admin_logs")
            # Step A: Alice (admin) primes admin audit logs -> 200 MISS then 200 HIT
            r_adm_prime = client.get("/api/v1/admin/audit-logs", headers={"Authorization": f"Bearer {p_alice.auth_token}"})
            assert r_adm_prime.status_code == 200
            assert res_admin_logs.canary_token in r_adm_prime.text

            r_adm_hit = client.get("/api/v1/admin/audit-logs", headers={"Authorization": f"Bearer {p_alice.auth_token}"})
            assert r_adm_hit.status_code == 200
            assert r_adm_hit.headers.get("X-Cache-Status") == "HIT"

            # Step B: Downgrade Alice's role to standard_user in origin database
            client.post(
                "/api/v1/admin/downgrade-role",
                json={"user_id": p_alice.user_id, "new_role": "standard_user"},
                headers={"Authorization": f"Bearer {p_alice.auth_token}"}
            )

            # Step C: Alice repeat request through Nginx -> auth_request detects role downgrade, returns 403!
            r_adm_post_down = client.get("/api/v1/admin/audit-logs", headers={"Authorization": f"Bearer {p_alice.auth_token}"})
            assert r_adm_post_down.status_code == 403
            assert res_admin_logs.canary_token not in r_adm_post_down.text

            # -------------------------------------------------------------
            # 11. Tenant Membership Eviction Lifecycle Verification
            # -------------------------------------------------------------
            p_david = sim.get_principal("user_david")
            res_delta_dash = sim.get_resource("res_delta_dashboard")
            # Step A: David primes delta dashboard -> 200 MISS then 200 HIT
            r_david_prime = client.get("/api/v1/tenant/dashboard", headers={"Authorization": f"Bearer {p_david.auth_token}"})
            assert r_david_prime.status_code == 200
            assert res_delta_dash.canary_token in r_david_prime.text

            # Step B: Evict David from tenant
            client.post(
                "/api/v1/admin/evict-tenant-member",
                json={"user_id": p_david.user_id},
                headers={"Authorization": f"Bearer {p_david.auth_token}"}
            )

            # Step C: David repeat request through Nginx -> auth_request denies evicted user (403), zero cache hit
            r_david_post_evict = client.get("/api/v1/tenant/dashboard", headers={"Authorization": f"Bearer {p_david.auth_token}"})
            assert r_david_post_evict.status_code == 403
            assert res_delta_dash.canary_token not in r_david_post_evict.text

            # -------------------------------------------------------------
            # 12. Path Normalization & Traversal Immune Subrequest Verification
            # -------------------------------------------------------------
            # Non-admin attacker attempts encoded traversal to reach admin endpoint with standard user token
            p_brian = sim.get_principal("user_brian")
            r_traversal = client.get(
                "/api/v1/tenant/%2e%2e/admin/audit-logs",
                headers={"Authorization": f"Bearer {p_brian.auth_token}"}
            )
            assert r_traversal.status_code == 403

            # -------------------------------------------------------------
            # 13. Isolated Lab Reset & Route Enumeration Hardening (Phase 9 Audit)
            # -------------------------------------------------------------
            # A. Unauthenticated attempt to reset lab through Nginx proxy is DENIED (401 Unauthorized)
            r_proxy_noauth_reset = client.post("/api/v1/lab/reset")
            assert r_proxy_noauth_reset.status_code == 401

            # Authenticated attempt to reset lab through Nginx proxy is DENIED (403 Forbidden: route unmapped in proxy policy)
            r_proxy_auth_reset = client.post("/api/v1/lab/reset", headers={"Authorization": f"Bearer {p_alice.auth_token}"})
            assert r_proxy_auth_reset.status_code == 403

            # B. Direct backend attempt to reset lab without test-control authorization header is DENIED (403)
            with httpx.Client(base_url=backend_url, timeout=5.0) as direct_client:
                r_direct_no_auth_reset = direct_client.post("/api/v1/lab/reset")
                assert r_direct_no_auth_reset.status_code == 403

                # C. Direct backend call with test-control header succeeds (200)
                r_direct_auth_reset = direct_client.post(
                    "/api/v1/lab/reset",
                    headers={"X-TenantCache-Test-Control": "TC_LOCAL_TEST_CONTROL"}
                )
                assert r_direct_auth_reset.status_code == 200

            # D. Authenticated admin requesting non-existent / undeclared route under /admin prefix is DENIED (403)
            # Proves S2 policy does not use broad prefix inheritance
            r_fake_admin = client.get(
                "/api/v1/admin/not-a-real-route",
                headers={"Authorization": f"Bearer {p_alice.auth_token}"}
            )
            assert r_fake_admin.status_code == 403

            # E. Request for non-existent public document is DENIED (403) by policy verifier
            # (Prevents prefix-based authorization of non-existent resources)
            r_fake_pub = client.get("/api/v1/public/docs/non-existent-doc")
            assert r_fake_pub.status_code == 403

            # -------------------------------------------------------------
            # 14. Resource Deletion Immunity Regression Suite (Phase 10 Security Closure)
            # -------------------------------------------------------------
            # A. Alice Private Profile Deletion
            res_prof_alice = sim.get_resource("res_alice_profile")
            # Step A1: Prime cache for Alice's profile (200 MISS then 200 HIT)
            r_prof_prime = client.get("/api/v1/user/profile", headers={"Authorization": f"Bearer {p_alice.auth_token}"})
            assert r_prof_prime.status_code == 200
            assert r_prof_prime.headers.get("X-Cache-Status") == "MISS"
            assert res_prof_alice.canary_token in r_prof_prime.text

            r_prof_hit = client.get("/api/v1/user/profile", headers={"Authorization": f"Bearer {p_alice.auth_token}"})
            assert r_prof_hit.status_code == 200
            assert r_prof_hit.headers.get("X-Cache-Status") == "HIT"
            assert res_prof_alice.canary_token in r_prof_hit.text

            # Step A2: Admin deletes Alice's profile resource at origin
            r_del_prof = client.post(
                "/api/v1/admin/delete-resource",
                json={"resource_id": "res_alice_profile"},
                headers={"Authorization": f"Bearer {p_alice.auth_token}"}
            )
            assert r_del_prof.status_code == 200

            # Step A3: Direct origin request returns 404 Not Found
            with httpx.Client(base_url=backend_url, timeout=5.0) as direct_client:
                r_dir_prof = direct_client.get("/api/v1/user/profile", headers={"Authorization": f"Bearer {p_alice.auth_token}"})
                assert r_dir_prof.status_code == 404
                assert "Profile not found" in r_dir_prof.text

            # Step A4: Request through Nginx proxy -> S2 auth_request queries origin, fails closed (403),
            # strictly preventing Nginx from serving the cached 200 HIT!
            r_proxy_prof = client.get("/api/v1/user/profile", headers={"Authorization": f"Bearer {p_alice.auth_token}"})
            assert r_proxy_prof.status_code == 403
            assert res_prof_alice.canary_token not in r_proxy_prof.text

            # B. Tenant Dashboard Deletion
            # Step B1: Prime cache for Acme dashboard (200 MISS then 200 HIT)
            r_dash_prime = client.get("/api/v1/tenant/dashboard", headers={"Authorization": f"Bearer {p_alex.auth_token}"})
            assert r_dash_prime.status_code == 200
            assert res_acme_dash.canary_token in r_dash_prime.text

            r_dash_hit = client.get("/api/v1/tenant/dashboard", headers={"Authorization": f"Bearer {p_alex.auth_token}"})
            assert r_dash_hit.status_code == 200
            assert r_dash_hit.headers.get("X-Cache-Status") == "HIT"
            assert res_acme_dash.canary_token in r_dash_hit.text

            # Step B2: Admin deletes Acme dashboard resource at origin
            r_del_dash = client.post(
                "/api/v1/admin/delete-resource",
                json={"resource_id": "res_acme_dashboard"},
                headers={"Authorization": f"Bearer {p_alice.auth_token}"}
            )
            assert r_del_dash.status_code == 200

            # Step B3: Direct origin returns 404
            with httpx.Client(base_url=backend_url, timeout=5.0) as direct_client:
                r_dir_dash = direct_client.get("/api/v1/tenant/dashboard", headers={"Authorization": f"Bearer {p_alex.auth_token}"})
                assert r_dir_dash.status_code == 404

            # Step B4: Nginx proxy returns 403 Forbidden; zero canary leak!
            r_proxy_dash = client.get("/api/v1/tenant/dashboard", headers={"Authorization": f"Bearer {p_alex.auth_token}"})
            assert r_proxy_dash.status_code == 403
            assert res_acme_dash.canary_token not in r_proxy_dash.text

            # C. Admin Audit Logs Deletion
            # Step C1: Prime cache for Acme audit logs (200 MISS then 200 HIT)
            client.post(
                "/api/v1/admin/downgrade-role",
                json={"user_id": p_alice.user_id, "new_role": "admin"},
                headers={"Authorization": f"Bearer {p_alice.auth_token}"}
            )
            r_log_prime = client.get("/api/v1/admin/audit-logs", headers={"Authorization": f"Bearer {p_alice.auth_token}"})
            assert r_log_prime.status_code == 200
            assert res_admin_logs.canary_token in r_log_prime.text

            r_log_hit = client.get("/api/v1/admin/audit-logs", headers={"Authorization": f"Bearer {p_alice.auth_token}"})
            assert r_log_hit.status_code == 200
            assert r_log_hit.headers.get("X-Cache-Status") == "HIT"
            assert res_admin_logs.canary_token in r_log_hit.text

            # Step C2: Admin deletes Acme audit logs resource at origin
            r_del_log = client.post(
                "/api/v1/admin/delete-resource",
                json={"resource_id": "res_acme_admin_logs"},
                headers={"Authorization": f"Bearer {p_alice.auth_token}"}
            )
            assert r_del_log.status_code == 200

            # Step C3: Direct origin returns 404
            with httpx.Client(base_url=backend_url, timeout=5.0) as direct_client:
                r_dir_log = direct_client.get("/api/v1/admin/audit-logs", headers={"Authorization": f"Bearer {p_alice.auth_token}"})
                assert r_dir_log.status_code == 404

            # Step C4: Nginx proxy returns 403 Forbidden; zero canary leak!
            r_proxy_log = client.get("/api/v1/admin/audit-logs", headers={"Authorization": f"Bearer {p_alice.auth_token}"})
            assert r_proxy_log.status_code == 403
            assert res_admin_logs.canary_token not in r_proxy_log.text
    finally:
        _stop_process_safe(proc)
