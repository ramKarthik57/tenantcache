"""Integration test executing against REAL native Nginx on localhost."""

import os
import subprocess
import time
import httpx
import pytest
from src.tenantcache.simulator import TenantSimulator
from src.tenantcache.oracle import SecurityOracle
from src.tenantcache.detection import LeakageDetector
from src.tenantcache.generator import RequestGenerator
from src.tenantcache.differential import DifferentialRunner
from src.tenantcache.models import CacheStatus, LeakageType


def test_real_nginx_v1_live_cross_tenant_leak():
    # 1. Start FastAPI backend on port 8000
    app_proc = subprocess.Popen(
        ["python", "-m", "uvicorn", "lab.application.main:app", "--host", "127.0.0.1", "--port", "8000"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )

    # Give backend 1.5 seconds to bind
    time.sleep(1.5)

    nginx_dir = os.path.abspath("lab/nginx_runtime/nginx-1.26.2")
    nginx_exe = os.path.join(nginx_dir, "nginx.exe")
    nginx_conf = os.path.abspath("lab/nginx/windows/v1_missing_tenant_key.conf")

    # Clear cache folder
    cache_dir = os.path.join(nginx_dir, "temp", "cache_v1")
    if os.path.exists(cache_dir):
        import shutil
        shutil.rmtree(cache_dir, ignore_errors=True)
    os.makedirs(cache_dir, exist_ok=True)

    # Start Real Nginx
    nginx_proc = subprocess.Popen(
        [nginx_exe, "-c", nginx_conf],
        cwd=nginx_dir,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(1.0)

    try:
        # 2. Verify Real Nginx responds on port 8080
        with httpx.Client(base_url="http://127.0.0.1:8080", timeout=5.0) as client:
            health = client.get("/healthz")
            assert health.status_code == 200
            assert "X-Cache-Status" in health.headers

            # 3. Setup TenantCache objects
            sim = TenantSimulator(seed=42)
            oracle = SecurityOracle(sim.resources)
            detector = LeakageDetector(oracle, sim.canary_registry, sim.resources)
            generator = RequestGenerator(sim)

            p_alice = sim.get_principal("user_alice")
            p_bob = sim.get_principal("user_bob")
            res_acme_dash = sim.get_resource("res_acme_dashboard")

            # Sequence: Alice (Acme) warms cache -> Bob (Beta) queries same URI
            seq = generator.generate_cross_tenant_sequence(p_alice, p_bob, res_acme_dash)

            # Step 1: Alice queries real Nginx
            desc1, req1 = seq.steps[0]
            resp1 = client.request(
                method=req1.method,
                url=req1.url_path,
                headers=req1.headers
            )
            assert resp1.status_code == 200
            assert resp1.headers.get("X-Cache-Status") == "MISS"
            assert res_acme_dash.canary_token in resp1.text

            # Step 2: Bob queries real Nginx on the same endpoint
            desc2, req2 = seq.steps[1]
            resp2 = client.request(
                method=req2.method,
                url=req2.url_path,
                headers=req2.headers
            )
            assert resp2.status_code == 200

            # CRITICAL REAL NGINX VALIDATION:
            # Real Nginx must return X-Cache-Status: HIT
            real_nginx_cache_status = resp2.headers.get("X-Cache-Status")
            assert real_nginx_cache_status == "HIT", f"Expected HIT from real Nginx, got {real_nginx_cache_status}"

            # Real Nginx served Alice's canary to Bob!
            assert res_acme_dash.canary_token in resp2.text

            # Evaluate with TenantCache detector
            rec = DifferentialRunner(oracle, detector, live_base_url="http://127.0.0.1:8080").execute_request(req2)
            finding = detector.evaluate_response(
                principal=req2.principal,
                target_resource=res_acme_dash,
                response=rec,
                sequence_category=seq.category
            )
            assert finding is not None
            assert finding.leakage_type == LeakageType.CROSS_TENANT_LEAK
            assert finding.detected_canary == res_acme_dash.canary_token
            assert finding.response_cache_status == CacheStatus.HIT

    finally:
        # Stop Nginx and FastAPI
        subprocess.run(["taskkill.exe", "/F", "/IM", "nginx.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        app_proc.terminate()
        try:
            app_proc.wait(timeout=2.0)
        except Exception:
            app_proc.kill()
