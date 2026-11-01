"""Integration tests executing against REAL native Nginx on localhost across multiple archetypes."""

import os
import subprocess
import time
import httpx
import pytest
from src.tenantcache.simulator import TenantSimulator
from src.tenantcache.oracle import SecurityOracle, AuthDecision
from src.tenantcache.detection import LeakageDetector
from src.tenantcache.generator import RequestGenerator
from src.tenantcache.differential import DifferentialRunner
from src.tenantcache.models import CacheStatus, LeakageType


def _run_nginx_test(conf_rel_path: str, cache_folder_name: str):
    nginx_dir = os.path.abspath("lab/nginx_runtime/nginx-1.26.2")
    nginx_exe = os.path.join(nginx_dir, "nginx.exe")
    nginx_conf = os.path.abspath(conf_rel_path)

    cache_dir = os.path.join(nginx_dir, "temp", cache_folder_name)
    if os.path.exists(cache_dir):
        import shutil
        shutil.rmtree(cache_dir, ignore_errors=True)
    os.makedirs(cache_dir, exist_ok=True)

    # Ensure clean process table
    subprocess.run(["taskkill.exe", "/F", "/IM", "nginx.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    nginx_proc = subprocess.Popen(
        [nginx_exe, "-c", nginx_conf],
        cwd=nginx_dir,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(1.2)
    return nginx_proc, nginx_exe, nginx_dir


def test_real_nginx_v1_live_cross_tenant_leak():
    """Validates V1 (Missing Tenant Key) on live native Nginx binary."""
    app_proc = subprocess.Popen(
        ["python", "-m", "uvicorn", "lab.application.main:app", "--host", "127.0.0.1", "--port", "8000"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(1.5)

    nginx_proc, nginx_exe, nginx_dir = _run_nginx_test("lab/nginx/windows/v1_missing_tenant_key.conf", "cache_v1")

    try:
        with httpx.Client(base_url="http://127.0.0.1:8080", timeout=5.0) as client:
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
            resp1 = client.request(method=req1.method, url=req1.url_path, headers=req1.headers)
            assert resp1.status_code == 200
            assert res_acme_dash.canary_token in resp1.text

            # Step 2: Bob queries real Nginx on the same endpoint
            desc2, req2 = seq.steps[1]
            resp2 = client.request(method=req2.method, url=req2.url_path, headers=req2.headers)
            assert resp2.status_code == 200

            # Real Nginx must return HIT
            real_nginx_cache_status = resp2.headers.get("X-Cache-Status")
            assert real_nginx_cache_status == "HIT", f"Expected HIT from real Nginx, got {real_nginx_cache_status}"

            # Real Nginx served Alice's canary to Bob!
            assert res_acme_dash.canary_token in resp2.text

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

    finally:
        subprocess.run(["taskkill.exe", "/F", "/IM", "nginx.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        app_proc.terminate()
        try:
            app_proc.wait(timeout=2.0)
        except Exception:
            app_proc.kill()


def test_real_nginx_s1_strict_private_bypass():
    """Validates S1 (Strict Private Bypass) on live native Nginx binary."""
    app_proc = subprocess.Popen(
        ["python", "-m", "uvicorn", "lab.application.main:app", "--host", "127.0.0.1", "--port", "8000"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    time.sleep(1.5)

    nginx_proc, nginx_exe, nginx_dir = _run_nginx_test("lab/nginx/windows/s1_strict_private.conf", "cache_s1")

    try:
        with httpx.Client(base_url="http://127.0.0.1:8080", timeout=5.0) as client:
            sim = TenantSimulator(seed=42)
            oracle = SecurityOracle(sim.resources)
            detector = LeakageDetector(oracle, sim.canary_registry, sim.resources)
            generator = RequestGenerator(sim)

            p_alice = sim.get_principal("user_alice")
            p_bob = sim.get_principal("user_bob")
            res_acme_dash = sim.get_resource("res_acme_dashboard")

            seq = generator.generate_cross_tenant_sequence(p_alice, p_bob, res_acme_dash)

            # Step 1: Alice queries real Nginx
            desc1, req1 = seq.steps[0]
            resp1 = client.request(method=req1.method, url=req1.url_path, headers=req1.headers)
            assert resp1.status_code == 200
            # S1 must BYPASS cache for authenticated requests
            s1_status_1 = resp1.headers.get("X-Cache-Status", "").upper()
            assert "BYPASS" in s1_status_1

            # Step 2: Bob queries real Nginx
            desc2, req2 = seq.steps[1]
            resp2 = client.request(method=req2.method, url=req2.url_path, headers=req2.headers)
            assert resp2.status_code == 200
            s1_status_2 = resp2.headers.get("X-Cache-Status", "").upper()
            assert "BYPASS" in s1_status_2

            # Bob receives his own tenant dashboard, NOT Alice's!
            assert res_acme_dash.canary_token not in resp2.text

            # Detector must find ZERO leaks
            rec = DifferentialRunner(oracle, detector, live_base_url="http://127.0.0.1:8080").execute_request(req2)
            finding = detector.evaluate_response(
                principal=req2.principal,
                target_resource=res_acme_dash,
                response=rec,
                sequence_category=seq.category
            )
            assert finding is None

    finally:
        subprocess.run(["taskkill.exe", "/F", "/IM", "nginx.exe"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        app_proc.terminate()
        try:
            app_proc.wait(timeout=2.0)
        except Exception:
            app_proc.kill()
