"""Unit tests for TargetSecurityGuard and Framework self-defense."""

import pytest
from tenantcache.config import TargetSecurityGuard, TenantCacheConfig
from tenantcache.differential import DifferentialRunner
from tenantcache.simulator import TenantSimulator
from tenantcache.oracle import SecurityOracle
from tenantcache.detection import LeakageDetector


def test_target_security_guard_blocks_external_domains():
    external_targets = [
        "https://google.com",
        "http://example.com/api",
        "http://169.254.169.254/latest/meta-data/",
        "http://192.168.1.100:8080",
        "https://evil-attacker.io"
    ]
    for target in external_targets:
        with pytest.raises(ValueError, match="Security Safeguard Violation"):
            TargetSecurityGuard.validate_target_url(target)


def test_target_security_guard_allows_local_lab():
    local_targets = [
        "http://localhost:8080",
        "http://127.0.0.1:8000",
        "http://0.0.0.0:80",
        "http://testserver",
        "http://tenantcache_app:8000",
        "http://tenantcache_proxy:80"
    ]
    for target in local_targets:
        assert TargetSecurityGuard.validate_target_url(target) is True


def test_differential_runner_enforces_security_guard():
    sim = TenantSimulator(seed=42)
    oracle = SecurityOracle(sim.resources, sim.principals)
    detector = LeakageDetector(oracle, sim.canary_registry, sim.resources)

    with pytest.raises(ValueError, match="Security Safeguard Violation"):
        DifferentialRunner(oracle, detector, live_base_url="https://production-banking-app.com")
