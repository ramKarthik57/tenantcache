"""Integration tests for DifferentialRunner."""

from src.tenantcache.simulator import TenantSimulator
from src.tenantcache.oracle import SecurityOracle
from src.tenantcache.detection import LeakageDetector
from src.tenantcache.generator import RequestGenerator
from src.tenantcache.differential import DifferentialRunner
from src.tenantcache.cache import ProxyCacheSimulator
from lab.application.database import lab_db


def test_runner_v1_detects_cross_tenant_leak():
    sim = TenantSimulator(seed=42)
    lab_db.reset(sim)
    oracle = SecurityOracle(sim.resources)
    detector = LeakageDetector(oracle, sim.canary_registry, sim.resources)
    generator = RequestGenerator(sim)

    cache_sim = ProxyCacheSimulator(config_archetype="V1_MISSING_TENANT_KEY")
    runner = DifferentialRunner(oracle, detector, cache_simulator=cache_sim)

    p_alice = sim.get_principal("user_alice")
    p_bob = sim.get_principal("user_bob")
    res_dash = sim.get_resource("res_acme_dashboard")

    seq = generator.generate_cross_tenant_sequence(p_alice, p_bob, res_dash)
    findings = runner.run_sequence(seq)

    assert len(findings) == 1
    f = findings[0]
    assert f.leakage_type.value == "CROSS_TENANT_LEAK"
    assert f.resource_owner_tenant == "tenant_acme"
    assert "bob" in f.adversary_principal


def test_runner_s1_blocks_leak():
    sim = TenantSimulator(seed=42)
    lab_db.reset(sim)
    oracle = SecurityOracle(sim.resources)
    detector = LeakageDetector(oracle, sim.canary_registry, sim.resources)
    generator = RequestGenerator(sim)

    cache_sim = ProxyCacheSimulator(config_archetype="SECURE_S1_STRICT_PRIVATE")
    runner = DifferentialRunner(oracle, detector, cache_simulator=cache_sim)

    p_alice = sim.get_principal("user_alice")
    p_bob = sim.get_principal("user_bob")
    res_dash = sim.get_resource("res_acme_dashboard")

    seq = generator.generate_cross_tenant_sequence(p_alice, p_bob, res_dash)
    findings = runner.run_sequence(seq)

    assert len(findings) == 0
