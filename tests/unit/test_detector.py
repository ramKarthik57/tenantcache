"""Unit tests for LeakageDetector."""

from src.tenantcache.simulator import TenantSimulator
from src.tenantcache.oracle import SecurityOracle
from src.tenantcache.detection import LeakageDetector
from src.tenantcache.models import ResponseRecord, CacheStatus, LeakageType, Severity


def test_leakage_detector_identifies_cross_tenant_leak():
    sim = TenantSimulator(seed=42)
    oracle = SecurityOracle(sim.resources)
    detector = LeakageDetector(oracle, sim.canary_registry, sim.resources)

    acme_dash = sim.get_resource("res_acme_dashboard")
    bob = sim.get_principal("user_bob")

    # Bob's response contains Acme's canary
    leaked_body = f'{{"revenue": "$42M", "secret": "{acme_dash.canary_token}"}}'
    resp = ResponseRecord(status_code=200, body_text=leaked_body, cache_status=CacheStatus.HIT)

    finding = detector.evaluate_response(bob, acme_dash, resp)
    assert finding is not None
    assert finding.leakage_type == LeakageType.CROSS_TENANT_LEAK
    assert finding.severity == Severity.CRITICAL
    assert finding.detected_canary == acme_dash.canary_token
    assert finding.resource_owner_tenant == "tenant_acme"


def test_leakage_detector_allows_public_resource():
    sim = TenantSimulator(seed=42)
    oracle = SecurityOracle(sim.resources)
    detector = LeakageDetector(oracle, sim.canary_registry, sim.resources)

    public_doc = sim.get_resource("res_pub_guideline")
    bob = sim.get_principal("user_bob")

    public_body = f'{{"doc": "guidelines", "canary": "{public_doc.canary_token}"}}'
    resp = ResponseRecord(status_code=200, body_text=public_body, cache_status=CacheStatus.HIT)

    finding = detector.evaluate_response(bob, public_doc, resp)
    assert finding is None  # Public resource caching is NOT a leak!
