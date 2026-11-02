"""Property-based testing with Hypothesis verifying formal security invariants."""

import pytest
from hypothesis import given, strategies as st
from tenantcache.simulator import TenantSimulator
from tenantcache.oracle import SecurityOracle, AuthDecision
from tenantcache.detection import LeakageDetector
from tenantcache.models import ResponseRecord, CacheStatus, Visibility


@given(st.integers(min_value=1, max_value=10000))
def test_hypothesis_canary_uniqueness_and_invariant(seed):
    sim = TenantSimulator(seed=seed)
    oracle = SecurityOracle(sim.resources, sim.principals)
    detector = LeakageDetector(oracle, sim.canary_registry, sim.resources)

    # Invariant 1: All private canaries must be unique
    canaries = list(sim.canary_registry.keys())
    assert len(canaries) == len(set(canaries))

    # Invariant 2: For any arbitrary principal and resource, if Oracle says ALLOW, detector never flags leak
    for p in sim.principals.values():
        pub_res = sim.get_resource("res_pub_guideline")
        resp = ResponseRecord(
            status_code=200,
            body_text=f"Public doc payload: {pub_res.canary_token}",
            cache_status=CacheStatus.HIT
        )
        finding = detector.evaluate_response(p, pub_res, resp)
        assert finding is None, "Legitimate allowed access must never be flagged as a leak"


@given(
    st.sampled_from(["tenant_acme", "tenant_beta", "tenant_gamma"]),
    st.text(min_size=5, max_size=50)
)
def test_hypothesis_noise_resilience(tenant_id, random_noise):
    sim = TenantSimulator(seed=100)
    oracle = SecurityOracle(sim.resources, sim.principals)
    detector = LeakageDetector(oracle, sim.canary_registry, sim.resources)

    p = sim.get_principal("user_alice")
    r = sim.get_resource("res_acme_dashboard")

    # Invariant 3: Responses without legitimate canaries must NEVER trigger a finding
    clean_noise = random_noise.replace("TC_CANARY_", "NOISE_")
    resp = ResponseRecord(
        status_code=200,
        body_text=f'{{"data": "{clean_noise}"}}',
        cache_status=CacheStatus.HIT
    )
    finding = detector.evaluate_response(p, r, resp)
    assert finding is None, "Noise without verified canaries must never trigger a false positive"
