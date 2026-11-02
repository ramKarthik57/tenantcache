"""Unit tests for ProxyCacheSimulator."""

from tenantcache.cache import ProxyCacheSimulator
from tenantcache.models import RequestSpec, Principal, Role, CacheStatus


def test_proxy_cache_hit_and_miss():
    cache = ProxyCacheSimulator(config_archetype="V1_MISSING_TENANT_KEY")
    p1 = Principal(user_id="u1", username="u1", tenant_id="t1", role=Role.ADMIN)
    req = RequestSpec(url_path="/api/v1/test", principal=p1)

    # Initial lookup -> MISS
    assert cache.lookup(req) is None

    # Store entry
    cache.store(req, 200, {"Content-Type": "application/json"}, '{"data": "val"}')

    # Subsequent lookup -> HIT
    res = cache.lookup(req)
    assert res is not None
    assert res.cache_status == CacheStatus.HIT
    assert res.status_code == 200
    assert res.body_text == '{"data": "val"}'


def test_proxy_cache_v1_cross_tenant_collision():
    cache = ProxyCacheSimulator(config_archetype="V1_MISSING_TENANT_KEY")
    p_acme = Principal(user_id="u_alice", username="alice", tenant_id="t_acme", role=Role.ADMIN)
    p_beta = Principal(user_id="u_bob", username="bob", tenant_id="t_beta", role=Role.ADMIN)

    req_acme = RequestSpec(url_path="/api/v1/tenant/dashboard", principal=p_acme)
    req_beta = RequestSpec(url_path="/api/v1/tenant/dashboard", principal=p_beta)

    # Acme stores confidential dashboard
    cache.store(req_acme, 200, {}, '{"secret": "acme_secret"}')

    # Beta queries same URL -> V1 collides and serves Acme's data!
    hit_beta = cache.lookup(req_beta)
    assert hit_beta is not None
    assert hit_beta.body_text == '{"secret": "acme_secret"}'


def test_proxy_cache_s1_bypass():
    cache = ProxyCacheSimulator(config_archetype="SECURE_S1_STRICT_PRIVATE")
    p = Principal(
        user_id="u1",
        username="u1",
        tenant_id="t1",
        role=Role.ADMIN,
        headers={"Authorization": "Bearer TEST"}
    )
    req = RequestSpec(url_path="/api/v1/tenant/dashboard", principal=p, headers=p.headers)

    assert cache.should_bypass(req) is True
    assert cache.lookup(req) is None
