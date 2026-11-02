"""Leakage Detection Engine with Canary-Based Invariant Verification."""

import time
from typing import Optional, Dict, List
from tenantcache.models import (
    Finding, LeakageType, Severity, Principal, Resource, ResponseRecord,
    CacheStatus, Visibility, Role
)
from tenantcache.oracle import SecurityOracle, AuthDecision


class LeakageDetector:
    """Detects and classifies cache isolation failures with 100% canary-attributed certainty."""

    def __init__(self, oracle: SecurityOracle, canary_registry: Dict[str, str], resources: Dict[str, Resource]):
        self.oracle = oracle
        self.canary_registry = canary_registry
        self.resources = resources

    def scan_response_for_canaries(self, body_text: str) -> List[str]:
        """Scans response body for known canaries in the universe."""
        detected = []
        for canary in self.canary_registry:
            if canary in body_text:
                detected.append(canary)
        return detected

    def evaluate_response(
        self,
        principal: Principal,
        target_resource: Resource,
        response: ResponseRecord,
        step_name: str = "probe",
        sequence_category: str = "GENERAL"
    ) -> Optional[Finding]:
        """Evaluates whether an HTTP response violates the security invariant."""
        # 1. Extract all canary tokens present in the response
        detected_canaries = self.scan_response_for_canaries(response.body_text)
        response.matched_canaries = detected_canaries

        # If no canaries are found, no confidential data leak can be proven
        if not detected_canaries:
            return None

        # 2. For each detected canary, determine the origin resource and verify invariant
        for canary in detected_canaries:
            origin_resource_id = self.canary_registry.get(canary)
            if not origin_resource_id or origin_resource_id not in self.resources:
                continue

            origin_resource = self.resources[origin_resource_id]

            # Invariant Check: Does ground-truth oracle permit principal to access this resource?
            decision = self.oracle.evaluate(principal, origin_resource)

            # If access is ALLOW, this is legitimate (e.g. public document or authorized user)
            if decision == AuthDecision.ALLOW:
                continue

            # If decision is DENY, INVARIANT IS VIOLATED: CONFIRMED LEAK!
            leak_type, severity = self._classify_violation(
                principal=principal,
                origin_resource=origin_resource,
                sequence_category=sequence_category,
                cache_status=response.cache_status
            )

            title = f"{leak_type.value}: {origin_resource.name} leaked to {principal.username}"
            desc = (
                f"Principal {principal.identifier()} received confidential canary '{canary}' "
                f"belonging to {origin_resource.tenant_id}::{origin_resource.name} via HTTP response. "
                f"Ground-Truth Oracle decision: DENY. Response Cache-Status: {response.cache_status.value}."
            )

            finding = Finding(
                leakage_type=leak_type,
                severity=severity,
                title=title,
                description=desc,
                target_path=origin_resource.endpoint_path,
                resource_id=origin_resource.id,
                resource_owner_tenant=origin_resource.tenant_id,
                resource_owner_user=origin_resource.owner_id,
                victim_principal=origin_resource.owner_id,
                adversary_principal=principal.identifier(),
                detected_canary=canary,
                response_cache_status=response.cache_status,
                evidence_headers=response.headers,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
            )
            return finding

        return None

    def _classify_violation(
        self,
        principal: Principal,
        origin_resource: Resource,
        sequence_category: str,
        cache_status: CacheStatus
    ) -> (LeakageType, Severity):
        # Revocation
        if principal.user_id in origin_resource.is_revoked_for or sequence_category == "STALE_REVOCATION":
            return LeakageType.STALE_REVOCATION_LEAK, Severity.HIGH

        # Cross-Tenant
        if principal.tenant_id != origin_resource.tenant_id:
            if sequence_category == "CACHE_KEY_SPOOFING":
                return LeakageType.CACHE_KEY_SPOOFING_LEAK, Severity.HIGH
            return LeakageType.CROSS_TENANT_LEAK, Severity.CRITICAL

        # Privilege Boundary
        if origin_resource.allowed_roles and principal.role not in origin_resource.allowed_roles:
            return LeakageType.PRIVILEGE_ESCALATION_LEAK, Severity.HIGH

        # Cross-User (within same tenant)
        if origin_resource.visibility == Visibility.USER_PRIVATE and principal.user_id != origin_resource.owner_id:
            return LeakageType.CROSS_USER_LEAK, Severity.HIGH

        return LeakageType.CROSS_TENANT_LEAK, Severity.HIGH


class OracleFreeDifferentialDetector:
    """Naive differential detector operating strictly without an authorization oracle.
    
    Evaluates observable HTTP response evidence (body text identity, canary reflection, cache status)
    without consulting ground-truth authorization models. Consequently cannot distinguish legitimate
    shared content (public documentation, intra-tenant shared dashboards) from true unauthorized leaks.
    """

    def __init__(self, canary_registry: Optional[Dict[str, str]] = None):
        self.canary_registry = canary_registry or {}

    def evaluate_differential(
        self,
        prime_response: Optional[ResponseRecord],
        probe_response: ResponseRecord,
        probing_principal: Principal,
        target_path: str,
        priming_principal: Optional[Principal] = None
    ) -> Optional[Finding]:
        """Evaluates whether probe_response appears to be a cache leakage based purely on observable evidence.
        
        A naive differential tester compares responses between substituted identity tokens.
        If the probing user shares the identity of the priming user, a cache hit appears to be normal
        same-user caching; without an authorization oracle, the tester cannot detect temporal revocation.
        Across differing identities, cache hits and response collisions are flagged as leakages.
        """
        # Same-user cache hit is considered benign by naive diffing (lacks oracle to track revocation)
        if priming_principal and priming_principal.user_id == probing_principal.user_id:
            return None

        # 1. Must be a successful response served from cache
        is_cache_hit = "HIT" in probe_response.cache_status.value.upper()
        if probe_response.status_code != 200 or not is_cache_hit:
            return None

        # 2. Check for response body identity or canary reflection from prime response
        has_content_collision = False
        detected_token = None

        if prime_response and prime_response.status_code == 200:
            if prime_response.body_text and prime_response.body_text == probe_response.body_text:
                has_content_collision = True
            if prime_response.matched_canaries:
                for c in prime_response.matched_canaries:
                    if c in probe_response.body_text:
                        has_content_collision = True
                        detected_token = c
                        break

        # Also scan response for known canaries in registry
        if not detected_token and self.canary_registry:
            for canary in self.canary_registry:
                if canary in probe_response.body_text:
                    has_content_collision = True
                    detected_token = canary
                    break

        if has_content_collision:
            res_id = self.canary_registry.get(detected_token, "res_unknown") if detected_token else "res_unknown"
            return Finding(
                leakage_type=LeakageType.CROSS_TENANT_LEAK,
                severity=Severity.HIGH,
                title=f"NAIVE_DIFF_LEAK: Cached response collision on {target_path}",
                description=f"Observable cache collision detected for {probing_principal.username} on {target_path} without oracle validation.",
                target_path=target_path,
                resource_id=res_id,
                resource_owner_tenant="unknown",
                resource_owner_user="unknown",
                victim_principal="prime_user",
                adversary_principal=probing_principal.identifier(),
                detected_canary=detected_token or "COLLISION",
                response_cache_status=probe_response.cache_status,
                evidence_headers=probe_response.headers,
                timestamp=time.strftime("%Y-%m-%d %H:%M:%S")
            )

        return None
