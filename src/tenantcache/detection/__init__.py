"""Leakage Detection Engine with Canary-Based Invariant Verification."""

import time
from typing import Optional, Dict, List
from src.tenantcache.models import (
    Finding, LeakageType, Severity, Principal, Resource, ResponseRecord,
    CacheStatus, Visibility, Role
)
from src.tenantcache.oracle import SecurityOracle, AuthDecision


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
