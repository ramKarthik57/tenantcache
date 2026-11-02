"""Independent Ground-Truth Security Authorization Oracle with Isolated Reference Ledgers."""

import copy
from enum import Enum
from typing import Optional, Dict, Union
from tenantcache.models import Principal, Resource, RequestSpec, Visibility, Role


class AuthDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class SecurityOracle:
    """Independent ground-truth access control evaluator.
    
    Maintains isolated reference policy ledgers (resources and principals) completely decoupled
    from the target application's mutable runtime database, proxy cache state, or fixtures.
    Evaluates whether a principal P has legitimate authorization to access resource R independent
    of HTTP status codes, headers, or caching status. Fails closed (DENY) for unknown resource
    or principal IDs and never consults external mutable objects.

    Trust Boundary Specification:
    - Principal fixtures represent declared test scenarios (adversary/victim testing inputs).
    - When initialized with an independent principal ledger, identities are validated against
      self.principals by ID, preventing caller-side forgery of principal attributes.
    - If the principal ledger is unavailable or empty, protected resource access strictly fails closed (DENY).
    - Resource attributes are evaluated exclusively from self.resources.
    """

    def __init__(self, resources: Dict[str, Resource], principals: Optional[Dict[str, Principal]] = None):
        # Maintain isolated deepcopy of expected authorization ledgers
        self.resources: Dict[str, Resource] = copy.deepcopy(resources)
        self.principals: Dict[str, Principal] = copy.deepcopy(principals) if principals is not None else {}

    def reset_ledger(self, resources: Dict[str, Resource], principals: Optional[Dict[str, Principal]] = None) -> None:
        """Restores independent reference ledgers from clean state."""
        self.resources = copy.deepcopy(resources)
        if principals is not None:
            self.principals = copy.deepcopy(principals)

    def record_revocation(self, resource_id: str, user_id: str) -> None:
        """Applies explicit revocation transition event to the independent policy ledger."""
        if resource_id in self.resources:
            res = self.resources[resource_id]
            res.is_revoked_for.add(user_id)
            res.allowed_user_ids.discard(user_id)

    def record_grant(self, resource_id: str, user_id: str) -> None:
        """Applies explicit permission grant event to the independent policy ledger."""
        if resource_id in self.resources:
            res = self.resources[resource_id]
            res.allowed_user_ids.add(user_id)
            res.is_revoked_for.discard(user_id)

    def evaluate(self, principal: Union[Principal, str], resource: Union[Resource, str], request: Optional[RequestSpec] = None) -> AuthDecision:
        """Evaluates A(P, R, Q) -> ALLOW | DENY strictly against the isolated reference ledgers.
        
        Guarantees complete state isolation: resolves resource and principal identities strictly
        via internal ledgers. Fails closed (DENY) if either resource or principal is unregistered
        or unknown. Never reads mutable attributes from any external caller-passed object.
        """
        # 1. Resolve Resource from private ledger
        res_id = resource.id if isinstance(resource, Resource) else str(resource)
        if res_id not in self.resources:
            return AuthDecision.DENY

        res = self.resources[res_id]

        # 2. Public resources are accessible by any principal (or anonymous)
        if res.visibility == Visibility.PUBLIC:
            return AuthDecision.ALLOW

        # 3. Resolve Principal from private ledger (Strict Fail-Closed)
        # If no principal ledger was provided or ledger is empty, protected access is strictly DENIED
        if not self.principals:
            return AuthDecision.DENY

        p_id = principal if isinstance(principal, str) else getattr(principal, "user_id", str(principal))
        if not p_id or p_id not in self.principals:
            return AuthDecision.DENY

        # Strictly bind to oracle's registered principal state; ignore external mutable attributes
        p = self.principals[p_id]

        # 4. Check if principal's access was specifically revoked in oracle ledger
        if p.user_id in res.is_revoked_for:
            return AuthDecision.DENY

        # 5. Cross-Tenant boundary check: Must belong to the same tenant
        if p.tenant_id != res.tenant_id:
            return AuthDecision.DENY

        # 6. User-Private boundary check: Must be the resource owner
        if res.visibility == Visibility.USER_PRIVATE:
            return AuthDecision.ALLOW if p.user_id == res.owner_id else AuthDecision.DENY

        # 7. Role-Restricted boundary check: Must possess required role
        if res.allowed_roles:
            if p.role not in res.allowed_roles:
                return AuthDecision.DENY

        # 8. Explicit User ACL check: If allowed_user_ids is specified
        if res.allowed_user_ids:
            return AuthDecision.ALLOW if p.user_id in res.allowed_user_ids else AuthDecision.DENY

        return AuthDecision.ALLOW
