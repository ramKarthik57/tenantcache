"""Independent Ground-Truth Security Authorization Oracle."""

from enum import Enum
from typing import Optional, Dict
from src.tenantcache.models import Principal, Resource, RequestSpec, Visibility, Role


class AuthDecision(str, Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"


class SecurityOracle:
    """Independent ground-truth access control evaluator.
    
    Determines whether a principal P has legitimate authorization to access resource R
    independent of any HTTP status codes, headers, or caching status returned by the target.
    """

    def __init__(self, resources: Dict[str, Resource]):
        self.resources = resources

    def evaluate(self, principal: Principal, resource: Resource, request: Optional[RequestSpec] = None) -> AuthDecision:
        """Evaluates A(P, R, Q) -> ALLOW | DENY."""
        # 1. Public resources are accessible by any principal (or anonymous)
        if resource.visibility == Visibility.PUBLIC:
            return AuthDecision.ALLOW

        # 2. Check if principal's access was specifically revoked
        if principal.user_id in resource.is_revoked_for:
            return AuthDecision.DENY

        # 3. Cross-Tenant boundary check: Must belong to the same tenant
        if principal.tenant_id != resource.tenant_id:
            return AuthDecision.DENY

        # 4. User-Private boundary check: Must be the resource owner
        if resource.visibility == Visibility.USER_PRIVATE:
            if principal.user_id != resource.owner_id:
                return AuthDecision.DENY

        # 5. Role and User permissions check
        if resource.allowed_roles and principal.role not in resource.allowed_roles:
            return AuthDecision.DENY

        if resource.allowed_user_ids and principal.user_id not in resource.allowed_user_ids:
            return AuthDecision.DENY

        return AuthDecision.ALLOW

    def evaluate_by_id(self, principal: Principal, resource_id: str, request: Optional[RequestSpec] = None) -> AuthDecision:
        if resource_id not in self.resources:
            return AuthDecision.DENY
        return self.evaluate(principal, self.resources[resource_id], request)
