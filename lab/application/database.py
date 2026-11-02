"""Database layer for the Multi-Tenant Lab Target Application with Full Lifecycle Management."""

from typing import Dict, Any, Optional
from tenantcache.simulator import TenantSimulator
from tenantcache.models import Role


class LabDatabase:
    """Manages the synthetic multi-tenant database state for the lab environment.
    Supports complete token and permission lifecycle: revocation, expiration,
    session invalidation, role mutation/downgrade, and dynamic resource deletion.
    """

    def __init__(self, seed: int = 42):
        self.seed = seed
        self.simulator = TenantSimulator(seed=seed)
        self.revoked_tokens: set[str] = set()
        self.expired_tokens: set[str] = set()
        self.invalidated_sessions: set[str] = set()

    def reset(self, sim: Optional[TenantSimulator] = None):
        """Resets database to initial seeded state."""
        if sim is not None:
            self.simulator = sim
        else:
            self.simulator = TenantSimulator(seed=self.seed)
        self.revoked_tokens.clear()
        self.expired_tokens.clear()
        self.invalidated_sessions.clear()

    def get_user_by_token(self, token: str) -> Optional[Dict[str, Any]]:
        if token in self.revoked_tokens or token in self.expired_tokens:
            return None
        # Format: "TOKEN_<tenant_id>_<USERNAME>_SECURE_SIG"
        for p in self.simulator.principals.values():
            if p.auth_token == token:
                if p.user_id in self.invalidated_sessions:
                    return None
                return {
                    "user_id": p.user_id,
                    "username": p.username,
                    "tenant_id": p.tenant_id,
                    "role": p.role.value
                }
        return None

    def get_resource(self, resource_id: str):
        return self.simulator.resources.get(resource_id)

    def revoke_user_access(self, resource_id: str, user_id: str):
        self.simulator.revoke_access(resource_id, user_id)

    def expire_token(self, token: str):
        self.expired_tokens.add(token)

    def invalidate_session(self, user_id: str):
        self.invalidated_sessions.add(user_id)

    def update_role(self, user_id: str, new_role: Role):
        if user_id in self.simulator.principals:
            self.simulator.principals[user_id].role = new_role

    def remove_tenant_member(self, user_id: str):
        if user_id in self.simulator.principals:
            self.simulator.principals[user_id].tenant_id = "tenant_evicted"

    def delete_resource(self, resource_id: str):
        if resource_id in self.simulator.resources:
            del self.simulator.resources[resource_id]


# Global singleton instance for the lab app
lab_db = LabDatabase()
