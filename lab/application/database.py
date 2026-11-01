"""Database layer for the Multi-Tenant Lab Target Application."""

from typing import Dict, Any, Optional
from src.tenantcache.simulator import TenantSimulator


class LabDatabase:
    """Manages the synthetic multi-tenant database state for the lab environment."""

    def __init__(self, seed: int = 42):
        self.seed = seed
        self.simulator = TenantSimulator(seed=seed)
        self.revoked_tokens: set[str] = set()

    def reset(self, sim: Optional[TenantSimulator] = None):
        """Resets database to initial seeded state."""
        if sim is not None:
            self.simulator = sim
        else:
            self.simulator = TenantSimulator(seed=self.seed)
        self.revoked_tokens.clear()

    def get_user_by_token(self, token: str) -> Optional[Dict[str, Any]]:
        if token in self.revoked_tokens:
            return None
        # Format: "TOKEN_<tenant_id>_<USERNAME>_SECURE_SIG"
        for p in self.simulator.principals.values():
            if p.auth_token == token:
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


# Global singleton instance for the lab app
lab_db = LabDatabase()
