"""Tenant Simulator module: generates synthetic multi-tenant structures, resources, and canaries."""

import zlib
import uuid
from typing import Dict, List, Tuple
from src.tenantcache.models import Tenant, User, Resource, Principal, Role, Visibility


class TenantSimulator:
    """Simulates a multi-tenant enterprise universe with synthetic users, resources, and canaries."""

    def __init__(self, seed: int = 42):
        self.seed = seed
        self.tenants: Dict[str, Tenant] = {}
        self.users: Dict[str, User] = {}
        self.principals: Dict[str, Principal] = {}
        self.resources: Dict[str, Resource] = {}
        self.canary_registry: Dict[str, str] = {}  # canary_token -> resource_id
        self._initialize_universe()

    def _generate_canary(self, tenant_id: str, resource_id: str, field: str) -> str:
        import hashlib
        unique_id = hashlib.sha256(f"{self.seed}:{tenant_id}:{resource_id}:{field}".encode("utf-8")).hexdigest()[:12]
        crc = hex(zlib.crc32(f"{tenant_id}:{resource_id}:{field}".encode("utf-8")) & 0xFFFFFFFF)[2:]
        token = f"TC_CANARY_{unique_id}_{crc.upper()}"
        return token

    def _initialize_universe(self):
        # 1. Create Tenants
        t_acme = Tenant(id="tenant_acme", name="Acme Corporation", slug="acme")
        t_beta = Tenant(id="tenant_beta", name="Beta Dynamics", slug="beta")
        t_gamma = Tenant(id="tenant_gamma", name="Gamma Industries", slug="gamma")
        for t in [t_acme, t_beta, t_gamma]:
            self.tenants[t.id] = t

        # 2. Create Users for each Tenant
        # Acme: Alice (Admin), Alex (Standard)
        u_alice = User(id="user_alice", tenant_id="tenant_acme", username="alice", role=Role.ADMIN, email="alice@acme.test")
        u_alex = User(id="user_alex", tenant_id="tenant_acme", username="alex", role=Role.STANDARD_USER, email="alex@acme.test")

        # Beta: Bob (Admin), Brian (Standard)
        u_bob = User(id="user_bob", tenant_id="tenant_beta", username="bob", role=Role.ADMIN, email="bob@beta.test")
        u_brian = User(id="user_brian", tenant_id="tenant_beta", username="brian", role=Role.STANDARD_USER, email="brian@beta.test")

        # Gamma: Charlie (Standard)
        u_charlie = User(id="user_charlie", tenant_id="tenant_gamma", username="charlie", role=Role.STANDARD_USER, email="charlie@gamma.test")

        for u in [u_alice, u_alex, u_bob, u_brian, u_charlie]:
            self.users[u.id] = u
            p = Principal(
                user_id=u.id,
                username=u.username,
                tenant_id=u.tenant_id,
                role=u.role,
                auth_token=f"TOKEN_{u.tenant_id}_{u.username.upper()}_SECURE_SIG",
                headers={
                    "Authorization": f"Bearer TOKEN_{u.tenant_id}_{u.username.upper()}_SECURE_SIG",
                    "X-Tenant-ID": u.tenant_id,
                },
                cookies={"session_id": f"sess_{u.tenant_id}_{u.username}"}
            )
            self.principals[u.id] = p

        # 3. Create Resources across Visibility spectrum
        # (A) Public Guidelines (legitimately shareable across all tenants)
        pub_canary = "TC_PUBLIC_DOC_GENERAL_COMPLIANCE_2026"
        res_public_doc = Resource(
            id="res_pub_guideline",
            tenant_id="SYSTEM",
            owner_id="SYSTEM",
            name="Public Security Guidelines",
            endpoint_path="/api/v1/public/docs/guidelines",
            visibility=Visibility.PUBLIC,
            canary_token=pub_canary,
            payload={"title": "Public Security Guidelines", "content": f"Official guidelines. Public Token: {pub_canary}"},
        )
        self.resources[res_public_doc.id] = res_public_doc
        self.canary_registry[pub_canary] = res_public_doc.id

        # (B) Acme Tenant Dashboard (Tenant Shared)
        acme_dash_canary = self._generate_canary("tenant_acme", "dash", "kpi")
        res_acme_dash = Resource(
            id="res_acme_dashboard",
            tenant_id="tenant_acme",
            owner_id="user_alice",
            name="Acme Quarterly Dashboard",
            endpoint_path="/api/v1/tenant/dashboard",
            visibility=Visibility.TENANT_SHARED,
            canary_token=acme_dash_canary,
            payload={"tenant": "tenant_acme", "revenue_target": "$42M", "secret_kpi": acme_dash_canary},
            allowed_user_ids={"user_alice", "user_alex"},
            allowed_roles={Role.ADMIN, Role.STANDARD_USER}
        )
        self.resources[res_acme_dash.id] = res_acme_dash
        self.canary_registry[acme_dash_canary] = res_acme_dash.id

        # (C) Beta Tenant Dashboard (Tenant Shared)
        beta_dash_canary = self._generate_canary("tenant_beta", "dash", "kpi")
        res_beta_dash = Resource(
            id="res_beta_dashboard",
            tenant_id="tenant_beta",
            owner_id="user_bob",
            name="Beta Quarterly Dashboard",
            endpoint_path="/api/v1/tenant/dashboard",
            visibility=Visibility.TENANT_SHARED,
            canary_token=beta_dash_canary,
            payload={"tenant": "tenant_beta", "revenue_target": "$18M", "secret_kpi": beta_dash_canary},
            allowed_user_ids={"user_bob", "user_brian"},
            allowed_roles={Role.ADMIN, Role.STANDARD_USER}
        )
        self.resources[res_beta_dash.id] = res_beta_dash
        self.canary_registry[beta_dash_canary] = res_beta_dash.id

        # (D) Acme Invoices (Tenant Invoices: /api/v1/tenant/invoices/inv-101)
        acme_inv_canary = self._generate_canary("tenant_acme", "inv-101", "invoice_sum")
        res_acme_inv = Resource(
            id="res_acme_invoice_101",
            tenant_id="tenant_acme",
            owner_id="user_alice",
            name="Acme Master Invoice 101",
            endpoint_path="/api/v1/tenant/invoices/inv-101",
            visibility=Visibility.TENANT_SHARED,
            canary_token=acme_inv_canary,
            payload={"invoice_id": "inv-101", "amount": "$890,000", "confidential_code": acme_inv_canary},
            allowed_user_ids={"user_alice", "user_alex"},
            allowed_roles={Role.ADMIN, Role.STANDARD_USER}
        )
        self.resources[res_acme_inv.id] = res_acme_inv
        self.canary_registry[acme_inv_canary] = res_acme_inv.id

        # (E) Alice's Private Profile (User Private)
        alice_prof_canary = self._generate_canary("tenant_acme", "prof_alice", "ssn")
        res_alice_profile = Resource(
            id="res_alice_profile",
            tenant_id="tenant_acme",
            owner_id="user_alice",
            name="Alice Executive Profile",
            endpoint_path="/api/v1/user/profile",
            visibility=Visibility.USER_PRIVATE,
            canary_token=alice_prof_canary,
            payload={"user": "alice", "ssn_last4": "8812", "vault_secret": alice_prof_canary},
            allowed_user_ids={"user_alice"},
            allowed_roles={Role.ADMIN}
        )
        self.resources[res_alice_profile.id] = res_alice_profile
        self.canary_registry[alice_prof_canary] = res_alice_profile.id

        # (F) Alex's Private Profile (User Private)
        alex_prof_canary = self._generate_canary("tenant_acme", "prof_alex", "ssn")
        res_alex_profile = Resource(
            id="res_alex_profile",
            tenant_id="tenant_acme",
            owner_id="user_alex",
            name="Alex User Profile",
            endpoint_path="/api/v1/user/profile",
            visibility=Visibility.USER_PRIVATE,
            canary_token=alex_prof_canary,
            payload={"user": "alex", "ssn_last4": "1244", "vault_secret": alex_prof_canary},
            allowed_user_ids={"user_alex"},
            allowed_roles={Role.STANDARD_USER}
        )
        self.resources[res_alex_profile.id] = res_alex_profile
        self.canary_registry[alex_prof_canary] = res_alex_profile.id

        # (G) Alice's Private Admin Audit Logs (/api/v1/admin/audit-logs)
        alice_admin_canary = self._generate_canary("tenant_acme", "audit", "security_key")
        res_admin_logs = Resource(
            id="res_acme_admin_logs",
            tenant_id="tenant_acme",
            owner_id="user_alice",
            name="Acme Admin Audit Logs",
            endpoint_path="/api/v1/admin/audit-logs",
            visibility=Visibility.USER_PRIVATE,
            canary_token=alice_admin_canary,
            payload={"admin": "alice", "security_events": ["root_key_rotate"], "secret_token": alice_admin_canary},
            allowed_user_ids={"user_alice"},
            allowed_roles={Role.ADMIN}
        )
        self.resources[res_admin_logs.id] = res_admin_logs
        self.canary_registry[alice_admin_canary] = res_admin_logs.id

        # (H) Shared Project with Revocable Access (/api/v1/shared/projects/proj-alpha)
        # Initially granted to Alice and Alex; Alex will have access revoked dynamically!
        proj_canary = self._generate_canary("tenant_acme", "proj-alpha", "intellectual_prop")
        res_shared_project = Resource(
            id="res_acme_project_alpha",
            tenant_id="tenant_acme",
            owner_id="user_alice",
            name="Project Alpha R&D Blueprint",
            endpoint_path="/api/v1/shared/projects/proj-alpha",
            visibility=Visibility.TENANT_SHARED,
            canary_token=proj_canary,
            payload={"project": "Alpha", "patent_pending": proj_canary, "status": "CONFIDENTIAL"},
            allowed_user_ids={"user_alice", "user_alex"},
            allowed_roles={Role.ADMIN, Role.STANDARD_USER},
            is_revoked_for=set()
        )
        self.resources[res_shared_project.id] = res_shared_project
        self.canary_registry[proj_canary] = res_shared_project.id

    def get_principal(self, user_id: str) -> Principal:
        return self.principals[user_id]

    def get_resource(self, resource_id: str) -> Resource:
        return self.resources[resource_id]

    def revoke_access(self, resource_id: str, user_id: str):
        """Simulate dynamic revocation in the origin security state."""
        if resource_id in self.resources:
            self.resources[resource_id].allowed_user_ids.discard(user_id)
            self.resources[resource_id].is_revoked_for.add(user_id)
