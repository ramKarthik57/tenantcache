"""Tenant Simulator module: generates synthetic multi-tenant structures, resources, and canaries."""

import zlib
import hashlib
from typing import Dict, List, Tuple, Set
from tenantcache.models import Tenant, User, Resource, Principal, Role, Visibility


class TenantSimulator:
    """Simulates an expanded enterprise multi-tenant universe with synthetic users, resources, and canaries."""

    def __init__(self, seed: int = 42):
        self.seed = seed
        self.tenants: Dict[str, Tenant] = {}
        self.users: Dict[str, User] = {}
        self.principals: Dict[str, Principal] = {}
        self.resources: Dict[str, Resource] = {}
        self.canary_registry: Dict[str, str] = {}  # canary_token -> resource_id
        self._initialize_universe()

    def _generate_canary(self, tenant_id: str, resource_id: str, field: str) -> str:
        unique_id = hashlib.sha256(f"{self.seed}:{tenant_id}:{resource_id}:{field}".encode("utf-8")).hexdigest()[:12]
        crc = hex(zlib.crc32(f"{tenant_id}:{resource_id}:{field}".encode("utf-8")) & 0xFFFFFFFF)[2:]
        token = f"TC_CANARY_{unique_id}_{crc.upper()}"
        return token

    def _initialize_universe(self):
        # 1. Five Enterprise Tenants
        t_acme = Tenant(id="tenant_acme", name="Acme Corporation", slug="acme")
        t_beta = Tenant(id="tenant_beta", name="Beta Dynamics", slug="beta")
        t_gamma = Tenant(id="tenant_gamma", name="Gamma Industries", slug="gamma")
        t_delta = Tenant(id="tenant_delta", name="Delta Technologies", slug="delta")
        t_epsilon = Tenant(id="tenant_epsilon", name="Epsilon Logistics", slug="epsilon")

        for t in [t_acme, t_beta, t_gamma, t_delta, t_epsilon]:
            self.tenants[t.id] = t

        # 2. Ten Principals across Tenants and Roles
        user_specs = [
            ("user_alice", "tenant_acme", "alice", Role.ADMIN, "alice@acme.test"),
            ("user_alex", "tenant_acme", "alex", Role.STANDARD_USER, "alex@acme.test"),
            ("user_amanda", "tenant_acme", "amanda", Role.STANDARD_USER, "amanda@acme.test"),
            ("user_bob", "tenant_beta", "bob", Role.ADMIN, "bob@beta.test"),
            ("user_brian", "tenant_beta", "brian", Role.STANDARD_USER, "brian@beta.test"),
            ("user_charlie", "tenant_gamma", "charlie", Role.STANDARD_USER, "charlie@gamma.test"),
            ("user_clara", "tenant_gamma", "clara", Role.ADMIN, "clara@gamma.test"),
            ("user_david", "tenant_delta", "david", Role.ADMIN, "david@delta.test"),
            ("user_diana", "tenant_delta", "diana", Role.STANDARD_USER, "diana@delta.test"),
            ("user_eric", "tenant_epsilon", "eric", Role.GUEST, "eric@epsilon.test"),
        ]

        for u_id, t_id, uname, role, email in user_specs:
            u = User(id=u_id, tenant_id=t_id, username=uname, role=role, email=email)
            self.users[u.id] = u
            token = f"TOKEN_{t_id}_{uname.upper()}_SECURE_SIG"
            p = Principal(
                user_id=u.id,
                username=u.username,
                tenant_id=u.tenant_id,
                role=u.role,
                auth_token=token,
                headers={
                    "Authorization": f"Bearer {token}",
                    "X-Tenant-ID": u.tenant_id,
                },
                cookies={"session_id": f"sess_{u.tenant_id}_{u.username}"}
            )
            self.principals[u.id] = p

        # 3. Comprehensive Multi-Tenant Resource Catalog
        # (A) Public Guidelines and Public Terms (Visibility = PUBLIC)
        self._add_resource(
            res_id="res_pub_guideline",
            tenant_id="SYSTEM",
            owner_id="SYSTEM",
            name="Public Security Guidelines",
            endpoint_path="/api/v1/public/docs/guidelines",
            visibility=Visibility.PUBLIC,
            canary="TC_PUBLIC_DOC_GENERAL_COMPLIANCE_2026",
            payload={"title": "Public Security Guidelines", "token": "TC_PUBLIC_DOC_GENERAL_COMPLIANCE_2026", "content": "Official Public Compliance Guidelines"}
        )
        self._add_resource(
            res_id="res_pub_terms",
            tenant_id="SYSTEM",
            owner_id="SYSTEM",
            name="Public Terms of Service",
            endpoint_path="/api/v1/public/docs/terms",
            visibility=Visibility.PUBLIC,
            canary="TC_PUBLIC_TERMS_OF_SERVICE_V2",
            payload={"title": "Terms of Service", "token": "TC_PUBLIC_TERMS_OF_SERVICE_V2"}
        )

        # (B) Tenant Dashboards (Visibility = TENANT_SHARED)
        for t_id, owner_id in [
            ("tenant_acme", "user_alice"),
            ("tenant_beta", "user_bob"),
            ("tenant_gamma", "user_clara"),
            ("tenant_delta", "user_david")
        ]:
            c = self._generate_canary(t_id, "dash", "kpi")
            self._add_resource(
                res_id=f"res_{t_id.replace('tenant_', '')}_dashboard",
                tenant_id=t_id,
                owner_id=owner_id,
                name=f"{t_id.title()} Executive Dashboard",
                endpoint_path="/api/v1/tenant/dashboard",
                visibility=Visibility.TENANT_SHARED,
                canary=c,
                payload={"tenant": t_id, "kpi_metric": c},
                allowed_roles={Role.ADMIN, Role.STANDARD_USER}
            )

        # (C) Invoices and Financial Records (Visibility = TENANT_SHARED)
        inv_c1 = self._generate_canary("tenant_acme", "inv-101", "sum")
        self._add_resource(
            res_id="res_acme_invoice_101",
            tenant_id="tenant_acme",
            owner_id="user_alice",
            name="Acme Master Invoice 101",
            endpoint_path="/api/v1/tenant/invoices/inv-101",
            visibility=Visibility.TENANT_SHARED,
            canary=inv_c1,
            payload={"invoice_id": "inv-101", "amount": "$890,000", "code": inv_c1},
            allowed_roles={Role.ADMIN, Role.STANDARD_USER}
        )

        inv_c2 = self._generate_canary("tenant_beta", "inv-202", "sum")
        self._add_resource(
            res_id="res_beta_invoice_202",
            tenant_id="tenant_beta",
            owner_id="user_bob",
            name="Beta Enterprise Invoice 202",
            endpoint_path="/api/v1/tenant/invoices/inv-202",
            visibility=Visibility.TENANT_SHARED,
            canary=inv_c2,
            payload={"invoice_id": "inv-202", "amount": "$450,000", "code": inv_c2},
            allowed_roles={Role.ADMIN, Role.STANDARD_USER}
        )

        # (D) User Private Profiles (Visibility = USER_PRIVATE)
        for u_id, uname, t_id in [
            ("user_alice", "alice", "tenant_acme"),
            ("user_alex", "alex", "tenant_acme"),
            ("user_amanda", "amanda", "tenant_acme"),
            ("user_bob", "bob", "tenant_beta"),
            ("user_brian", "brian", "tenant_beta"),
            ("user_charlie", "charlie", "tenant_gamma"),
            ("user_david", "david", "tenant_delta")
        ]:
            c = self._generate_canary(t_id, f"prof_{uname}", "ssn")
            self._add_resource(
                res_id=f"res_{uname}_profile",
                tenant_id=t_id,
                owner_id=u_id,
                name=f"{uname.title()} Private Profile",
                endpoint_path="/api/v1/user/profile",
                visibility=Visibility.USER_PRIVATE,
                canary=c,
                payload={"username": uname, "ssn_vault": c},
                allowed_user_ids={u_id}
            )

        # (E) Admin Audit Logs (Visibility = USER_PRIVATE, Role = ADMIN)
        for t_id, admin_id in [
            ("tenant_acme", "user_alice"),
            ("tenant_beta", "user_bob"),
            ("tenant_gamma", "user_clara"),
            ("tenant_delta", "user_david")
        ]:
            c = self._generate_canary(t_id, "audit", "master_key")
            self._add_resource(
                res_id=f"res_{t_id.replace('tenant_', '')}_admin_logs",
                tenant_id=t_id,
                owner_id=admin_id,
                name=f"{t_id.title()} Root Audit Logs",
                endpoint_path="/api/v1/admin/audit-logs",
                visibility=Visibility.USER_PRIVATE,
                canary=c,
                payload={"admin": admin_id, "root_key": c},
                allowed_user_ids={admin_id},
                allowed_roles={Role.ADMIN}
            )

        # (F) Eight Revocable Shared Projects (Visibility = TENANT_SHARED with dynamic revocation)
        revocable_specs = [
            ("res_acme_project_alpha", "tenant_acme", "user_alice", "Project Alpha Stealth Blueprint", "/api/v1/shared/projects/proj-alpha", "blueprint", {"user_alice", "user_alex"}),
            ("res_beta_project_merger", "tenant_beta", "user_bob", "Project Titan M&A Dossier", "/api/v1/shared/projects/proj-titan", "merger", {"user_bob", "user_brian"}),
            ("res_gamma_project_ai", "tenant_gamma", "user_clara", "Project Neural Weight Matrix", "/api/v1/shared/projects/proj-neural", "ai_weights", {"user_clara", "user_charlie"}),
            ("res_delta_project_patent", "tenant_delta", "user_david", "Quantum Cryptography Patent Draft", "/api/v1/shared/projects/proj-quantum", "patent", {"user_david", "user_diana"}),
            ("res_acme_project_supply", "tenant_acme", "user_alice", "Project Supply Chain Logistics", "/api/v1/shared/projects/proj-supply", "supply", {"user_alice", "user_amanda"}),
            ("res_beta_project_audit", "tenant_beta", "user_bob", "Project Sovereign Ledger Audit", "/api/v1/shared/projects/proj-audit", "audit_sec", {"user_bob", "user_brian"}),
            ("res_gamma_project_cloud", "tenant_gamma", "user_clara", "Project Orbital Cloud Relay", "/api/v1/shared/projects/proj-cloud", "relay", {"user_clara", "user_charlie"}),
            ("res_delta_project_crypto", "tenant_delta", "user_david", "Project Post-Quantum Lattice Key", "/api/v1/shared/projects/proj-crypto", "lattice", {"user_david", "user_diana"}),
        ]

        for res_id, t_id, owner_id, name, path, canary_field, allowed_users in revocable_specs:
            c = self._generate_canary(t_id, res_id, canary_field)
            self._add_resource(
                res_id=res_id,
                tenant_id=t_id,
                owner_id=owner_id,
                name=name,
                endpoint_path=path,
                visibility=Visibility.TENANT_SHARED,
                canary=c,
                payload={"project_id": res_id, "project_name": name, "confidential_token": c},
                allowed_user_ids=allowed_users,
                allowed_roles={Role.ADMIN, Role.STANDARD_USER}
            )

    def _add_resource(
        self,
        res_id: str,
        tenant_id: str,
        owner_id: str,
        name: str,
        endpoint_path: str,
        visibility: Visibility,
        canary: str,
        payload: Dict,
        allowed_user_ids: Set[str] = None,
        allowed_roles: Set[Role] = None
    ):
        r = Resource(
            id=res_id,
            tenant_id=tenant_id,
            owner_id=owner_id,
            name=name,
            endpoint_path=endpoint_path,
            visibility=visibility,
            canary_token=canary,
            payload=payload,
            allowed_user_ids=allowed_user_ids or set(),
            allowed_roles=allowed_roles or set(),
            is_revoked_for=set()
        )
        self.resources[r.id] = r
        self.canary_registry[canary] = r.id

    def get_principal(self, user_id: str) -> Principal:
        return self.principals[user_id]

    def get_resource(self, resource_id: str) -> Resource:
        return self.resources[resource_id]

    def revoke_access(self, resource_id: str, user_id: str):
        if resource_id in self.resources:
            self.resources[resource_id].allowed_user_ids.discard(user_id)
            self.resources[resource_id].is_revoked_for.add(user_id)
