"""Request Generation Engine for Identity-Aware Differential Testing."""

from typing import List, Dict, Any, Tuple
from tenantcache.models import Principal, Resource, RequestSpec, Role, Visibility
from tenantcache.simulator import TenantSimulator


class TestSequence:
    """Represents an ordered execution sequence of requests across identities and cache states."""
    def __init__(self, name: str, category: str, description: str, resource: Resource):
        self.name = name
        self.category = category
        self.description = description
        self.resource = resource
        self.steps: List[Tuple[str, RequestSpec]] = []  # (step_description, request_spec)

    def add_step(self, description: str, request: RequestSpec):
        self.steps.append((description, request))


class RequestGenerator:
    """Generates deterministic, bounded differential request sequences."""

    def __init__(self, simulator: TenantSimulator):
        self.sim = simulator

    def build_request(
        self,
        principal: Principal,
        url_path: str,
        method: str = "GET",
        custom_headers: Dict[str, str] = None,
        query_params: Dict[str, str] = None,
        body: Any = None,
        step_name: str = "probe"
    ) -> RequestSpec:
        headers = principal.headers.copy()
        if custom_headers:
            headers.update(custom_headers)
        
        return RequestSpec(
            method=method,
            url_path=url_path,
            principal=principal,
            headers=headers,
            query_params=query_params or {},
            body=body,
            step_name=step_name
        )

    def generate_cross_tenant_sequence(self, victim_p: Principal, attacker_p: Principal, resource: Resource) -> TestSequence:
        """Sequence: Victim queries and warms cache -> Attacker queries the same endpoint."""
        seq = TestSequence(
            name=f"CrossTenant_{victim_p.tenant_id}_to_{attacker_p.tenant_id}_{resource.id}",
            category="CROSS_TENANT",
            description=f"Verify if {attacker_p.identifier()} can read {resource.name} belonging to {victim_p.identifier()} via cache.",
            resource=resource
        )
        # Step 1: Victim queries resource (Cold Cache -> Warm Cache)
        req_victim = self.build_request(victim_p, resource.endpoint_path, step_name="warm_cache")
        seq.add_step("Victim authorized access (primes cache)", req_victim)

        # Step 2: Attacker queries resource (Warm Cache)
        req_attacker = self.build_request(attacker_p, resource.endpoint_path, step_name="cross_tenant_probe")
        seq.add_step("Attacker unauthorized access (checks cache isolation)", req_attacker)

        return seq

    def generate_cross_user_sequence(self, user_a: Principal, user_b: Principal, resource: Resource) -> TestSequence:
        """Sequence: User A queries their private resource -> User B within same tenant queries it."""
        seq = TestSequence(
            name=f"CrossUser_{user_a.username}_to_{user_b.username}_{resource.id}",
            category="CROSS_USER",
            description=f"Verify if {user_b.identifier()} can read private resource of {user_a.identifier()}.",
            resource=resource
        )
        req_a = self.build_request(user_a, resource.endpoint_path, step_name="warm_user_cache")
        seq.add_step("User A queries private profile (primes cache)", req_a)

        req_b = self.build_request(user_b, resource.endpoint_path, step_name="cross_user_probe")
        seq.add_step("User B queries User A profile endpoint (checks user isolation)", req_b)

        return seq

    def generate_privilege_sequence(self, admin_p: Principal, std_p: Principal, resource: Resource) -> TestSequence:
        """Sequence: Admin queries admin-only resource -> Standard user queries it."""
        seq = TestSequence(
            name=f"Privilege_{admin_p.username}_to_{std_p.username}_{resource.id}",
            category="PRIVILEGE_BOUNDARY",
            description=f"Verify if {std_p.identifier()} can access {resource.name} after admin access.",
            resource=resource
        )
        req_admin = self.build_request(admin_p, resource.endpoint_path, step_name="warm_admin_cache")
        seq.add_step("Admin accesses privileged resource (primes cache)", req_admin)

        req_std = self.build_request(std_p, resource.endpoint_path, step_name="privilege_probe")
        seq.add_step("Standard user queries privileged endpoint", req_std)

        return seq

    def generate_revocation_sequence(self, principal: Principal, resource: Resource) -> TestSequence:
        """Sequence: User queries allowed resource -> Access is revoked at origin -> User re-queries."""
        seq = TestSequence(
            name=f"Revocation_{principal.username}_{resource.id}",
            category="STALE_REVOCATION",
            description=f"Verify if {principal.identifier()} can still access {resource.name} after access revocation.",
            resource=resource
        )
        # Step 1: Legitimate query (Cold -> Warm)
        req_initial = self.build_request(principal, resource.endpoint_path, step_name="initial_authorized_access")
        seq.add_step("Initial authorized query (primes cache)", req_initial)

        # Step 2: Access is revoked in DB (executed dynamically during runner)
        # Step 3: Re-query by the same principal
        req_post_revoke = self.build_request(principal, resource.endpoint_path, step_name="post_revocation_probe")
        seq.add_step("Post-revocation query (evaluates revocation lag)", req_post_revoke)

        return seq

    def generate_header_spoofing_sequence(self, victim_p: Principal, attacker_p: Principal, resource: Resource) -> TestSequence:
        """Sequence: Attacker supplies forged X-Tenant-ID matching victim's tenant."""
        seq = TestSequence(
            name=f"HeaderSpoofing_{attacker_p.username}_spoofs_{victim_p.tenant_id}_{resource.id}",
            category="CACHE_KEY_SPOOFING",
            description=f"Verify if forging X-Tenant-ID to {victim_p.tenant_id} extracts or pollutes cached data.",
            resource=resource
        )
        # Step 1: Victim warms legitimate cache
        req_victim = self.build_request(victim_p, resource.endpoint_path, step_name="victim_warm")
        seq.add_step("Victim warms cache with legitimate credentials", req_victim)

        # Step 2: Attacker queries with their own auth token but victim's X-Tenant-ID header
        forged_headers = {"X-Tenant-ID": victim_p.tenant_id}
        req_spoofed = self.build_request(
            attacker_p,
            resource.endpoint_path,
            custom_headers=forged_headers,
            step_name="header_spoof_probe"
        )
        seq.add_step("Attacker queries with forged X-Tenant-ID header", req_spoofed)

        return seq
