"""Research Evaluation Engine: Benchmark Harness, Baselines, and Quantitative Metrics."""

import time
from typing import List, Dict, Any, Tuple
from src.tenantcache.models import BenchmarkResult, Finding, LeakageType, Severity, Visibility
from src.tenantcache.simulator import TenantSimulator
from src.tenantcache.oracle import SecurityOracle, AuthDecision
from src.tenantcache.detection import LeakageDetector
from src.tenantcache.generator import RequestGenerator, TestSequence
from src.tenantcache.differential import DifferentialRunner
from src.tenantcache.cache import ProxyCacheSimulator
from lab.application.database import lab_db


class BenchmarkSuite:
    """Manages systematic experimental evaluation across configurations and baseline approaches."""

    def __init__(self, seed: int = 42):
        self.seed = seed
        self.sim = TenantSimulator(seed=seed)
        lab_db.simulator = self.sim
        self.oracle = SecurityOracle(self.sim.resources)
        self.detector = LeakageDetector(self.oracle, self.sim.canary_registry, self.sim.resources)
        self.generator = RequestGenerator(self.sim)

    def _generate_test_scenarios(self) -> List[Tuple[TestSequence, bool]]:
        """Generates a comprehensive matrix of test scenarios with ground-truth vulnerability expectations.
        
        Returns: List of (sequence, is_vulnerable_in_v1)
        """
        scenarios = []

        # P_Alice (Acme Admin), P_Alex (Acme Std), P_Bob (Beta Admin), P_Brian (Beta Std)
        p_alice = self.sim.get_principal("user_alice")
        p_alex = self.sim.get_principal("user_alex")
        p_bob = self.sim.get_principal("user_bob")
        p_brian = self.sim.get_principal("user_brian")

        # 1. Cross-Tenant: Alice (Acme) -> Bob (Beta) on Acme Dashboard (Vulnerable in V1)
        res_acme_dash = self.sim.get_resource("res_acme_dashboard")
        scenarios.append((self.generator.generate_cross_tenant_sequence(p_alice, p_bob, res_acme_dash), True))

        # 2. Cross-Tenant Reverse: Bob (Beta) -> Alice (Acme) on Beta Dashboard (Vulnerable in V1)
        res_beta_dash = self.sim.get_resource("res_beta_dashboard")
        scenarios.append((self.generator.generate_cross_tenant_sequence(p_bob, p_alice, res_beta_dash), True))

        # 3. Cross-Tenant Invoice: Alice (Acme) -> Brian (Beta) on Acme Invoice (Vulnerable in V1)
        res_acme_inv = self.sim.get_resource("res_acme_invoice_101")
        scenarios.append((self.generator.generate_cross_tenant_sequence(p_alice, p_brian, res_acme_inv), True))

        # 4. Cross-User: Alice (Acme) -> Alex (Acme) on Alice's Private Profile (Vulnerable in V1, V2)
        res_alice_prof = self.sim.get_resource("res_alice_profile")
        scenarios.append((self.generator.generate_cross_user_sequence(p_alice, p_alex, res_alice_prof), True))

        # 5. Privilege Boundary: Alice (Admin) -> Alex (Std User) on Admin Audit Logs (Vulnerable in V1, V2)
        res_admin_logs = self.sim.get_resource("res_acme_admin_logs")
        scenarios.append((self.generator.generate_privilege_sequence(p_alice, p_alex, res_admin_logs), True))

        # 6. Stateful Revocation: Alex queries project -> Revoked in origin -> Re-queries (Vulnerable in V4)
        res_project = self.sim.get_resource("res_acme_project_alpha")
        scenarios.append((self.generator.generate_revocation_sequence(p_alex, res_project), True))

        # 7. Public Resource Control: Alice queries -> Bob queries Public Guidelines (SAFE: No leak)
        res_public = self.sim.get_resource("res_pub_guideline")
        scenarios.append((self.generator.generate_cross_tenant_sequence(p_alice, p_bob, res_public), False))

        # 8. Intra-Tenant Legitimate Sharing: Alice queries Acme Dashboard -> Alex queries Acme Dashboard (SAFE)
        scenarios.append((self.generator.generate_cross_user_sequence(p_alice, p_alex, res_acme_dash), False))

        # 9. Header Spoofing: Bob queries Acme Dashboard with forged X-Tenant-ID (Vulnerable in V3)
        scenarios.append((self.generator.generate_header_spoofing_sequence(p_alice, p_bob, res_acme_dash), True))

        return scenarios

    def run_baseline_a_single_endpoint(self, config_archetype: str = "V1_MISSING_TENANT_KEY") -> BenchmarkResult:
        """Baseline A: Conventional Endpoint Testing.
        Tests endpoints in isolation without cross-identity cache priming sequences.
        """
        start_time = time.time()
        lab_db.reset()
        cache_sim = ProxyCacheSimulator(config_archetype=config_archetype)
        runner = DifferentialRunner(self.oracle, self.detector, cache_simulator=cache_sim)
        scenarios = self._generate_test_scenarios()

        tp = fp = tn = fn = 0
        findings = []

        vuln_archetype_map = {
            "V1_MISSING_TENANT_KEY": {"CROSS_TENANT", "CROSS_USER", "PRIVILEGE_BOUNDARY", "STALE_REVOCATION", "CACHE_KEY_SPOOFING"},
            "V2_MISSING_USER_AUTH": {"CROSS_USER", "PRIVILEGE_BOUNDARY", "STALE_REVOCATION", "CACHE_KEY_SPOOFING"},
            "V3_UNVALIDATED_HEADER": {"CACHE_KEY_SPOOFING", "CROSS_USER", "PRIVILEGE_BOUNDARY", "STALE_REVOCATION"},
            "V4_STALE_REVOCATION": {"STALE_REVOCATION"},
            "V5_ERRONEOUS_PUBLIC": {"CROSS_TENANT", "CROSS_USER", "PRIVILEGE_BOUNDARY", "STALE_REVOCATION", "CACHE_KEY_SPOOFING"},
            "V6_NORMALIZATION": {"CROSS_TENANT", "CROSS_USER", "PRIVILEGE_BOUNDARY", "STALE_REVOCATION", "CACHE_KEY_SPOOFING"},
            "SECURE_S1_STRICT_PRIVATE": set(),
            "SECURE_S2_IDENTITY_KEYED": set(),
        }
        active_vulns = vuln_archetype_map.get(config_archetype, set())

        for seq, _ in scenarios:
            probe_step = next((req for desc, req in seq.steps if "probe" in req.step_name), seq.steps[-1][1])
            if seq.category == "STALE_REVOCATION":
                oracle_decision = AuthDecision.DENY
            else:
                oracle_decision = self.oracle.evaluate(probe_step.principal, seq.resource)
            is_vulnerable = (seq.category in active_vulns) and (oracle_decision == AuthDecision.DENY)

            # Baseline A only runs the probe request in isolation against a cold cache (no prior warming)
            cache_sim.purge_all()
            resp = runner.execute_request(probe_step)

            finding = self.detector.evaluate_response(
                principal=probe_step.principal,
                target_resource=seq.resource,
                response=resp,
                step_name=probe_step.step_name,
                sequence_category=seq.category
            )

            detected = finding is not None
            if detected:
                findings.append(finding)
                if is_vulnerable:
                    tp += 1
                else:
                    fp += 1
            else:
                if is_vulnerable:
                    fn += 1
                else:
                    tn += 1

        duration = max(time.time() - start_time, 0.001)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        accuracy = (tp + tn) / len(scenarios) if scenarios else 0.0

        return BenchmarkResult(
            framework_name="Baseline A (Stateless Endpoint Testing)",
            mode=config_archetype,
            total_scenarios=len(scenarios),
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1_score=round(f1, 4),
            accuracy=round(accuracy, 4),
            total_requests=runner.total_requests,
            duration_seconds=round(duration, 4),
            requests_per_second=round(runner.total_requests / duration, 2),
            findings_count=len(findings),
            findings=findings
        )

    def run_baseline_b_token_substitution(self, config_archetype: str = "V1_MISSING_TENANT_KEY") -> BenchmarkResult:
        """Baseline B: Simple Token Substitution.
        Substitutes tokens between users, but does not manipulate cache states or revocation lifecycles.
        """
        start_time = time.time()
        lab_db.reset()
        cache_sim = ProxyCacheSimulator(config_archetype=config_archetype)
        runner = DifferentialRunner(self.oracle, self.detector, cache_simulator=cache_sim)
        scenarios = self._generate_test_scenarios()

        tp = fp = tn = fn = 0
        findings = []

        vuln_archetype_map = {
            "V1_MISSING_TENANT_KEY": {"CROSS_TENANT", "CROSS_USER", "PRIVILEGE_BOUNDARY", "STALE_REVOCATION", "CACHE_KEY_SPOOFING"},
            "V2_MISSING_USER_AUTH": {"CROSS_USER", "PRIVILEGE_BOUNDARY", "STALE_REVOCATION", "CACHE_KEY_SPOOFING"},
            "V3_UNVALIDATED_HEADER": {"CACHE_KEY_SPOOFING", "CROSS_USER", "PRIVILEGE_BOUNDARY", "STALE_REVOCATION"},
            "V4_STALE_REVOCATION": {"STALE_REVOCATION"},
            "V5_ERRONEOUS_PUBLIC": {"CROSS_TENANT", "CROSS_USER", "PRIVILEGE_BOUNDARY", "STALE_REVOCATION", "CACHE_KEY_SPOOFING"},
            "V6_NORMALIZATION": {"CROSS_TENANT", "CROSS_USER", "PRIVILEGE_BOUNDARY", "STALE_REVOCATION", "CACHE_KEY_SPOOFING"},
            "SECURE_S1_STRICT_PRIVATE": set(),
            "SECURE_S2_IDENTITY_KEYED": set(),
        }
        active_vulns = vuln_archetype_map.get(config_archetype, set())

        for seq, _ in scenarios:
            probe_step = next((req for desc, req in seq.steps if "probe" in req.step_name), seq.steps[-1][1])
            if seq.category == "STALE_REVOCATION":
                oracle_decision = AuthDecision.DENY
            else:
                oracle_decision = self.oracle.evaluate(probe_step.principal, seq.resource)
            is_vulnerable = (seq.category in active_vulns) and (oracle_decision == AuthDecision.DENY)

            # Baseline B executes steps, but does not reset cache or simulate origin revocation transitions
            for desc, req in seq.steps:
                resp = runner.execute_request(req)
                if "probe" in req.step_name:
                    finding = self.detector.evaluate_response(
                        principal=req.principal,
                        target_resource=seq.resource,
                        response=resp,
                        step_name=req.step_name,
                        sequence_category=seq.category
                    )
                    detected = finding is not None
                    # Revocation test will fail in Baseline B because revocation hook was not called
                    if detected:
                        findings.append(finding)
                        if is_vulnerable:
                            tp += 1
                        else:
                            fp += 1
                    else:
                        if is_vulnerable:
                            fn += 1
                        else:
                            tn += 1

        duration = max(time.time() - start_time, 0.001)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0.0
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0

        return BenchmarkResult(
            framework_name="Baseline B (Simple Identity Substitution)",
            mode=config_archetype,
            total_scenarios=len(scenarios),
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1_score=round(f1, 4),
            accuracy=round(accuracy, 4),
            total_requests=runner.total_requests,
            duration_seconds=round(duration, 4),
            requests_per_second=round(runner.total_requests / duration, 2),
            findings_count=len(findings),
            findings=findings
        )

    def run_tenantcache(self, config_archetype: str = "V1_MISSING_TENANT_KEY") -> BenchmarkResult:
        """TenantCache: Full Stateful Differential Invariant Testing.
        Identity-aware sequences, deterministic cache-state control, origin revocation hooks,
        and canary-based ground-truth verification.
        """
        start_time = time.time()
        lab_db.reset()
        cache_sim = ProxyCacheSimulator(config_archetype=config_archetype)
        runner = DifferentialRunner(self.oracle, self.detector, cache_simulator=cache_sim)
        scenarios = self._generate_test_scenarios()

        tp = fp = tn = fn = 0
        findings = []

        def revocation_hook(res_id: str, user_id: str):
            lab_db.revoke_user_access(res_id, user_id)
            self.oracle.resources[res_id].is_revoked_for.add(user_id)
            self.oracle.resources[res_id].allowed_user_ids.discard(user_id)
            if "S2" in config_archetype:
                # S2 actively purges cached entries upon authorization revocation
                runner.cache_sim.purge_all()

        # Expected vulnerability profile by archetype
        vuln_archetype_map = {
            "V1_MISSING_TENANT_KEY": {"CROSS_TENANT", "CROSS_USER", "PRIVILEGE_BOUNDARY", "STALE_REVOCATION", "CACHE_KEY_SPOOFING"},
            "V2_MISSING_USER_AUTH": {"CROSS_USER", "PRIVILEGE_BOUNDARY", "STALE_REVOCATION", "CACHE_KEY_SPOOFING"},
            "V3_UNVALIDATED_HEADER": {"CACHE_KEY_SPOOFING", "CROSS_USER", "PRIVILEGE_BOUNDARY", "STALE_REVOCATION"},
            "V4_STALE_REVOCATION": {"STALE_REVOCATION"},
            "V5_ERRONEOUS_PUBLIC": {"CROSS_TENANT", "CROSS_USER", "PRIVILEGE_BOUNDARY", "STALE_REVOCATION", "CACHE_KEY_SPOOFING"},
            "V6_NORMALIZATION": {"CROSS_TENANT", "CROSS_USER", "PRIVILEGE_BOUNDARY", "STALE_REVOCATION", "CACHE_KEY_SPOOFING"},
            "SECURE_S1_STRICT_PRIVATE": set(),
            "SECURE_S2_IDENTITY_KEYED": set(),
        }

        active_vulns = vuln_archetype_map.get(config_archetype, set())

        for seq, raw_is_vuln in scenarios:
            probe_step = next((req for desc, req in seq.steps if "probe" in req.step_name), seq.steps[-1][1])
            if seq.category == "STALE_REVOCATION":
                oracle_decision = AuthDecision.DENY
            else:
                oracle_decision = self.oracle.evaluate(probe_step.principal, seq.resource)

            # Ground-truth vulnerability: Archetype collides on this category AND Oracle denies access
            is_vuln = (seq.category in active_vulns) and (oracle_decision == AuthDecision.DENY)

            seq_findings = runner.run_sequence(seq, on_revocation_hook=revocation_hook)
            detected = len(seq_findings) > 0

            if detected:
                findings.extend(seq_findings)
                if is_vuln:
                    tp += 1
                else:
                    fp += 1
            else:
                if is_vuln:
                    fn += 1
                else:
                    tn += 1

        duration = max(time.time() - start_time, 0.001)
        precision = tp / (tp + fp) if (tp + fp) > 0 else 1.0
        recall = tp / (tp + fn) if (tp + fn) > 0 else (1.0 if not active_vulns else 0.0)
        f1 = (2 * precision * recall) / (precision + recall) if (precision + recall) > 0 else 0.0
        accuracy = (tp + tn) / len(scenarios) if scenarios else 0.0

        return BenchmarkResult(
            framework_name="TenantCache (Stateful Differential Verification)",
            mode=config_archetype,
            total_scenarios=len(scenarios),
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1_score=round(f1, 4),
            accuracy=round(accuracy, 4),
            total_requests=runner.total_requests,
            duration_seconds=round(duration, 4),
            requests_per_second=round(runner.total_requests / duration, 2),
            findings_count=len(findings),
            findings=findings
        )
