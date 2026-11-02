"""Research Evaluation Engine: Expanded Benchmark Corpus, Rigorous Statistical Modeling, and Fair Baselines."""

import time
import math
import json
import csv
import os
from statistics import NormalDist
from typing import List, Dict, Any, Tuple, Optional
from pydantic import BaseModel, Field
from tenantcache.models import Finding, LeakageType, Severity, Visibility, Principal, Resource, Role, RequestSpec
from tenantcache.simulator import TenantSimulator
from tenantcache.oracle import SecurityOracle, AuthDecision
from tenantcache.detection import LeakageDetector, OracleFreeDifferentialDetector
from tenantcache.generator import RequestGenerator, TestSequence
from tenantcache.differential import DifferentialRunner
from tenantcache.cache import ProxyCacheSimulator
from lab.application.database import lab_db


class ScenarioManifestRecord(BaseModel):
    scenario_id: str
    dataset_version: str
    archetype_category: str
    priming_principal: str
    probing_principal: str
    resource_id: str
    resource_visibility: str
    expected_authorization: str
    ground_truth_label: bool
    description: str


class StatisticalBenchmarkResult(BaseModel):
    framework_name: str
    mode: str
    dataset_version: str = "v1.1"
    total_scenarios: int
    true_positives: int
    false_positives: int
    true_negatives: int
    false_negatives: int
    precision: Optional[float] = None
    precision_ci_95: Optional[Tuple[float, float]] = None
    recall: Optional[float] = None
    recall_ci_95: Optional[Tuple[float, float]] = None
    f1_score: Optional[float] = None
    specificity: Optional[float] = None
    specificity_ci_95: Optional[Tuple[float, float]] = None
    accuracy: float = 0.0
    accuracy_ci_95: Optional[Tuple[float, float]] = None
    false_positive_rate: float = 0.0
    total_requests: int
    cache_resets: int = 0
    state_transitions: int = 0
    distinct_principals_covered: int = 0
    duration_seconds: float
    requests_per_second: float
    findings_count: int
    findings: List[Finding] = Field(default_factory=list)


def wilson_score_ci(successes: int, total: int, confidence: float = 0.95) -> Optional[Tuple[float, float]]:
    """Calculates Wilson score interval for binomial proportions.
    Returns None if total <= 0 (e.g. undefined precision/recall when denominator is 0).
    """
    if total <= 0:
        return None
    z = NormalDist().inv_cdf((1.0 + confidence) / 2.0)
    p_hat = successes / total
    denominator = 1.0 + (z ** 2) / total
    center = (p_hat + (z ** 2) / (2.0 * total)) / denominator
    spread = (z / denominator) * math.sqrt((p_hat * (1.0 - p_hat) / total) + ((z ** 2) / (4.0 * (total ** 2))))
    lower = max(0.0, center - spread)
    upper = min(1.0, center + spread)
    return (round(lower, 4), round(upper, 4))


class BenchmarkSuite:
    """Manages systematic experimental evaluation across configurations, expanded corpus, and baselines."""

    def __init__(self, seed: int = 42):
        self.seed = seed
        self.sim = TenantSimulator(seed=seed)
        lab_db.simulator = self.sim
        self.oracle = SecurityOracle(self.sim.resources, self.sim.principals)
        self.detector = LeakageDetector(self.oracle, self.sim.canary_registry, self.sim.resources)
        self.generator = RequestGenerator(self.sim)

    def generate_expanded_scenarios(self, version: str = "v1.1") -> List[Tuple[TestSequence, bool]]:
        """Generates test corpus:
        - v1.0: 54-scenario corpus (46 vulnerable positive, 8 negative controls).
        - v1.1: Reconciled & expanded 66-scenario corpus (46 positive, 20 negative with balanced controls).
        """
        scenarios = []

        # Principals
        p_alice = self.sim.get_principal("user_alice")      # Acme Admin
        p_alex = self.sim.get_principal("user_alex")        # Acme Std
        p_amanda = self.sim.get_principal("user_amanda")    # Acme Std
        p_bob = self.sim.get_principal("user_bob")          # Beta Admin
        p_brian = self.sim.get_principal("user_brian")      # Beta Std
        p_charlie = self.sim.get_principal("user_charlie")  # Gamma Std
        p_clara = self.sim.get_principal("user_clara")      # Gamma Admin
        p_david = self.sim.get_principal("user_david")      # Delta Admin
        p_diana = self.sim.get_principal("user_diana")      # Delta Std
        p_eric = self.sim.get_principal("user_eric")        # Epsilon Guest

        # ---------------------------------------------------------
        # 1. CROSS-TENANT SCENARIOS (14 Scenarios)
        # ---------------------------------------------------------
        res_acme_dash = self.sim.get_resource("res_acme_dashboard")
        res_beta_dash = self.sim.get_resource("res_beta_dashboard")
        res_gamma_dash = self.sim.get_resource("res_gamma_dashboard")
        res_delta_dash = self.sim.get_resource("res_delta_dashboard")

        scenarios.append((self.generator.generate_cross_tenant_sequence(p_alice, p_bob, res_acme_dash), True))
        scenarios.append((self.generator.generate_cross_tenant_sequence(p_bob, p_alice, res_beta_dash), True))
        scenarios.append((self.generator.generate_cross_tenant_sequence(p_clara, p_david, res_gamma_dash), True))
        scenarios.append((self.generator.generate_cross_tenant_sequence(p_david, p_charlie, res_delta_dash), True))
        scenarios.append((self.generator.generate_cross_tenant_sequence(p_alice, p_charlie, res_acme_dash), True))
        scenarios.append((self.generator.generate_cross_tenant_sequence(p_bob, p_diana, res_beta_dash), True))
        scenarios.append((self.generator.generate_cross_tenant_sequence(p_david, p_eric, res_delta_dash), True))

        # Invoices
        res_acme_inv = self.sim.get_resource("res_acme_invoice_101")
        res_beta_inv = self.sim.get_resource("res_beta_invoice_202")
        scenarios.append((self.generator.generate_cross_tenant_sequence(p_alice, p_brian, res_acme_inv), True))
        scenarios.append((self.generator.generate_cross_tenant_sequence(p_bob, p_alex, res_beta_inv), True))
        scenarios.append((self.generator.generate_cross_tenant_sequence(p_alice, p_david, res_acme_inv), True))
        scenarios.append((self.generator.generate_cross_tenant_sequence(p_bob, p_eric, res_beta_inv), True))
        scenarios.append((self.generator.generate_cross_tenant_sequence(p_alex, p_charlie, res_acme_inv), True))
        scenarios.append((self.generator.generate_cross_tenant_sequence(p_brian, p_diana, res_beta_inv), True))
        scenarios.append((self.generator.generate_cross_tenant_sequence(p_alice, p_eric, res_acme_dash), True))

        # ---------------------------------------------------------
        # 2. CROSS-USER PRIVATE SCENARIOS (10 Scenarios)
        # ---------------------------------------------------------
        res_prof_alice = self.sim.get_resource("res_alice_profile")
        res_prof_alex = self.sim.get_resource("res_alex_profile")
        res_prof_amanda = self.sim.get_resource("res_amanda_profile")
        res_prof_bob = self.sim.get_resource("res_bob_profile")
        res_prof_brian = self.sim.get_resource("res_brian_profile")
        res_prof_charlie = self.sim.get_resource("res_charlie_profile")
        res_prof_david = self.sim.get_resource("res_david_profile")

        scenarios.append((self.generator.generate_cross_user_sequence(p_alice, p_alex, res_prof_alice), True))
        scenarios.append((self.generator.generate_cross_user_sequence(p_alex, p_alice, res_prof_alex), True))
        scenarios.append((self.generator.generate_cross_user_sequence(p_alice, p_amanda, res_prof_alice), True))
        scenarios.append((self.generator.generate_cross_user_sequence(p_amanda, p_alex, res_prof_amanda), True))
        scenarios.append((self.generator.generate_cross_user_sequence(p_amanda, p_alice, res_prof_amanda), True))
        scenarios.append((self.generator.generate_cross_user_sequence(p_alex, p_amanda, res_prof_alex), True))
        scenarios.append((self.generator.generate_cross_user_sequence(p_bob, p_brian, res_prof_bob), True))
        scenarios.append((self.generator.generate_cross_user_sequence(p_brian, p_bob, res_prof_brian), True))
        scenarios.append((self.generator.generate_cross_user_sequence(p_charlie, p_clara, res_prof_charlie), True))
        scenarios.append((self.generator.generate_cross_user_sequence(p_david, p_diana, res_prof_david), True))

        # ---------------------------------------------------------
        # 3. PRIVILEGE BOUNDARY SCENARIOS (8 Scenarios)
        # ---------------------------------------------------------
        res_admin_acme = self.sim.get_resource("res_acme_admin_logs")
        res_admin_beta = self.sim.get_resource("res_beta_admin_logs")
        res_admin_gamma = self.sim.get_resource("res_gamma_admin_logs")
        res_admin_delta = self.sim.get_resource("res_delta_admin_logs")

        scenarios.append((self.generator.generate_privilege_sequence(p_alice, p_alex, res_admin_acme), True))
        scenarios.append((self.generator.generate_privilege_sequence(p_alice, p_amanda, res_admin_acme), True))
        scenarios.append((self.generator.generate_privilege_sequence(p_bob, p_brian, res_admin_beta), True))
        scenarios.append((self.generator.generate_privilege_sequence(p_clara, p_charlie, res_admin_gamma), True))
        scenarios.append((self.generator.generate_privilege_sequence(p_david, p_diana, res_admin_delta), True))
        scenarios.append((self.generator.generate_privilege_sequence(p_alice, p_eric, res_admin_acme), True))
        scenarios.append((self.generator.generate_privilege_sequence(p_bob, p_eric, res_admin_beta), True))
        scenarios.append((self.generator.generate_privilege_sequence(p_david, p_eric, res_admin_delta), True))

        # ---------------------------------------------------------
        # 4. EIGHT STATEFUL REVOCATION SCENARIOS (8 Distinct Projects & Users)
        # ---------------------------------------------------------
        r_rev1 = self.sim.get_resource("res_acme_project_alpha")
        r_rev2 = self.sim.get_resource("res_beta_project_merger")
        r_rev3 = self.sim.get_resource("res_gamma_project_ai")
        r_rev4 = self.sim.get_resource("res_delta_project_patent")
        r_rev5 = self.sim.get_resource("res_acme_project_supply")
        r_rev6 = self.sim.get_resource("res_beta_project_audit")
        r_rev7 = self.sim.get_resource("res_gamma_project_cloud")
        r_rev8 = self.sim.get_resource("res_delta_project_crypto")

        scenarios.append((self.generator.generate_revocation_sequence(p_alex, r_rev1), True))
        scenarios.append((self.generator.generate_revocation_sequence(p_brian, r_rev2), True))
        scenarios.append((self.generator.generate_revocation_sequence(p_charlie, r_rev3), True))
        scenarios.append((self.generator.generate_revocation_sequence(p_diana, r_rev4), True))
        scenarios.append((self.generator.generate_revocation_sequence(p_amanda, r_rev5), True))
        scenarios.append((self.generator.generate_revocation_sequence(p_brian, r_rev6), True))
        scenarios.append((self.generator.generate_revocation_sequence(p_charlie, r_rev7), True))
        scenarios.append((self.generator.generate_revocation_sequence(p_diana, r_rev8), True))

        # ---------------------------------------------------------
        # 5. HEADER SPOOFING & UNKEYED PARAMETER SCENARIOS (6 Scenarios)
        # ---------------------------------------------------------
        scenarios.append((self.generator.generate_header_spoofing_sequence(p_alice, p_bob, res_acme_dash), True))
        scenarios.append((self.generator.generate_header_spoofing_sequence(p_bob, p_alice, res_beta_dash), True))
        scenarios.append((self.generator.generate_header_spoofing_sequence(p_clara, p_david, res_gamma_dash), True))
        scenarios.append((self.generator.generate_header_spoofing_sequence(p_david, p_charlie, res_delta_dash), True))
        scenarios.append((self.generator.generate_header_spoofing_sequence(p_alice, p_eric, res_acme_inv), True))
        scenarios.append((self.generator.generate_header_spoofing_sequence(p_bob, p_diana, res_beta_inv), True))

        # ---------------------------------------------------------
        # 6. LEGITIMATE PUBLIC & BENIGN SHARED CONTROLS
        # ---------------------------------------------------------
        res_pub_guide = self.sim.get_resource("res_pub_guideline")
        res_pub_terms = self.sim.get_resource("res_pub_terms")

        # 4 Cross-Tenant Public Documents
        scenarios.append((self.generator.generate_cross_tenant_sequence(p_alice, p_bob, res_pub_guide), False))
        scenarios.append((self.generator.generate_cross_tenant_sequence(p_bob, p_charlie, res_pub_terms), False))
        scenarios.append((self.generator.generate_cross_tenant_sequence(p_clara, p_david, res_pub_guide), False))
        scenarios.append((self.generator.generate_cross_tenant_sequence(p_david, p_eric, res_pub_terms), False))

        # 4 Legitimate Intra-Tenant Shared Dashboard Access
        scenarios.append((self.generator.generate_cross_user_sequence(p_alice, p_alex, res_acme_dash), False))
        scenarios.append((self.generator.generate_cross_user_sequence(p_alice, p_amanda, res_acme_dash), False))
        scenarios.append((self.generator.generate_cross_user_sequence(p_bob, p_brian, res_beta_dash), False))
        scenarios.append((self.generator.generate_cross_user_sequence(p_clara, p_charlie, res_gamma_dash), False))

        if version != "v1.0":
            # 12 Additional Negative Controls for Corpus v1.1 (Total 20 Negative Controls)
            # 4 Additional Cross-Tenant Public Document accesses
            scenarios.append((self.generator.generate_cross_tenant_sequence(p_alex, p_brian, res_pub_guide), False))
            scenarios.append((self.generator.generate_cross_tenant_sequence(p_brian, p_charlie, res_pub_terms), False))
            scenarios.append((self.generator.generate_cross_tenant_sequence(p_charlie, p_diana, res_pub_guide), False))
            scenarios.append((self.generator.generate_cross_tenant_sequence(p_diana, p_eric, res_pub_terms), False))

            # 4 Legitimate Intra-User Profile Accesses (User accesses own profile)
            scenarios.append((self.generator.generate_cross_user_sequence(p_alice, p_alice, res_prof_alice), False))
            scenarios.append((self.generator.generate_cross_user_sequence(p_bob, p_bob, res_prof_bob), False))
            scenarios.append((self.generator.generate_cross_user_sequence(p_charlie, p_charlie, res_prof_charlie), False))
            scenarios.append((self.generator.generate_cross_user_sequence(p_david, p_david, res_prof_david), False))

            # 4 Legitimate Authorized Project Accesses (Authorized user before revocation)
            scenarios.append((self.generator.generate_cross_user_sequence(p_alex, p_alex, r_rev1), False))
            scenarios.append((self.generator.generate_cross_user_sequence(p_brian, p_brian, r_rev2), False))
            scenarios.append((self.generator.generate_cross_user_sequence(p_charlie, p_charlie, r_rev3), False))
            scenarios.append((self.generator.generate_cross_user_sequence(p_diana, p_diana, r_rev4), False))

        return scenarios

    def export_scenario_manifest(self, version: str = "v1.1", output_dir: str = "benchmarks/manifests"):
        """Exports fully documented, versioned scenario manifest as JSON and CSV."""
        os.makedirs(output_dir, exist_ok=True)
        scenarios = self.generate_expanded_scenarios(version=version)
        records = []

        for i, (seq, label) in enumerate(scenarios):
            prime_principal = seq.steps[0][1].principal.username if seq.steps else "none"
            probe_step = next((req for desc, req in seq.steps if "probe" in req.step_name), seq.steps[-1][1])
            probe_principal = probe_step.principal.username
            if seq.category == "STALE_REVOCATION":
                exp_auth = "DENY"
            else:
                dec = self.oracle.evaluate(probe_step.principal, seq.resource)
                exp_auth = dec.value

            rec = ScenarioManifestRecord(
                scenario_id=f"TC_{version.upper()}_{i+1:03d}",
                dataset_version=version,
                archetype_category=seq.category,
                priming_principal=prime_principal,
                probing_principal=probe_principal,
                resource_id=seq.resource.id,
                resource_visibility=seq.resource.visibility.value,
                expected_authorization=exp_auth,
                ground_truth_label=label,
                description=f"{seq.category} test on {seq.resource.id} primed by {prime_principal} probed by {probe_principal}"
            )
            records.append(rec)

        json_path = os.path.join(output_dir, f"scenarios_{version}.json")
        csv_path = os.path.join(output_dir, f"scenarios_{version}.csv")

        with open(json_path, "w", encoding="utf-8") as f:
            json.dump([r.model_dump() for r in records], f, indent=2)

        with open(csv_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(ScenarioManifestRecord.model_fields.keys()))
            writer.writeheader()
            for r in records:
                writer.writerow(r.model_dump())

        return json_path, csv_path

    def run_baseline_a_single_endpoint(self, config_archetype: str = "V1_MISSING_TENANT_KEY", dataset_version: str = "v1.1", matched_budget: bool = False) -> StatisticalBenchmarkResult:
        """Baseline A: Conventional Endpoint Testing. 
        - If matched_budget is True: Issues 3 repeated probe requests per scenario (fuzzing/busting params).
        - If matched_budget is False: Issues standard single probe request per scenario.
        """
        start_time = time.time()
        lab_db.reset()
        cache_sim = ProxyCacheSimulator(config_archetype=config_archetype)
        runner = DifferentialRunner(self.oracle, self.detector, cache_simulator=cache_sim)
        scenarios = self.generate_expanded_scenarios(version=dataset_version)

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

        tp = fp = tn = fn = 0
        findings = []
        cache_resets = 0
        state_transitions = 0
        principals_seen = set()

        for seq, label in scenarios:
            probe_step = next((req for desc, req in seq.steps if "probe" in req.step_name), seq.steps[-1][1])
            principals_seen.add(probe_step.principal.user_id)
            is_vulnerable = label and (seq.category in active_vulns)

            # Cold purge before probing
            cache_sim.purge_all()
            cache_resets += 1

            if matched_budget:
                # Issue 3 requests to match 3-request sequence budget of TenantCache
                resp1 = runner.execute_request(probe_step)
                # probe variation 2
                probe_step2 = RequestSpec(step_name=f"{probe_step.step_name}_v2", method=probe_step.method, url_path=f"{probe_step.url_path}?busting=1", principal=probe_step.principal, headers=probe_step.headers)
                resp2 = runner.execute_request(probe_step2)
                # probe variation 3
                resp = runner.execute_request(probe_step)
            else:
                resp = runner.execute_request(probe_step)

            finding = self.detector.evaluate_response(
                principal=probe_step.principal,
                target_resource=seq.resource,
                response=resp,
                step_name=probe_step.step_name,
                sequence_category=seq.category
            )

            if finding is not None:
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
        precision = (tp / (tp + fp)) if (tp + fp) > 0 else None
        recall = (tp / (tp + fn)) if (tp + fn) > 0 else (None if not active_vulns else 0.0)
        f1 = (2 * precision * recall) / (precision + recall) if (precision is not None and recall is not None and (precision + recall) > 0) else None
        specificity = (tn / (tn + fp)) if (tn + fp) > 0 else None
        accuracy = (tp + tn) / len(scenarios) if scenarios else 0.0
        fpr = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0

        budget_label = "Matched-Budget" if matched_budget else "Capability"
        return StatisticalBenchmarkResult(
            framework_name=f"Baseline A ({budget_label} Stateless DAST)",
            mode=config_archetype,
            dataset_version=dataset_version,
            total_scenarios=len(scenarios),
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            precision=round(precision, 4) if precision is not None else None,
            precision_ci_95=wilson_score_ci(tp, tp + fp) if (tp + fp) > 0 else None,
            recall=round(recall, 4) if recall is not None else None,
            recall_ci_95=wilson_score_ci(tp, tp + fn) if (tp + fn) > 0 else None,
            f1_score=round(f1, 4) if f1 is not None else None,
            specificity=round(specificity, 4) if specificity is not None else None,
            specificity_ci_95=wilson_score_ci(tn, tn + fp) if (tn + fp) > 0 else None,
            accuracy=round(accuracy, 4),
            accuracy_ci_95=wilson_score_ci(tp + tn, len(scenarios)),
            false_positive_rate=round(fpr, 4),
            total_requests=runner.total_requests,
            cache_resets=cache_resets,
            state_transitions=state_transitions,
            distinct_principals_covered=len(principals_seen),
            duration_seconds=round(duration, 4),
            requests_per_second=round(runner.total_requests / duration, 2),
            findings_count=len(findings),
            findings=findings
        )

    def run_baseline_b_token_substitution(self, config_archetype: str = "V1_MISSING_TENANT_KEY", dataset_version: str = "v1.1", matched_budget: bool = False) -> StatisticalBenchmarkResult:
        """Baseline B: Simple Token Substitution / Naive Differential Testing.
        Executes prime-probe sequences and detects cache hits/collisions purely on observable HTTP evidence,
        without access to an authorization oracle.
        """
        start_time = time.time()
        fresh_sim = TenantSimulator(seed=self.seed)
        lab_db.reset(fresh_sim)
        cache_sim = ProxyCacheSimulator(config_archetype=config_archetype)
        oracle = SecurityOracle(fresh_sim.resources, fresh_sim.principals)
        detector = LeakageDetector(oracle, fresh_sim.canary_registry, fresh_sim.resources)
        naive_detector = OracleFreeDifferentialDetector(canary_registry=fresh_sim.canary_registry)
        runner = DifferentialRunner(oracle, detector, cache_simulator=cache_sim)
        scenarios = self.generate_expanded_scenarios(version=dataset_version)

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

        tp = fp = tn = fn = 0
        findings = []
        cache_resets = 0
        state_transitions = 0
        principals_seen = set()

        for seq, label in scenarios:
            # Per-scenario isolation
            scenario_sim = TenantSimulator(seed=self.seed)
            lab_db.reset(scenario_sim)
            oracle.reset_ledger(scenario_sim.resources, scenario_sim.principals)
            cache_sim.purge_all()
            cache_resets += 1

            prime_principal = seq.steps[0][1].principal
            probe_step = next((req for desc, req in seq.steps if "probe" in req.step_name), seq.steps[-1][1])
            principals_seen.add(probe_step.principal.user_id)
            is_vulnerable = label and (seq.category in active_vulns)

            # Matched budget 3-step sequence: cold probe, prime, differential probe
            if matched_budget and len(seq.steps) < 3:
                cold_probe = RequestSpec(
                    step_name=f"{probe_step.step_name}_cold",
                    method=probe_step.method,
                    url_path=probe_step.url_path,
                    principal=probe_step.principal,
                    headers=dict(probe_step.headers),
                    query_params=probe_step.query_params
                )
                runner.execute_request(cold_probe)

            prime_resp = None
            probe_resp = None

            for desc, req in seq.steps:
                principals_seen.add(req.principal.user_id)
                if "post_revocation_probe" in req.step_name and seq.category == "STALE_REVOCATION":
                    state_transitions += 1
                    lab_db.revoke_user_access(seq.resource.id, req.principal.user_id)
                    oracle.record_revocation(seq.resource.id, req.principal.user_id)

                resp = runner.execute_request(req)
                if "prime" in req.step_name or req == seq.steps[0][1]:
                    prime_resp = resp
                if "probe" in req.step_name:
                    probe_resp = resp

            # Evaluate purely with OracleFreeDifferentialDetector
            finding = naive_detector.evaluate_differential(
                prime_response=prime_resp,
                probe_response=probe_resp,
                probing_principal=probe_step.principal,
                target_path=seq.resource.endpoint_path,
                priming_principal=prime_principal
            )

            if finding is not None:
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
        precision = (tp / (tp + fp)) if (tp + fp) > 0 else None
        recall = (tp / (tp + fn)) if (tp + fn) > 0 else (None if not active_vulns else 0.0)
        f1 = (2 * precision * recall) / (precision + recall) if (precision is not None and recall is not None and (precision + recall) > 0) else None
        specificity = (tn / (tn + fp)) if (tn + fp) > 0 else None
        accuracy = (tp + tn) / (tp + tn + fp + fn) if (tp + tn + fp + fn) > 0 else 0.0
        fpr = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0

        budget_label = "Matched-Budget" if matched_budget else "Capability"
        return StatisticalBenchmarkResult(
            framework_name=f"Baseline B ({budget_label} Naive Diffing)",
            mode=config_archetype,
            dataset_version=dataset_version,
            total_scenarios=len(scenarios),
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            precision=round(precision, 4) if precision is not None else None,
            precision_ci_95=wilson_score_ci(tp, tp + fp) if (tp + fp) > 0 else None,
            recall=round(recall, 4) if recall is not None else None,
            recall_ci_95=wilson_score_ci(tp, tp + fn) if (tp + fn) > 0 else None,
            f1_score=round(f1, 4) if f1 is not None else None,
            specificity=round(specificity, 4) if specificity is not None else None,
            specificity_ci_95=wilson_score_ci(tn, tn + fp) if (tn + fp) > 0 else None,
            accuracy=round(accuracy, 4),
            accuracy_ci_95=wilson_score_ci(tp + tn, tp + tn + fp + fn),
            false_positive_rate=round(fpr, 4),
            total_requests=runner.total_requests,
            cache_resets=cache_resets,
            state_transitions=state_transitions,
            distinct_principals_covered=len(principals_seen),
            duration_seconds=round(duration, 4),
            requests_per_second=round(runner.total_requests / duration, 2),
            findings_count=len(findings),
            findings=findings
        )

    def run_tenantcache(self, config_archetype: str = "V1_MISSING_TENANT_KEY", dataset_version: str = "v1.1", matched_budget: bool = False) -> StatisticalBenchmarkResult:
        """TenantCache: Stateful Differential Verification with Dynamic Origin Synchronization."""
        start_time = time.time()
        sim = TenantSimulator(seed=self.seed)
        lab_db.reset(sim)
        oracle = SecurityOracle(sim.resources, sim.principals)
        detector = LeakageDetector(oracle, sim.canary_registry, sim.resources)
        generator = RequestGenerator(sim)
        cache_sim = ProxyCacheSimulator(config_archetype=config_archetype)
        runner = DifferentialRunner(oracle, detector, cache_simulator=cache_sim)
        scenarios = self.generate_expanded_scenarios(version=dataset_version)

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

        tp = fp = tn = fn = 0
        findings = []
        cache_resets = 0
        state_transitions = 0
        principals_seen = set()

        def revocation_hook(res_id: str, user_id: str):
            nonlocal state_transitions
            state_transitions += 1
            lab_db.revoke_user_access(res_id, user_id)
            oracle.record_revocation(res_id, user_id)

        for seq, label in scenarios:
            # Clean database, reference ledger, and cache state per sequence
            fresh_sim = TenantSimulator(seed=self.seed)
            lab_db.reset(fresh_sim)
            oracle.reset_ledger(fresh_sim.resources, fresh_sim.principals)
            detector.resources = fresh_sim.resources
            cache_sim.purge_all()
            cache_resets += 1

            probe_step = next((req for desc, req in seq.steps if "probe" in req.step_name), seq.steps[-1][1])
            principals_seen.add(probe_step.principal.user_id)
            is_vuln = label and (seq.category in active_vulns)

            # Matched budget 3-step sequence: cold probe, prime, differential probe
            if matched_budget and len(seq.steps) < 3:
                cold_probe = RequestSpec(
                    step_name=f"{probe_step.step_name}_cold",
                    method=probe_step.method,
                    url_path=probe_step.url_path,
                    principal=probe_step.principal,
                    headers=dict(probe_step.headers),
                    query_params=probe_step.query_params
                )
                runner.execute_request(cold_probe)

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

        if not active_vulns:
            precision = None
            recall = None
            f1 = None
            precision_ci = None
            recall_ci = None
        else:
            precision = (tp / (tp + fp)) if (tp + fp) > 0 else None
            recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
            f1 = (2 * precision * recall) / (precision + recall) if (precision is not None and (precision + recall) > 0) else 0.0
            precision_ci = wilson_score_ci(tp, tp + fp) if (tp + fp) > 0 else None
            recall_ci = wilson_score_ci(tp, tp + fn) if (tp + fn) > 0 else None

        specificity = (tn / (tn + fp)) if (tn + fp) > 0 else None
        specificity_ci = wilson_score_ci(tn, tn + fp) if (tn + fp) > 0 else None
        accuracy = (tp + tn) / len(scenarios) if scenarios else 0.0
        accuracy_ci = wilson_score_ci(tp + tn, len(scenarios))
        fpr = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0

        budget_label = "Matched-Budget" if matched_budget else "Capability"
        return StatisticalBenchmarkResult(
            framework_name=f"TenantCache ({budget_label} Verification)",
            mode=config_archetype,
            dataset_version=dataset_version,
            total_scenarios=len(scenarios),
            true_positives=tp,
            false_positives=fp,
            true_negatives=tn,
            false_negatives=fn,
            precision=round(precision, 4) if precision is not None else None,
            precision_ci_95=precision_ci,
            recall=round(recall, 4) if recall is not None else None,
            recall_ci_95=recall_ci,
            f1_score=round(f1, 4) if f1 is not None else None,
            specificity=round(specificity, 4) if specificity is not None else None,
            specificity_ci_95=specificity_ci,
            accuracy=round(accuracy, 4),
            accuracy_ci_95=accuracy_ci,
            false_positive_rate=round(fpr, 4),
            total_requests=runner.total_requests,
            cache_resets=cache_resets,
            state_transitions=state_transitions,
            distinct_principals_covered=len(principals_seen),
            duration_seconds=round(duration, 4),
            requests_per_second=round(runner.total_requests / duration, 2),
            findings_count=len(findings),
            findings=findings
        )

    def run_ablation_study(self, dataset_version: str = "v1.1") -> Dict[str, Any]:
        """Executes systematic component ablation study on V1_MISSING_TENANT_KEY with category-wise confusion matrices."""
        categories = ["CROSS_TENANT", "CROSS_USER", "PRIVILEGE_BOUNDARY", "STALE_REVOCATION", "CACHE_KEY_SPOOFING", "BENIGN_CONTROLS"]
        scenarios = self.generate_expanded_scenarios(version=dataset_version)

        # 1. Full TenantCache: Execute scenarios and accumulate category CM from actual predictions
        res_full = self.run_tenantcache("V1_MISSING_TENANT_KEY", dataset_version=dataset_version, matched_budget=True)
        cm_full = {c: {"tp": 0, "fp": 0, "tn": 0, "fn": 0} for c in categories}
        sim_full = TenantSimulator(seed=self.seed)
        cache_sim_full = ProxyCacheSimulator(config_archetype="V1_MISSING_TENANT_KEY")
        oracle_full = SecurityOracle(sim_full.resources, sim_full.principals)
        detector_full = LeakageDetector(oracle_full, sim_full.canary_registry, sim_full.resources)
        runner_full = DifferentialRunner(oracle_full, detector_full, cache_simulator=cache_sim_full)

        for seq, label in scenarios:
            c = "BENIGN_CONTROLS" if not label else seq.category
            cache_sim_full.purge_all()
            lab_db.reset(sim_full)
            oracle_full.reset_ledger(sim_full.resources, sim_full.principals)

            def on_rev_full(r_id, u_id):
                lab_db.revoke_user_access(r_id, u_id)
                oracle_full.record_revocation(r_id, u_id)

            findings = runner_full.run_sequence(seq, on_revocation_hook=on_rev_full)
            has_leak = len(findings) > 0
            if has_leak:
                if label:
                    cm_full[c]["tp"] += 1
                else:
                    cm_full[c]["fp"] += 1
            else:
                if label:
                    cm_full[c]["fn"] += 1
                else:
                    cm_full[c]["tn"] += 1

        # 2. Ablation 1: No Cache-State Sequencing (Stateless DAST): Accumulate from actual stateless executions
        res_no_cache = self.run_baseline_a_single_endpoint("V1_MISSING_TENANT_KEY", dataset_version=dataset_version, matched_budget=True)
        cm_no_cache = {c: {"tp": 0, "fp": 0, "tn": 0, "fn": 0} for c in categories}
        sim_no_seq = TenantSimulator(seed=self.seed)
        cache_sim_no_seq = ProxyCacheSimulator(config_archetype="V1_MISSING_TENANT_KEY")
        oracle_no_seq = SecurityOracle(sim_no_seq.resources, sim_no_seq.principals)
        detector_no_seq = LeakageDetector(oracle_no_seq, sim_no_seq.canary_registry, sim_no_seq.resources)
        runner_no_seq = DifferentialRunner(oracle_no_seq, detector_no_seq, cache_simulator=cache_sim_no_seq)

        for seq, label in scenarios:
            c = "BENIGN_CONTROLS" if not label else seq.category
            cache_sim_no_seq.purge_all()
            lab_db.reset(sim_no_seq)
            oracle_no_seq.reset_ledger(sim_no_seq.resources, sim_no_seq.principals)

            probe_step = next((req for desc, req in seq.steps if "probe" in req.step_name), seq.steps[-1][1])
            resp = runner_no_seq.execute_request(probe_step)
            finding = detector_no_seq.evaluate_response(
                principal=probe_step.principal,
                target_resource=seq.resource,
                response=resp,
                step_name="stateless_probe",
                sequence_category=seq.category
            )
            has_leak = finding is not None
            if has_leak:
                if label:
                    cm_no_cache[c]["tp"] += 1
                else:
                    cm_no_cache[c]["fp"] += 1
            else:
                if label:
                    cm_no_cache[c]["fn"] += 1
                else:
                    cm_no_cache[c]["tn"] += 1

        # 3. Ablation 2: No Ground-Truth Oracle (Naive Diffing)
        res_no_oracle = self.run_baseline_b_token_substitution("V1_MISSING_TENANT_KEY", dataset_version=dataset_version, matched_budget=True)
        cm_no_oracle = {c: {"tp": 0, "fp": 0, "tn": 0, "fn": 0} for c in categories}
        naive_det = OracleFreeDifferentialDetector(canary_registry=self.sim.canary_registry)
        sim_ab2 = TenantSimulator(seed=self.seed)
        cache_sim_ab2 = ProxyCacheSimulator(config_archetype="V1_MISSING_TENANT_KEY")
        runner_ab2 = DifferentialRunner(self.oracle, self.detector, cache_simulator=cache_sim_ab2)
        for seq, label in scenarios:
            c = "BENIGN_CONTROLS" if not label else seq.category
            cache_sim_ab2.purge_all()
            lab_db.reset(sim_ab2)
            prime_principal = seq.steps[0][1].principal
            prime_resp = None
            probe_resp = None
            probe_step = next((req for desc, req in seq.steps if "probe" in req.step_name), seq.steps[-1][1])
            for desc, req in seq.steps:
                if "post_revocation_probe" in req.step_name and seq.category == "STALE_REVOCATION":
                    lab_db.revoke_user_access(seq.resource.id, req.principal.user_id)
                resp = runner_ab2.execute_request(req)
                if "prime" in req.step_name or req == seq.steps[0][1]:
                    prime_resp = resp
                if "probe" in req.step_name:
                    probe_resp = resp
            f_naive = naive_det.evaluate_differential(
                prime_response=prime_resp,
                probe_response=probe_resp,
                probing_principal=probe_step.principal,
                target_path=seq.resource.endpoint_path,
                priming_principal=prime_principal
            )
            if f_naive is not None:
                if label:
                    cm_no_oracle[c]["tp"] += 1
                else:
                    cm_no_oracle[c]["fp"] += 1
            else:
                if label:
                    cm_no_oracle[c]["fn"] += 1
                else:
                    cm_no_oracle[c]["tn"] += 1

        # 4. Control: Single-User Reachability Control (No Identity Diversity)
        # Note: Single-user testing functions as a reachability control experiment (TP=0, FN=46 by construction).
        # Tests entire corpus using a single authenticated principal (Alice vs. Alice)
        # Without multi-principal diversity, cross-tenant/cross-user/privilege leaks cannot be triggered
        sim3 = TenantSimulator(seed=self.seed)
        cache_sim3 = ProxyCacheSimulator(config_archetype="V1_MISSING_TENANT_KEY")
        oracle3 = SecurityOracle(sim3.resources, sim3.principals)
        detector3 = LeakageDetector(oracle3, sim3.canary_registry, sim3.resources)
        runner3 = DifferentialRunner(oracle3, detector3, cache_simulator=cache_sim3)
        single_principal = sim3.get_principal("user_alice")

        cm_no_ident = {c: {"tp": 0, "fp": 0, "tn": 0, "fn": 0} for c in categories}
        tp3 = fp3 = tn3 = fn3 = 0

        for seq, label in scenarios:
            c = "BENIGN_CONTROLS" if not label else seq.category
            cache_sim3.purge_all()
            lab_db.reset(sim3)

            prime_step = seq.steps[0][1]
            probe_step = next((req for desc, req in seq.steps if "probe" in req.step_name), seq.steps[-1][1])

            # In single-user scanning, both prime and probe are executed by the single authenticated identity
            single_prime = RequestSpec(
                step_name="single_prime",
                method=prime_step.method,
                url_path=prime_step.url_path,
                principal=single_principal,
                headers={"Authorization": f"Bearer {single_principal.auth_token}"},
                query_params=prime_step.query_params
            )
            single_probe = RequestSpec(
                step_name="single_probe",
                method=probe_step.method,
                url_path=probe_step.url_path,
                principal=single_principal,
                headers={"Authorization": f"Bearer {single_principal.auth_token}"},
                query_params=probe_step.query_params
            )

            runner3.execute_request(single_prime)
            resp = runner3.execute_request(single_probe)

            finding = detector3.evaluate_response(
                principal=single_principal,
                target_resource=seq.resource,
                response=resp,
                step_name="single_probe",
                sequence_category=seq.category
            )

            if finding is not None:
                if label:
                    tp3 += 1
                    cm_no_ident[c]["tp"] += 1
                else:
                    fp3 += 1
                    cm_no_ident[c]["fp"] += 1
            else:
                if label:
                    fn3 += 1
                    cm_no_ident[c]["fn"] += 1
                else:
                    tn3 += 1
                    cm_no_ident[c]["tn"] += 1

        ablation_records = [
            {
                "variant": "Full TenantCache",
                "identity_aware": True,
                "cache_sequenced": True,
                "oracle_enabled": True,
                "precision": res_full.precision,
                "recall": res_full.recall,
                "f1_score": res_full.f1_score,
                "false_positive_rate": res_full.false_positive_rate,
                "tp": res_full.true_positives,
                "fp": res_full.false_positives,
                "fn": res_full.false_negatives,
                "tn": res_full.true_negatives,
                "confusion_matrix": cm_full,
                "role_in_system": "Full Proposed Pipeline with Synchronized Dual-State Exploration"
            },
            {
                "variant": "Ablation 1: No Cache Sequencing",
                "identity_aware": True,
                "cache_sequenced": False,
                "oracle_enabled": True,
                "precision": res_no_cache.precision,
                "recall": res_no_cache.recall,
                "f1_score": res_no_cache.f1_score,
                "false_positive_rate": res_no_cache.false_positive_rate,
                "tp": res_no_cache.true_positives,
                "fp": res_no_cache.false_positives,
                "fn": res_no_cache.false_negatives,
                "tn": res_no_cache.true_negatives,
                "confusion_matrix": cm_no_cache,
                "role_in_system": "Evaluates isolated endpoints without priming cache state"
            },
            {
                "variant": "Ablation 2: No Ground-Truth Oracle",
                "identity_aware": True,
                "cache_sequenced": True,
                "oracle_enabled": False,
                "precision": res_no_oracle.precision,
                "recall": res_no_oracle.recall,
                "f1_score": res_no_oracle.f1_score,
                "false_positive_rate": res_no_oracle.false_positive_rate,
                "tp": res_no_oracle.true_positives,
                "fp": res_no_oracle.false_positives,
                "fn": res_no_oracle.false_negatives,
                "tn": res_no_oracle.true_negatives,
                "confusion_matrix": cm_no_oracle,
                "role_in_system": "Relies on naive response/length diffing on public assets"
            },
            {
                "variant": "Control: Single-User Reachability Control (No Identity Diversity)",
                "identity_aware": False,
                "cache_sequenced": True,
                "oracle_enabled": True,
                "precision": round(tp3 / (tp3 + fp3), 4) if (tp3 + fp3) > 0 else None,
                "recall": round(tp3 / (tp3 + fn3), 4) if (tp3 + fn3) > 0 else 0.0,
                "f1_score": round((2 * (tp3 / (tp3 + fp3)) * (tp3 / (tp3 + fn3))) / ((tp3 / (tp3 + fp3)) + (tp3 / (tp3 + fn3))), 4) if (tp3 + fp3 > 0 and tp3 + fn3 > 0 and ((tp3 / (tp3 + fp3)) + (tp3 / (tp3 + fn3))) > 0) else None,
                "false_positive_rate": round(fp3 / (fp3 + tn3), 4) if (fp3 + tn3) > 0 else 0.0,
                "tp": tp3,
                "fp": fp3,
                "fn": fn3,
                "tn": tn3,
                "confusion_matrix": cm_no_ident,
                "role_in_system": "Single authenticated principal (Alice vs. Alice); without identity diversity, cross-tenant leaks are never triggered"
            }
        ]

        return {
            "dataset_version": dataset_version,
            "total_scenarios": len(scenarios),
            "records": ablation_records
        }

    def run_multi_seed_repetitions(self, seeds: List[int] = [42, 43, 44, 45, 46], config_archetype: str = "V1_MISSING_TENANT_KEY", dataset_version: str = "v1.1") -> Dict[str, Any]:
        """Executes 5 deterministic-seed repetitions to measure execution variability vs scenario confidence intervals."""
        import statistics
        run_results = []

        for s in seeds:
            suite = BenchmarkSuite(seed=s)
            res = suite.run_tenantcache(config_archetype=config_archetype, dataset_version=dataset_version)
            run_results.append({
                "seed": s,
                "duration": res.duration_seconds,
                "throughput": res.requests_per_second,
                "tp": res.true_positives,
                "fp": res.false_positives,
                "tn": res.true_negatives,
                "fn": res.false_negatives,
                "recall": res.recall,
                "precision": res.precision,
                "specificity": res.specificity,
                "accuracy": res.accuracy
            })

        durations = [r["duration"] for r in run_results]
        throughputs = [r["throughput"] for r in run_results]
        recalls = [r["recall"] for r in run_results]
        precisions = [r["precision"] for r in run_results]

        summary = {
            "seeds_tested": seeds,
            "runs_count": len(seeds),
            "config_archetype": config_archetype,
            "dataset_version": dataset_version,
            "mean_duration": round(statistics.mean(durations), 4),
            "std_duration": round(statistics.stdev(durations), 4) if len(durations) > 1 else 0.0,
            "mean_throughput": round(statistics.mean(throughputs), 2),
            "std_throughput": round(statistics.stdev(throughputs), 2) if len(throughputs) > 1 else 0.0,
            "mean_recall": round(statistics.mean(recalls), 4),
            "std_recall": round(statistics.stdev(recalls), 4) if len(recalls) > 1 else 0.0,
            "mean_precision": round(statistics.mean(precisions), 4),
            "std_precision": round(statistics.stdev(precisions), 4) if len(precisions) > 1 else 0.0,
            "runs": run_results
        }
        return summary
