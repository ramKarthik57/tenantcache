"""End-to-End test executing the benchmark evaluation across all configurations."""

from src.tenantcache.evaluation import BenchmarkSuite
from src.tenantcache.reporting import ReportGenerator
import tempfile
import os


def test_full_benchmark_suite_e2e():
    suite = BenchmarkSuite(seed=42)

    # 1. Run Baseline A
    res_a = suite.run_baseline_a_single_endpoint(config_archetype="V1_MISSING_TENANT_KEY")
    assert res_a.recall == 0.0  # Stateless baseline completely misses cache isolation failures!
    assert res_a.precision is None  # Precision is undefined when 0 positive predictions made

    # 2. Run Baseline B
    res_b = suite.run_baseline_b_token_substitution(config_archetype="V1_MISSING_TENANT_KEY")
    assert res_b.recall > 0.0
    assert res_b.recall < 1.0  # Misses revocation and state transitions
    assert res_b.false_positives > 0  # Naive diffing generates false positives

    # 3. Run TenantCache on Vulnerable V1 (v1.1 Corpus: 46 Vulns, 20 Benign Controls)
    res_tc_v1 = suite.run_tenantcache(config_archetype="V1_MISSING_TENANT_KEY", dataset_version="v1.1")
    assert res_tc_v1.recall == 1.0
    assert res_tc_v1.precision == 1.0
    assert res_tc_v1.true_positives == 46
    assert res_tc_v1.true_negatives == 20
    assert res_tc_v1.false_positives == 0
    assert res_tc_v1.false_negatives == 0

    # 4. Verify Backward Compatibility with Legacy v1.0 Corpus (46 Vulns, 8 Benign Controls = 54 Total Scenarios)
    res_tc_v1_legacy = suite.run_tenantcache(config_archetype="V1_MISSING_TENANT_KEY", dataset_version="v1.0")
    assert res_tc_v1_legacy.total_scenarios == 54
    assert res_tc_v1_legacy.true_positives == 46
    assert res_tc_v1_legacy.true_negatives == 8

    # 5. Run TenantCache on Secure S1
    res_tc_s1 = suite.run_tenantcache(config_archetype="SECURE_S1_STRICT_PRIVATE", dataset_version="v1.1")
    assert res_tc_s1.findings_count == 0
    assert res_tc_s1.false_positives == 0
    assert res_tc_s1.precision is None  # Undefined on secure configs
    assert res_tc_s1.recall is None  # Undefined on secure configs
    assert res_tc_s1.specificity == 1.0

    # 5. Export reports to temp dir and verify file integrity
    with tempfile.TemporaryDirectory() as tmpdir:
        json_file = os.path.join(tmpdir, "test.json")
        csv_file = os.path.join(tmpdir, "test.csv")
        md_file = os.path.join(tmpdir, "test.md")

        results = [res_a, res_b, res_tc_v1, res_tc_s1]
        ReportGenerator.export_json(results, json_file)
        ReportGenerator.export_csv(results, csv_file)
        ReportGenerator.export_markdown(results, md_file)

        assert os.path.exists(json_file)
        assert os.path.exists(csv_file)
        assert os.path.exists(md_file)
        assert os.path.getsize(json_file) > 100
        assert os.path.getsize(csv_file) > 100
        assert os.path.getsize(md_file) > 100
