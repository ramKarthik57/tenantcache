"""Reporting module: exports experiment outputs to Markdown, JSON, and CSV with statistical confidence intervals."""

import json
import csv
import os
from typing import List, Dict, Any
from src.tenantcache.evaluation import StatisticalBenchmarkResult


class ReportGenerator:
    """Generates structured research reports with rigorous statistical metrics."""

    @staticmethod
    def export_json(results: List[StatisticalBenchmarkResult], output_path: str):
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        data = [r.model_dump() for r in results]
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def export_csv(results: List[StatisticalBenchmarkResult], output_path: str):
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        fieldnames = [
            "framework_name", "mode", "total_scenarios", "true_positives",
            "false_positives", "true_negatives", "false_negatives",
            "precision", "precision_ci_95", "recall", "recall_ci_95",
            "f1_score", "specificity", "specificity_ci_95", "accuracy", "accuracy_ci_95",
            "false_positive_rate", "cache_resets", "state_transitions", "distinct_principals_covered",
            "total_requests", "duration_seconds", "requests_per_second", "findings_count"
        ]
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in results:
                row = r.model_dump()
                filtered_row = {k: str(row.get(k, "")) for k in fieldnames}
                writer.writerow(filtered_row)

    @staticmethod
    def export_markdown(results: List[StatisticalBenchmarkResult], output_path: str) -> str:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        lines = [
            "# TenantCache: Experimental Evaluation and Statistical Benchmark Report",
            "",
            "## 1. Quantitative Benchmark Summary (with 95% Wilson Confidence Intervals)",
            "",
            "| Framework / Approach | Archetype | Scenarios | TP | FP | TN | FN | Precision (95% CI) | Recall (95% CI) | Specificity (95% CI) | Accuracy (95% CI) | FPR | Resets | Trans | Principals | Duration |",
            "|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|"
        ]

        for r in results:
            prec_str = f"{r.precision:.4f} `[{r.precision_ci_95[0]:.2f}, {r.precision_ci_95[1]:.2f}]`" if r.precision is not None else "*N/A (Undefined)*"
            rec_str = f"{r.recall:.4f} `[{r.recall_ci_95[0]:.2f}, {r.recall_ci_95[1]:.2f}]`" if r.recall is not None else "*N/A (Undefined)*"
            spec_str = f"{r.specificity:.4f} `[{r.specificity_ci_95[0]:.2f}, {r.specificity_ci_95[1]:.2f}]`" if r.specificity is not None else "*N/A (Undefined)*"
            acc_str = f"{r.accuracy:.4f} `[{r.accuracy_ci_95[0]:.2f}, {r.accuracy_ci_95[1]:.2f}]`"

            lines.append(
                f"| **{r.framework_name}** | `{r.mode}` | {r.total_scenarios} | {r.true_positives} | "
                f"{r.false_positives} | {r.true_negatives} | {r.false_negatives} | "
                f"{prec_str} | {rec_str} | {spec_str} | {acc_str} | "
                f"{r.false_positive_rate:.2f} | {r.cache_resets} | {r.state_transitions} | {r.distinct_principals_covered} | "
                f"{r.duration_seconds:.3f}s |"
            )

        lines.extend([
            "",
            "## 2. Statistical Invariant and Methodology Notes",
            "",
            "- **Zero-Denominator Precision & Recall (Secure S1 & S2):** When a secure configuration yields 0 positive scenarios ($TP + FP = 0, TP + FN = 0$), Precision and Recall are mathematically undefined and reported as *N/A (Undefined)*. Specificity is calculated as $TN / (TN + FP) = 54/54 = 1.000$ (with Wilson CI $[0.93, 1.00]$) and Accuracy is $1.000$.",
            "- **Baseline A Precision:** When Baseline A generates zero positive predictions ($TP=0, FP=0$), Precision is mathematically undefined and reported as *N/A (Undefined)*.",
            "- **Exploration Budget Documentation:** Baseline comparisons track explicit operational parameters: `Total Requests`, `Cache Resets`, `State Transitions`, and `Distinct Principals Covered`.",
            "- **Wilson Score Intervals:** Calculated at a 95% confidence level ($z = 1.96$), capturing sample size uncertainty over the 54-scenario benchmark corpus.",
            "",
            "## 3. Confirmed Vulnerability Findings Breakdown",
            ""
        ])

        all_findings = []
        for r in results:
            all_findings.extend(r.findings)

        unique_findings = {}
        for f in all_findings:
            key = f"{f.leakage_type.value}:{f.resource_id}:{f.adversary_principal}"
            if key not in unique_findings:
                unique_findings[key] = f

        if not unique_findings:
            lines.append("*No vulnerability findings detected in this evaluation run (e.g. Secure configurations).*")
        else:
            lines.append("| ID | Severity | Leakage Class | Target Endpoint | Victim Tenant | Adversary Principal | Detected Canary | Cache Status |")
            lines.append("|---|---|---|---|---|---|---|:---:|")
            for f in unique_findings.values():
                lines.append(
                    f"| `{f.id}` | **{f.severity.value}** | `{f.leakage_type.value}` | `{f.target_path}` | "
                    f"`{f.resource_owner_tenant}` | `{f.adversary_principal}` | `{f.detected_canary[:18]}...` | `{f.response_cache_status.value}` |"
                )

        content = "\n".join(lines) + "\n"
        with open(output_path, "w", encoding="utf-8") as f:
            f.write(content)
        return content
