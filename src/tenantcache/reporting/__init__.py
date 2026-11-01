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
            "f1_score", "accuracy", "accuracy_ci_95",
            "total_requests", "duration_seconds", "requests_per_second", "findings_count"
        ]
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in results:
                row = r.model_dump()
                filtered_row = {k: str(row[k]) for k in fieldnames}
                writer.writerow(filtered_row)

    @staticmethod
    def export_markdown(results: List[StatisticalBenchmarkResult], output_path: str) -> str:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        lines = [
            "# TenantCache: Experimental Evaluation and Statistical Benchmark Report",
            "",
            "## 1. Quantitative Benchmark Summary (with 95% Wilson Confidence Intervals)",
            "",
            "| Framework / Approach | Archetype | Scenarios | TP | FP | TN | FN | Precision (95% CI) | Recall (95% CI) | F1 Score | Accuracy (95% CI) | Duration | Req/s |",
            "|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|"
        ]

        for r in results:
            prec_str = f"{r.precision:.4f} `[{r.precision_ci_95[0]:.2f}, {r.precision_ci_95[1]:.2f}]`" if r.precision is not None else "*Undefined (N/A)*"
            rec_str = f"{r.recall:.4f} `[{r.recall_ci_95[0]:.2f}, {r.recall_ci_95[1]:.2f}]`"
            acc_str = f"{r.accuracy:.4f} `[{r.accuracy_ci_95[0]:.2f}, {r.accuracy_ci_95[1]:.2f}]`"

            lines.append(
                f"| **{r.framework_name}** | `{r.mode}` | {r.total_scenarios} | {r.true_positives} | "
                f"{r.false_positives} | {r.true_negatives} | {r.false_negatives} | "
                f"{prec_str} | {rec_str} | {r.f1_score:.4f} | {acc_str} | "
                f"{r.duration_seconds:.3f}s | {r.requests_per_second:.1f} |"
            )

        lines.extend([
            "",
            "## 2. Statistical Invariant and Methodology Notes",
            "",
            "- **Baseline A Precision:** When a baseline makes 0 positive predictions (TP=0, FP=0), Precision is mathematically undefined ($0/0$) and is explicitly reported as *Undefined (N/A)* rather than artificially defaulted to 1.0.",
            "- **Wilson Score Intervals:** Reported as `[lower, upper]` at a 95% confidence level ($z = 1.96$), reflecting the sample size uncertainty over the 54-scenario benchmark corpus.",
            "- **Expanded Corpus:** Evaluates 54 scenarios across 5 distinct enterprise tenants and multiple departments (14 cross-tenant, 10 cross-user private, 8 privilege boundary, 8 stateful revocation, 6 header spoofing, 8 benign public/shared controls).",
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
