"""Reporting module: exports experiment outputs to Markdown, JSON, and CSV."""

import json
import csv
import os
from typing import List, Dict, Any
from src.tenantcache.models import BenchmarkResult, Finding


class ReportGenerator:
    """Generates structured research reports."""

    @staticmethod
    def export_json(results: List[BenchmarkResult], output_path: str):
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        data = [r.model_dump() for r in results]
        with open(output_path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

    @staticmethod
    def export_csv(results: List[BenchmarkResult], output_path: str):
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        fieldnames = [
            "framework_name", "mode", "total_scenarios", "true_positives",
            "false_positives", "true_negatives", "false_negatives",
            "precision", "recall", "f1_score", "accuracy",
            "total_requests", "duration_seconds", "requests_per_second", "findings_count"
        ]
        with open(output_path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fieldnames)
            writer.writeheader()
            for r in results:
                row = r.model_dump()
                filtered_row = {k: row[k] for k in fieldnames}
                writer.writerow(filtered_row)

    @staticmethod
    def export_markdown(results: List[BenchmarkResult], output_path: str) -> str:
        os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
        lines = [
            "# TenantCache: Experimental Evaluation and Benchmark Report",
            "",
            "## 1. Quantitative Benchmark Summary",
            "",
            "| Framework / Approach | Configuration Mode | Total Scenarios | TP | FP | TN | FN | Precision | Recall | F1 Score | Accuracy | Duration (s) | Req/s |",
            "|---|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|"
        ]

        for r in results:
            lines.append(
                f"| **{r.framework_name}** | `{r.mode}` | {r.total_scenarios} | {r.true_positives} | "
                f"{r.false_positives} | {r.true_negatives} | {r.false_negatives} | "
                f"{r.precision:.4f} | {r.recall:.4f} | {r.f1_score:.4f} | {r.accuracy:.4f} | "
                f"{r.duration_seconds:.3f} | {r.requests_per_second:.1f} |"
            )

        lines.extend([
            "",
            "## 2. Confirmed Vulnerability Findings Breakdown",
            ""
        ])

        all_findings = []
        for r in results:
            all_findings.extend(r.findings)

        # Deduplicate findings by title and adversary
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
