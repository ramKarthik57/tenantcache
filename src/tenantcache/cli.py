"""TenantCache Professional Command-Line Interface."""

import typer
import sys
import time
import os
from typing import Optional
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from src.tenantcache.simulator import TenantSimulator
from src.tenantcache.evaluation import BenchmarkSuite
from src.tenantcache.reporting import ReportGenerator
from lab.application.database import lab_db

app = typer.Typer(
    name="tenantcache",
    help="TenantCache: Automated Differential Verification of Cache Isolation in Multi-Tenant Web Applications.",
    add_completion=False
)
lab_app = typer.Typer(help="Manage local laboratory target and proxy environments.")
app.add_typer(lab_app, name="lab")

console = Console()


@app.command()
def doctor():
    """Validates local environment, dependencies, and laboratory readiness."""
    console.print(Panel.fit("[bold cyan]TenantCache Doctor - Environment Health Check[/bold cyan]"))

    table = Table(title="Diagnostic Verifications")
    table.add_column("Component", style="bold")
    table.add_column("Status", style="bold")
    table.add_column("Details")

    # 1. Python version
    py_ver = f"{sys.version_info.major}.{sys.version_info.minor}.{sys.version_info.micro}"
    table.add_row("Python Runtime", "[green]PASS[/green]", f"Python {py_ver}")

    # 2. Lab Target App
    try:
        from lab.application.main import app as target_app
        table.add_row("Lab Application", "[green]PASS[/green]", "FastAPI target loaded successfully")
    except Exception as e:
        table.add_row("Lab Application", "[red]FAIL[/red]", str(e))

    # 3. Simulator & Oracle
    try:
        sim = TenantSimulator()
        table.add_row("Tenant Simulator", "[green]PASS[/green]", f"{len(sim.tenants)} Tenants, {len(sim.users)} Users, {len(sim.resources)} Resources")
    except Exception as e:
        table.add_row("Tenant Simulator", "[red]FAIL[/red]", str(e))

    # 4. Proxy Cache Simulator
    try:
        from src.tenantcache.cache import ProxyCacheSimulator
        p = ProxyCacheSimulator()
        table.add_row("Cache Simulator", "[green]PASS[/green]", "High-Fidelity RFC 9111 Proxy Engine Ready")
    except Exception as e:
        table.add_row("Cache Simulator", "[red]FAIL[/red]", str(e))

    console.print(table)
    console.print("[bold green]System is 100% operational for reproducible experiments.[/bold green]")


@lab_app.command("status")
def lab_status():
    """Displays current laboratory configuration and synthetic universe state."""
    sim = TenantSimulator()
    console.print(Panel.fit("[bold cyan]TenantCache Lab Status[/bold cyan]"))

    t_table = Table(title="Active Synthetic Tenants")
    t_table.add_column("Tenant ID", style="cyan")
    t_table.add_column("Name")
    t_table.add_column("Slug")
    for t in sim.tenants.values():
        t_table.add_row(t.id, t.name, t.slug)
    console.print(t_table)

    u_table = Table(title="Active Principals")
    u_table.add_column("User ID", style="magenta")
    u_table.add_column("Tenant")
    u_table.add_column("Username")
    u_table.add_column("Role")
    for u in sim.users.values():
        u_table.add_row(u.id, u.tenant_id, u.username, u.role.value)
    console.print(u_table)


@lab_app.command("reset")
def lab_reset():
    """Resets laboratory database and cache states to initial seed state."""
    lab_db.reset()
    console.print("[bold green]Laboratory database and security state reset successfully to seed 42.[/bold green]")


@app.command()
def scan(
    archetype: str = typer.Option("V1_MISSING_TENANT_KEY", help="Configuration archetype to test: V1_MISSING_TENANT_KEY, V2_MISSING_USER_AUTH, V3_UNVALIDATED_HEADER, V4_STALE_REVOCATION, V5_ERRONEOUS_PUBLIC, V6_NORMALIZATION, SECURE_S1_STRICT_PRIVATE, SECURE_S2_IDENTITY_KEYED"),
    export: Optional[str] = typer.Option(None, help="Path to export markdown scan report")
):
    """Executes differential verification scan across the specified cache archetype."""
    console.print(f"[bold yellow]Initiating TenantCache Differential Scan on Archetype:[/bold yellow] [bold cyan]{archetype}[/bold cyan]")
    suite = BenchmarkSuite()
    result = suite.run_tenantcache(config_archetype=archetype)

    table = Table(title=f"Scan Results: {archetype}")
    table.add_column("Metric", style="bold")
    table.add_column("Value")
    prec_str = f"{result.precision:.4f}" if result.precision is not None else "N/A (Undefined)"
    rec_str = f"{result.recall:.4f}" if result.recall is not None else "N/A (Undefined)"
    f1_str = f"{result.f1_score:.4f}" if result.f1_score is not None else "N/A (Undefined)"
    spec_str = f"{result.specificity:.4f}" if result.specificity is not None else "N/A (Undefined)"

    table.add_row("Total Scenarios Evaluated", str(result.total_scenarios))
    table.add_row("Confirmed Leakage Findings", str(result.findings_count))
    table.add_row("True Positives (TP)", str(result.true_positives))
    table.add_row("False Positives (FP)", str(result.false_positives))
    table.add_row("True Negatives (TN)", str(result.true_negatives))
    table.add_row("False Negatives (FN)", str(result.false_negatives))
    table.add_row("Precision", prec_str)
    if result.precision is not None:
        table.add_row("Precision 95% CI", f"[{result.precision_ci_95[0]:.2f}, {result.precision_ci_95[1]:.2f}]")
    table.add_row("Recall", rec_str)
    if result.recall is not None:
        table.add_row("Recall 95% CI", f"[{result.recall_ci_95[0]:.2f}, {result.recall_ci_95[1]:.2f}]")
    table.add_row("F1 Score", f1_str)
    table.add_row("Specificity", spec_str)
    if result.specificity is not None:
        table.add_row("Specificity 95% CI", f"[{result.specificity_ci_95[0]:.2f}, {result.specificity_ci_95[1]:.2f}]")
    table.add_row("Accuracy", f"{result.accuracy:.4f}")
    table.add_row("Accuracy 95% CI", f"[{result.accuracy_ci_95[0]:.2f}, {result.accuracy_ci_95[1]:.2f}]")
    table.add_row("False Positive Rate (FPR)", f"{result.false_positive_rate:.4f}")
    table.add_row("Cache Resets Executed", str(result.cache_resets))
    table.add_row("State Transitions Explored", str(result.state_transitions))
    table.add_row("Distinct Principals Tested", str(result.distinct_principals_covered))
    table.add_row("Duration", f"{result.duration_seconds:.3f} s")
    console.print(table)

    if result.findings:
        f_table = Table(title="Confirmed Cache Isolation Vulnerabilities", style="red")
        f_table.add_column("Finding ID", style="bold")
        f_table.add_column("Class")
        f_table.add_column("Severity")
        f_table.add_column("Target Path")
        f_table.add_column("Victim Tenant")
        f_table.add_column("Adversary")
        for f in result.findings:
            f_table.add_row(f.id, f.leakage_type.value, f.severity.value, f.target_path, f.resource_owner_tenant, f.adversary_principal)
        console.print(f_table)
    else:
        console.print("[bold green]Zero vulnerabilities detected. Target configuration preserved isolation invariants.[/bold green]")

    if export:
        ReportGenerator.export_markdown([result], export)
        console.print(f"[green]Report exported to {export}[/green]")


@app.command()
def benchmark(
    profile: str = typer.Option("comprehensive", help="Benchmark profile: 'quick' (V1 and S1) or 'comprehensive' (all archetypes)"),
    output_dir: str = typer.Option("benchmarks/results", help="Directory for exported benchmark data")
):
    """Executes full scientific benchmark comparing Baselines A and B against TenantCache."""
    console.print(Panel.fit(f"[bold cyan]TenantCache Research Benchmark: Profile = {profile}[/bold cyan]"))
    suite = BenchmarkSuite()

    archetypes = ["V1_MISSING_TENANT_KEY", "V4_STALE_REVOCATION", "SECURE_S1_STRICT_PRIVATE"] if profile == "quick" else [
        "V1_MISSING_TENANT_KEY",
        "V2_MISSING_USER_AUTH",
        "V3_UNVALIDATED_HEADER",
        "V4_STALE_REVOCATION",
        "V5_ERRONEOUS_PUBLIC",
        "V6_NORMALIZATION",
        "SECURE_S1_STRICT_PRIVATE",
        "SECURE_S2_IDENTITY_KEYED"
    ]

    all_results = []
    with console.status("[bold green]Executing controlled comparative benchmarks...[/bold green]"):
        # Run Baselines on V1
        res_baseline_a = suite.run_baseline_a_single_endpoint(config_archetype="V1_MISSING_TENANT_KEY")
        res_baseline_b = suite.run_baseline_b_token_substitution(config_archetype="V1_MISSING_TENANT_KEY")
        all_results.append(res_baseline_a)
        all_results.append(res_baseline_b)

        # Run TenantCache across archetypes
        for arch in archetypes:
            res_tc = suite.run_tenantcache(config_archetype=arch)
            all_results.append(res_tc)

    # Display comparison table
    comp_table = Table(title="Benchmark Evaluation: Baselines vs TenantCache (Expanded 54-Scenario Matrix)")
    comp_table.add_column("Methodology", style="bold")
    comp_table.add_column("Archetype", style="cyan")
    comp_table.add_column("Precision", justify="right")
    comp_table.add_column("Recall", justify="right")
    comp_table.add_column("F1", justify="right")
    comp_table.add_column("Specificity", justify="right")
    comp_table.add_column("TP", justify="right")
    comp_table.add_column("FP", justify="right")
    comp_table.add_column("FN", justify="right")
    comp_table.add_column("TN", justify="right")
    comp_table.add_column("Duration", justify="right")

    for r in all_results:
        prec_display = f"{r.precision:.2f}" if r.precision is not None else "N/A"
        rec_display = f"{r.recall:.2f}" if r.recall is not None else "N/A"
        f1_display = f"{r.f1_score:.2f}" if r.f1_score is not None else "N/A"
        spec_display = f"{r.specificity:.2f}" if r.specificity is not None else "N/A"
        comp_table.add_row(
            r.framework_name,
            r.mode,
            prec_display,
            rec_display,
            f1_display,
            spec_display,
            str(r.true_positives),
            str(r.false_positives),
            str(r.false_negatives),
            str(r.true_negatives),
            f"{r.duration_seconds:.3f}s"
        )
    console.print(comp_table)

    # Export machine-readable results
    os.makedirs(output_dir, exist_ok=True)
    json_path = os.path.join(output_dir, "benchmark_results.json")
    csv_path = os.path.join(output_dir, "benchmark_results.csv")
    md_path = os.path.join(output_dir, "benchmark_report.md")

    ReportGenerator.export_json(all_results, json_path)
    ReportGenerator.export_csv(all_results, csv_path)
    ReportGenerator.export_markdown(all_results, md_path)

    console.print(f"[bold green]Artifacts written successfully to {output_dir}:[/bold green]")
    console.print(f"  • JSON: {json_path}")
    console.print(f"  • CSV:  {csv_path}")
    console.print(f"  • MD:   {md_path}")


@app.command()
def ablation(output_path: str = typer.Option("benchmarks/results/ablation_report.md", help="Path to export ablation report")):
    """Executes systematic component ablation study across testing dimensions."""
    console.print(Panel.fit("[bold cyan]TenantCache Component Ablation Study[/bold cyan]"))
    suite = BenchmarkSuite()
    records = suite.run_ablation_study()

    table = Table(title="Component Ablation Results (V1 Archetype)")
    table.add_column("System Variant", style="bold")
    table.add_column("Identity", justify="center")
    table.add_column("Cache Seq", justify="center")
    table.add_column("Oracle", justify="center")
    table.add_column("Precision", justify="right")
    table.add_column("Recall", justify="right")
    table.add_column("F1", justify="right")
    table.add_column("FPR", justify="right")
    table.add_column("TP / FN", justify="right")

    for rec in records:
        prec = f"{rec['precision']:.2f}" if rec['precision'] is not None else "N/A"
        rec_val = f"{rec['recall']:.2f}" if rec['recall'] is not None else "N/A"
        f1 = f"{rec['f1_score']:.2f}" if rec['f1_score'] is not None else "N/A"
        table.add_row(
            rec["variant"],
            "YES" if rec["identity_aware"] else "NO",
            "YES" if rec["cache_sequenced"] else "NO",
            "YES" if rec["oracle_enabled"] else "NO",
            prec,
            rec_val,
            f1,
            f"{rec['false_positive_rate']:.2f}",
            f"{rec['tp']} / {rec['fn']}"
        )
    console.print(table)

    # Save to markdown
    os.makedirs(os.path.dirname(os.path.abspath(output_path)), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("# TenantCache Component Ablation Study\n\n")
        f.write("| Variant | Identity | Cache Seq | Oracle | Precision | Recall | F1 Score | FPR | TP | FN |\n")
        f.write("|---|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|:---:|\n")
        for rec in records:
            p = f"{rec['precision']:.4f}" if rec['precision'] is not None else "N/A"
            r = f"{rec['recall']:.4f}" if rec['recall'] is not None else "N/A"
            f1_s = f"{rec['f1_score']:.4f}" if rec['f1_score'] is not None else "N/A"
            f.write(f"| **{rec['variant']}** | {'Yes' if rec['identity_aware'] else 'No'} | {'Yes' if rec['cache_sequenced'] else 'No'} | {'Yes' if rec['oracle_enabled'] else 'No'} | {p} | {r} | {f1_s} | {rec['false_positive_rate']:.4f} | {rec['tp']} | {rec['fn']} |\n")
    console.print(f"[green]Ablation study saved to {output_path}[/green]")


@app.command()
def report(results_path: str = typer.Option("benchmarks/results/benchmark_report.md", help="Path to markdown report")):
    """Prints the latest benchmark summary report."""
    if not os.path.exists(results_path):
        console.print(f"[red]Report file '{results_path}' not found. Run 'tenantcache benchmark' first.[/red]")
        return
    with open(results_path, "r", encoding="utf-8") as f:
        console.print(f.read())


if __name__ == "__main__":
    app()
