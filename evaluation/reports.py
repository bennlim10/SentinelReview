import json
import re
from pathlib import Path

from evaluation.models import EvaluationReport


def write_reports(report: EvaluationReport, output_dir: str | Path, run_id: str):
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", run_id):
        raise ValueError("run_id must be a safe filename component")
    output = Path(output_dir)
    output.mkdir(parents=True, exist_ok=True)
    json_path = output / f"{run_id}.json"
    md_path = output / f"{run_id}.md"
    json_path.write_text(json.dumps(report.model_dump(mode="json"), indent=2, allow_nan=False) + "\n")
    lines = ["# SentinelReview evaluation report", "",
        f"**Report kind:** `{report.report_kind}`", "",
        "Synthetic harness results are not benchmark performance claims." if report.synthetic_results_not_performance_claims else "",
        "", "| Mode | TP | FP | TN | FN | Unscorable | Scanner errors | Precision | Recall | F1 |",
        "| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |"]
    def display(value):
        return "undefined" if value is None else f"{value:.4f}" if isinstance(value, float) else str(value)
    for mode, metric in report.metrics_by_mode.items():
        lines.append(f"| {mode} | {metric.true_positives} | {metric.false_positives} | "
            f"{metric.true_negatives} | {metric.false_negatives} | {metric.unscorable} | "
            f"{metric.scanner_errors} | {display(metric.precision)} | {display(metric.recall)} | {display(metric.f1)} |")
    lines += ["", f"Raw findings: {report.raw_findings_count}",
              f"Deduplicated findings: {report.deduplicated_findings_count}",
              f"Deduplication merges: {report.deduplication_merged_count}",
              f"Scanner agreement: `{json.dumps(report.scanner_agreement, sort_keys=True)}`",
              f"Dataset: {report.reproducibility.dataset_name} {report.reproducibility.dataset_version}",
              f"SentinelReview commit: {report.reproducibility.sentinelreview_commit or 'unavailable'}"
              f" (dirty={str(report.reproducibility.working_tree_dirty).lower()})",
              f"Bandit/Semgrep: {report.reproducibility.bandit_version or 'unavailable'} / "
              f"{report.reproducibility.semgrep_version or 'unavailable'}",
              f"Semgrep config: {report.reproducibility.semgrep_config_identity}",
              f"Total runtime seconds: {report.total_runtime_seconds:.6f}", ""]
    md_path.write_text("\n".join(lines))
    return json_path, md_path
