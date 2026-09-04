import argparse
from datetime import datetime, timezone

from evaluation.reports import write_reports
from evaluation.runner import EvaluationConfig, run_evaluation


def main():
    parser = argparse.ArgumentParser(description="Run SentinelReview's standalone evaluation harness")
    parser.add_argument("run", choices=["run"])
    parser.add_argument("--manifest", required=True)
    parser.add_argument("--output-dir", default="evaluation/results")
    parser.add_argument("--run-id")
    parser.add_argument("--semgrep-config", default="p/security-audit")
    parser.add_argument("--report-kind", choices=["synthetic_harness_test", "scanner_conformance",
                                                   "real_world_benchmark"],
                        default="synthetic_harness_test")
    args = parser.parse_args()
    config = EvaluationConfig(semgrep_config=args.semgrep_config)
    report = run_evaluation(args.manifest, config, report_kind=args.report_kind)
    run_id = args.run_id or datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    paths = write_reports(report, args.output_dir, run_id)
    print("\n".join(str(path) for path in paths))


if __name__ == "__main__":
    main()
