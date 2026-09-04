import platform
import subprocess
from collections import Counter
from datetime import datetime, timezone
from importlib.metadata import PackageNotFoundError, version
from pathlib import Path
from time import perf_counter

from pydantic import BaseModel, ConfigDict, Field

from app.scanners import bandit, semgrep
from app.services.dedup import deduplicate
from evaluation.ai_metrics import evaluate_ai
from evaluation.loader import load_manifest, sha256
from evaluation.matching import classify, record
from evaluation.metrics import binary_metrics
from evaluation.models import (EvaluationReport, MatchingPolicy, Reproducibility,
                               PairOutcome, TargetResult)


class EvaluationConfig(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)
    bandit_timeout_seconds: float = Field(default=30, gt=0)
    semgrep_timeout_seconds: float = Field(default=120, gt=0)
    semgrep_config: str = "p/security-audit"
    matching_policy: MatchingPolicy = Field(default_factory=MatchingPolicy)
    evaluate_ai: bool = False
    ai_provider: str | None = None
    ai_model: str | None = None
    ai_prompt_version: str | None = None
    max_fixture_bytes: int = Field(default=1_000_000, gt=0)
    source_cache_dir: str = "evaluation/cache"


def package_version(name: str):
    try:
        return version(name)
    except PackageNotFoundError:
        return None


def git_metadata():
    try:
        commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True,
            text=True, check=True).stdout.strip()
        dirty = bool(subprocess.run(["git", "status", "--porcelain"], capture_output=True,
            text=True, check=True).stdout.strip())
        return commit, dirty
    except (OSError, subprocess.SubprocessError):
        return None, True


def validate_semgrep_config(identity: str):
    if identity.startswith("p/"):
        return identity, None, identity
    path = Path(identity).resolve()
    if not path.is_file():
        raise ValueError("local Semgrep evaluation config does not exist")
    try:
        safe_identity = str(path.relative_to(Path.cwd().resolve()))
    except ValueError:
        safe_identity = f"local:{path.name}"
    return str(path), sha256(path.read_bytes()), safe_identity


def run_evaluation(manifest_path, config: EvaluationConfig | None = None,
                   *, report_kind="synthetic_harness_test") -> EvaluationReport:
    started = perf_counter()
    config = config or EvaluationConfig()
    manifest, contents, manifest_hash, fixture_hashes = load_manifest(
        manifest_path, max_fixture_bytes=config.max_fixture_bytes,
        cache_dir=config.source_cache_dir)
    semgrep_config, semgrep_hash, semgrep_identity = validate_semgrep_config(config.semgrep_config)
    results = []
    raw_total = dedup_total = 0
    findings_per_case = {}
    findings_by_scanner = Counter()
    findings_by_cwe = Counter()
    agreement = Counter()
    scanner_versions = {}
    for case in manifest.cases:
        files = {case.filename: contents[case.case_id]}
        before = perf_counter()
        bandit_result = bandit.scan(files, config.bandit_timeout_seconds)
        bandit_runtime = perf_counter() - before
        before = perf_counter()
        semgrep_result = semgrep.scan(files, config.semgrep_timeout_seconds,
                                      config_identity=semgrep_config)
        semgrep_runtime = perf_counter() - before
        scanner_versions.update(bandit=bandit_result.version, semgrep=semgrep_result.version)
        raw = [*bandit_result.findings, *semgrep_result.findings]
        combined = deduplicate(raw)
        raw_total += len(raw)
        dedup_total += len(combined)
        findings_per_case[case.case_id] = len(raw)
        findings_by_scanner.update({"bandit": len(bandit_result.findings),
                                    "semgrep": len(semgrep_result.findings)})
        for finding in raw:
            findings_by_cwe.update(finding.cwe_ids or ["unmapped"])
        mode_data = {
            "bandit": (bandit_result.findings, bandit_result, bandit_runtime),
            "semgrep": (semgrep_result.findings, semgrep_result, semgrep_runtime),
        }
        detections = {}
        for mode, (findings, scanner, runtime) in mode_data.items():
            records = [record(case, finding, config.matching_policy) for finding in findings]
            failed = not scanner.completed or bool(scanner.errors)
            status, detected = classify(case, records, config.matching_policy,
                                        scanner_error=failed)
            changed_status, _ = classify(case, records, config.matching_policy,
                scanner_error=failed, changed_only=True)
            detections[mode] = detected
            results.append(TargetResult(case_id=case.case_id, mode=mode, status=status,
                detected=detected, findings=records,
                unadjudicated_findings=[item for item in records if not item.target_match],
                scanner_errors=[error.message for error in scanner.errors],
                runtime_seconds=runtime, changed_line_status=changed_status,
                expected_vulnerability_present=case.vulnerability_present,
                expected_cwe_ids=case.cwe_ids))
        records = [record(case, finding, config.matching_policy) for finding in combined]
        partial = any(not scanner.completed or scanner.errors
                      for scanner in (bandit_result, semgrep_result))
        _, detected = classify(case, records, config.matching_policy)
        # A positive observation survives partial coverage; absence cannot be a
        # clean TN/FN when either scanner failed.
        failed = partial and detected is not True
        status, detected = classify(case, records, config.matching_policy, scanner_error=failed)
        changed_status, _ = classify(case, records, config.matching_policy,
            scanner_error=failed, changed_only=True)
        results.append(TargetResult(case_id=case.case_id, mode="combined", status=status,
            detected=detected, findings=records,
            unadjudicated_findings=[item for item in records if not item.target_match],
            scanner_errors=[error.message for scanner in (bandit_result, semgrep_result)
                            for error in scanner.errors],
            runtime_seconds=bandit_runtime + semgrep_runtime,
            changed_line_status=changed_status,
            expected_vulnerability_present=case.vulnerability_present,
            expected_cwe_ids=case.cwe_ids))
        if None in detections.values():
            agreement["unavailable"] += 1
        elif detections["bandit"] and detections["semgrep"]:
            agreement["both_detect"] += 1
        elif detections["bandit"]:
            agreement["bandit_only"] += 1
        elif detections["semgrep"]:
            agreement["semgrep_only"] += 1
        else:
            agreement["neither_detect"] += 1
    modes = ("bandit", "semgrep", "combined")
    grouped = {mode: [item for item in results if item.mode == mode] for mode in modes}
    pair_outcomes = []
    pairs = {case.pair_id for case in manifest.cases if case.pair_id}
    for pair_id in sorted(pairs):
        vulnerable = next(case for case in manifest.cases
                          if case.pair_id == pair_id and case.vulnerability_present)
        fixed = next(case for case in manifest.cases
                     if case.pair_id == pair_id and not case.vulnerability_present)
        for mode in modes:
            vulnerable_result = next(item for item in grouped[mode]
                                     if item.case_id == vulnerable.case_id)
            fixed_result = next(item for item in grouped[mode]
                                if item.case_id == fixed.case_id)
            outcome = f"{vulnerable_result.status}_{fixed_result.status}"
            pair_outcomes.append(PairOutcome(pair_id=pair_id, mode=mode,
                vulnerable_case_id=vulnerable.case_id,
                vulnerable_status=vulnerable_result.status,
                fixed_case_id=fixed.case_id, fixed_status=fixed_result.status,
                outcome=outcome))
    commit, dirty = git_metadata()
    reproducibility = Reproducibility(sentinelreview_commit=commit,
        working_tree_dirty=dirty, dataset_name=manifest.dataset_name,
        dataset_version=manifest.dataset_version, manifest_sha256=manifest_hash,
        fixture_sha256=fixture_hashes, bandit_version=scanner_versions.get("bandit"),
        semgrep_version=scanner_versions.get("semgrep"),
        semgrep_config_identity=semgrep_identity, semgrep_config_sha256=semgrep_hash,
        ai_enabled=config.evaluate_ai, ai_provider=config.ai_provider,
        ai_model=config.ai_model, prompt_version=config.ai_prompt_version,
        run_timestamp_utc=datetime.now(timezone.utc),
        platform=platform.platform(), python_version=platform.python_version(),
        configuration={"bandit_timeout_seconds": config.bandit_timeout_seconds,
            "semgrep_timeout_seconds": config.semgrep_timeout_seconds,
            "matching_policy": config.matching_policy.model_dump(),
            "max_fixture_bytes": config.max_fixture_bytes,
            "source_cache_dir": config.source_cache_dir})
    return EvaluationReport(report_kind=report_kind,
        synthetic_results_not_performance_claims=report_kind == "synthetic_harness_test",
        reproducibility=reproducibility, results=results,
        metrics_by_mode={mode: binary_metrics(items) for mode, items in grouped.items()},
        findings_per_case=findings_per_case,
        findings_by_scanner=dict(findings_by_scanner), findings_by_cwe=dict(findings_by_cwe),
        scanner_agreement=dict(agreement), raw_findings_count=raw_total,
        deduplicated_findings_count=dedup_total,
        deduplication_merged_count=raw_total-dedup_total,
        changed_line_metrics_by_mode={mode: binary_metrics(items, changed=True)
                                      for mode, items in grouped.items()},
        ai_metrics=evaluate_ai(results) if config.evaluate_ai else None,
        total_runtime_seconds=perf_counter()-started,
        report_label=manifest.display_name, pair_outcomes=pair_outcomes)
