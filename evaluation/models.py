from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from app.ai.models import AIReview


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class LineRange(StrictModel):
    start: int = Field(ge=1)
    end: int = Field(ge=1)

    @model_validator(mode="after")
    def ordered(self):
        if self.end < self.start:
            raise ValueError("line range end must be at or after start")
        return self

    def contains(self, line: int) -> bool:
        return self.start <= line <= self.end


class LabelProvenance(StrictModel):
    kind: Literal["external_annotation", "constructed_fixture",
                  "reviewed_advisory_manual_localization"]
    reference: str = Field(min_length=1)
    rationale: str = Field(min_length=1)
    reviewed_by: str | None = None
    reviewer_status: Literal["unreviewed", "single_reviewer", "independently_reviewed"] | None = None
    reviewed_at: datetime | None = None


class LicenseInfo(StrictModel):
    identifier: str | None = None
    reference: str = Field(min_length=1)
    source_retrieval_mode: Literal["local_fixture", "immutable_reference_fetch"] = "local_fixture"
    redistribution: str | None = None


class BenchmarkCase(StrictModel):
    case_id: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
    source_dataset: str = Field(min_length=1)
    source_reference: str = Field(min_length=1)
    source_revision: str | None = None
    language: Literal["python"]
    filename: str = Field(min_length=1)
    vulnerability_present: bool
    cwe_ids: list[str] = Field(default_factory=list)
    expected_category: str | None = None
    vulnerable_line_range: LineRange | None = None
    assessment_line_range: LineRange
    code: str | None = None
    fixture_path: str | None = None
    code_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")
    pair_id: str | None = None
    pair_role: Literal["vulnerable", "fixed"] | None = None
    benchmark_group: Literal["synthetic", "scanner_conformance", "real_world"] = "synthetic"
    repository: str | None = None
    fixing_commit: str | None = None
    cve_id: str | None = None
    ghsa_id: str | None = None
    advisory_references: list[str] = Field(default_factory=list)
    duplicate_cluster_id: str | None = None
    code_fingerprint: str | None = None
    normalized_fingerprint: str | None = None
    selection_reason: str | None = None
    known_scanner_test_overlap: bool | None = None
    changed_line_ranges: list[LineRange] | None = None
    notes: str = ""
    label_provenance: LabelProvenance
    license: LicenseInfo

    @model_validator(mode="after")
    def coherent(self):
        immutable_fetch = self.license.source_retrieval_mode == "immutable_reference_fetch"
        supplied = sum(value is not None for value in (self.code, self.fixture_path))
        if immutable_fetch and supplied:
            raise ValueError("immutable reference cases cannot embed source")
        if not immutable_fetch and supplied != 1:
            raise ValueError("exactly one of code or fixture_path is required")
        if self.filename.startswith("/") or ".." in self.filename.split("/"):
            raise ValueError("filename must be repository-relative")
        if self.fixture_path and (self.fixture_path.startswith("/") or ".." in self.fixture_path.split("/")):
            raise ValueError("fixture_path must remain inside the dataset directory")
        if self.vulnerability_present and self.vulnerable_line_range is None:
            raise ValueError("positive cases require a vulnerable line range")
        if not self.vulnerability_present and self.vulnerable_line_range is not None:
            raise ValueError("negative cases cannot declare a vulnerable line range")
        if self.vulnerable_line_range and not (
            self.assessment_line_range.contains(self.vulnerable_line_range.start)
            and self.assessment_line_range.contains(self.vulnerable_line_range.end)
        ):
            raise ValueError("vulnerable range must be inside assessment range")
        if not self.cwe_ids and not self.expected_category:
            raise ValueError("a target needs CWE IDs or an expected category")
        if any(not value.startswith("CWE-") or not value[4:].isdigit() for value in self.cwe_ids):
            raise ValueError("CWE IDs must use CWE-<number>")
        if self.benchmark_group == "real_world":
            required = {"repository": self.repository, "revision": self.source_revision,
                "pair_id": self.pair_id, "pair_role": self.pair_role,
                "fixing_commit": self.fixing_commit, "cve_id": self.cve_id,
                "duplicate_cluster_id": self.duplicate_cluster_id,
                "code_fingerprint": self.code_fingerprint,
                "selection_reason": self.selection_reason}
            missing = [name for name, value in required.items() if not value]
            if missing:
                raise ValueError(f"real-world case metadata missing: {', '.join(missing)}")
            if not immutable_fetch:
                raise ValueError("real-world cases must use immutable reference fetch")
            if not self.ghsa_id or not self.advisory_references:
                raise ValueError("real-world cases require GHSA and advisory references")
            if (self.label_provenance.kind != "reviewed_advisory_manual_localization"
                    or not self.label_provenance.reviewed_by
                    or not self.label_provenance.reviewer_status
                    or not self.label_provenance.reviewed_at):
                raise ValueError("real-world cases require complete review provenance")
            if not self.license.identifier or not self.license.redistribution:
                raise ValueError("real-world cases require complete license metadata")
            expected_role = "vulnerable" if self.vulnerability_present else "fixed"
            if self.pair_role != expected_role:
                raise ValueError("pair role must agree with vulnerability label")
        return self


class DatasetManifest(StrictModel):
    dataset_name: str = Field(min_length=1)
    dataset_version: str = Field(min_length=1)
    display_name: str | None = None
    cases: list[BenchmarkCase] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_cases(self):
        ids = [case.case_id for case in self.cases]
        if len(ids) != len(set(ids)):
            raise ValueError("case IDs must be unique")
        pairs: dict[str, list[BenchmarkCase]] = {}
        for case in self.cases:
            if case.benchmark_group == "real_world":
                pairs.setdefault(case.pair_id or "", []).append(case)
        for pair_id, cases in pairs.items():
            if len(cases) != 2 or {case.pair_role for case in cases} != {"vulnerable", "fixed"}:
                raise ValueError(f"real-world pair must contain vulnerable and fixed cases: {pair_id}")
            vulnerable = next(case for case in cases if case.pair_role == "vulnerable")
            fixed = next(case for case in cases if case.pair_role == "fixed")
            if (vulnerable.repository, vulnerable.filename, vulnerable.cwe_ids,
                    vulnerable.fixing_commit, vulnerable.duplicate_cluster_id) != (
                    fixed.repository, fixed.filename, fixed.cwe_ids,
                    fixed.fixing_commit, fixed.duplicate_cluster_id):
                raise ValueError(f"real-world pair metadata mismatch: {pair_id}")
            if fixed.source_revision != fixed.fixing_commit:
                raise ValueError(f"fixed case revision must equal fixing commit: {pair_id}")
            if vulnerable.source_revision == fixed.source_revision:
                raise ValueError(f"pair revisions must differ: {pair_id}")
        return self


class MappingEntry(StrictModel):
    scanner: str
    rule_id: str
    expected_category: str


class MatchingPolicy(StrictModel):
    version: str = Field(default="strict-v1", min_length=1)
    mappings: list[MappingEntry] = Field(default_factory=list)


class FindingRecord(StrictModel):
    source: str
    sources: list[str]
    filename: str
    line_number: int
    rule_id: str
    rule_ids: list[str]
    cwe_ids: list[str]
    severity: str
    in_assessment_scope: bool
    target_match: bool
    changed_line: bool | None
    ai_review: AIReview | None = None


class TargetResult(StrictModel):
    case_id: str
    mode: Literal["bandit", "semgrep", "combined"]
    status: Literal["tp", "fp", "tn", "fn", "unscorable", "scanner_error"]
    detected: bool | None
    findings: list[FindingRecord]
    unadjudicated_findings: list[FindingRecord]
    scanner_errors: list[str]
    runtime_seconds: float = Field(ge=0)
    changed_line_status: Literal["tp", "fp", "tn", "fn", "unscorable", "scanner_error"] | None = None
    expected_vulnerability_present: bool | None = None
    expected_cwe_ids: list[str] = Field(default_factory=list)


class PairOutcome(StrictModel):
    pair_id: str
    mode: Literal["bandit", "semgrep", "combined"]
    vulnerable_case_id: str
    vulnerable_status: str
    fixed_case_id: str
    fixed_status: str
    outcome: str


class BinaryMetrics(StrictModel):
    true_positives: int = 0
    false_positives: int = 0
    true_negatives: int = 0
    false_negatives: int = 0
    unscorable: int = 0
    scanner_errors: int = 0
    precision: float | None = None
    recall: float | None = None
    false_positive_rate: float | None = None
    f1: float | None = None


class AIMetrics(StrictModel):
    available_reviews: int = 0
    unavailable_reviews: int = 0
    decisive_reviews: int = 0
    needs_review: int = 0
    likely_valid_correct: int = 0
    likely_valid_incorrect: int = 0
    likely_false_positive_correct: int = 0
    likely_false_positive_incorrect: int = 0
    true_finding_downrank_risk: int = 0
    deterministic_misses_ai_cannot_recover: int = 0
    priority_distribution: dict[str, int] = Field(default_factory=dict)
    confidence_correct: list[float] = Field(default_factory=list)
    confidence_incorrect: list[float] = Field(default_factory=list)


class Reproducibility(StrictModel):
    sentinelreview_commit: str | None
    working_tree_dirty: bool
    dataset_name: str
    dataset_version: str
    manifest_sha256: str
    fixture_sha256: dict[str, str]
    bandit_version: str | None
    semgrep_version: str | None
    semgrep_config_identity: str
    semgrep_config_sha256: str | None
    ai_enabled: bool
    ai_provider: str | None = None
    ai_model: str | None = None
    prompt_version: str | None = None
    run_timestamp_utc: datetime
    platform: str
    python_version: str
    configuration: dict


class EvaluationReport(StrictModel):
    report_kind: Literal["synthetic_harness_test", "scanner_conformance", "real_world_benchmark"]
    synthetic_results_not_performance_claims: bool
    reproducibility: Reproducibility
    results: list[TargetResult]
    metrics_by_mode: dict[str, BinaryMetrics]
    findings_per_case: dict[str, int]
    findings_by_scanner: dict[str, int]
    findings_by_cwe: dict[str, int]
    scanner_agreement: dict[str, int]
    raw_findings_count: int
    deduplicated_findings_count: int
    deduplication_merged_count: int
    changed_line_metrics_by_mode: dict[str, BinaryMetrics | None]
    ai_metrics: AIMetrics | None
    total_runtime_seconds: float = Field(ge=0)
    report_label: str | None = None
    pair_outcomes: list[PairOutcome] = Field(default_factory=list)
