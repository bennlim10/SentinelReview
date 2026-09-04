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
    kind: Literal["external_annotation", "constructed_fixture"]
    reference: str = Field(min_length=1)
    rationale: str = Field(min_length=1)
    reviewed_by: str | None = None


class LicenseInfo(StrictModel):
    identifier: str | None = None
    reference: str = Field(min_length=1)


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
    changed_line_ranges: list[LineRange] | None = None
    notes: str = ""
    label_provenance: LabelProvenance
    license: LicenseInfo

    @model_validator(mode="after")
    def coherent(self):
        if (self.code is None) == (self.fixture_path is None):
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
        return self


class DatasetManifest(StrictModel):
    dataset_name: str = Field(min_length=1)
    dataset_version: str = Field(min_length=1)
    cases: list[BenchmarkCase] = Field(min_length=1)

    @model_validator(mode="after")
    def unique_cases(self):
        ids = [case.case_id for case in self.cases]
        if len(ids) != len(set(ids)):
            raise ValueError("case IDs must be unique")
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
