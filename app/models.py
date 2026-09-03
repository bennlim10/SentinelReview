from typing import Literal

from pydantic import BaseModel, Field, model_validator


class AnalysisRequest(BaseModel):
    repository: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$")
    pull_request_number: int = Field(gt=0, strict=True)


class Evidence(BaseModel):
    source: str
    rule_id: str
    category: str
    severity: str
    confidence: str | None
    description: str
    cwe_ids: list[str]


class Finding(BaseModel):
    severity: Literal["LOW", "MEDIUM", "HIGH", "UNDEFINED"]
    confidence: Literal["LOW", "MEDIUM", "HIGH", "UNDEFINED"] | None
    category: str
    filename: str
    line_number: int = Field(ge=1)
    description: str
    source: Literal["bandit", "semgrep"] = "bandit"
    rule_id: str
    cwe_id: int | None = None
    is_on_changed_line: bool | None
    sources: list[str] = Field(default_factory=list)
    rule_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    evidence: list[Evidence] = Field(default_factory=list)

    @model_validator(mode="after")
    def populate_traceability(self):
        if not self.sources:
            self.sources = [self.source]
        if not self.rule_ids:
            self.rule_ids = [self.rule_id]
        if not self.cwe_ids and self.cwe_id is not None:
            self.cwe_ids = [f"CWE-{self.cwe_id}"]
        if not self.evidence:
            self.evidence = [Evidence(source=self.source, rule_id=self.rule_id,
                category=self.category, severity=self.severity, confidence=self.confidence,
                description=self.description, cwe_ids=list(self.cwe_ids))]
        return self


class SkippedFile(BaseModel):
    filename: str
    reason: str


class ScannedFile(BaseModel):
    filename: str
    # Inclusive ranges in the head version; null means unknown, [] means no additions.
    changed_line_ranges: list[tuple[int, int]] | None


class ScannerError(BaseModel):
    scanner: str
    kind: str
    message: str
    filename: str | None = None


class ScannerMetadata(BaseModel):
    scanner: str
    version: str | None = None
    config_identity: str | None = None
    scanned_files: list[str] = Field(default_factory=list)
    completed: bool = True


class AnalysisResponse(BaseModel):
    repository: str
    pull_request_number: int
    title: str
    author: str | None
    base_branch: str
    head_branch: str
    head_sha: str
    files_changed: int
    python_files_scanned: int
    findings_count: int
    findings: list[Finding]
    scanned_files: list[ScannedFile]
    skipped_files: list[SkippedFile]
    warnings: list[str]
    raw_findings_count: int = 0
    deduplicated_findings_count: int = 0
    findings_on_changed_lines: int = 0
    findings_by_scanner: dict[str, int] = Field(default_factory=dict)
    findings_by_severity: dict[str, int] = Field(default_factory=dict)
    scanner_errors: list[ScannerError] = Field(default_factory=list)
    scanner_metadata: list[ScannerMetadata] = Field(default_factory=list)
    analysis_complete: bool
