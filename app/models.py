from typing import Literal

from pydantic import BaseModel, Field


class AnalysisRequest(BaseModel):
    repository: str = Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9-]{0,38}/[A-Za-z0-9_][A-Za-z0-9_.-]{0,99}$")
    pull_request_number: int = Field(gt=0, strict=True)


class Finding(BaseModel):
    severity: Literal["LOW", "MEDIUM", "HIGH", "UNDEFINED"]
    confidence: Literal["LOW", "MEDIUM", "HIGH", "UNDEFINED"]
    category: str
    filename: str
    line_number: int = Field(ge=1)
    description: str
    source: Literal["bandit"] = "bandit"
    rule_id: str
    cwe_id: int | None = None
    is_on_changed_line: bool | None


class SkippedFile(BaseModel):
    filename: str
    reason: str


class ScannedFile(BaseModel):
    filename: str
    # Inclusive ranges in the head version; null means unknown, [] means no additions.
    changed_line_ranges: list[tuple[int, int]] | None


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
    analysis_complete: bool
