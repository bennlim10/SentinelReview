"""Provider-independent, strict review contracts; no scanner-model imports."""
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid", strict=True)


class ReviewOutput(StrictModel):
    verdict: Literal["likely_valid", "likely_false_positive", "needs_review"]
    exploitability: Literal["low", "medium", "high", "unknown"]
    impact: Literal["low", "medium", "high", "unknown"]
    priority: Literal["low", "medium", "high", "critical"]
    confidence: float = Field(ge=0, le=1, allow_inf_nan=False)
    reasoning: str = Field(min_length=1, max_length=1500)
    remediation: str = Field(min_length=1, max_length=1500)
    evidence_used: list[str] = Field(min_length=1, max_length=20)


class PRContext(StrictModel):
    repository: str
    pull_request_number: int
    title: str
    base_branch: str
    head_branch: str
    head_sha: str


class FindingContext(StrictModel):
    filename: str
    line_number: int
    severity: str
    confidence: str | None
    category: str
    description: str
    sources: list[str]
    rule_ids: list[str]
    cwe_ids: list[str]
    is_on_changed_line: bool | None


class ReferencedEvidence(StrictModel):
    ref: str
    source: str
    rule_id: str
    category: str
    severity: str
    confidence: str | None
    description: str
    cwe_ids: list[str]


class CodeLine(StrictModel):
    ref: str
    line: int
    text: str


class DiffLine(StrictModel):
    ref: str
    head_line: int | None
    text: str


class ReviewInput(StrictModel):
    finding_id: str
    context_id: str
    prompt_version: str
    pr: PRContext
    finding: FindingContext
    scanner_evidence: list[ReferencedEvidence]
    code: list[CodeLine]
    diff: list[DiffLine]
    truncation_notes: list[str]

    def references(self) -> set[str]:
        return {item.ref for item in [*self.scanner_evidence, *self.code, *self.diff]}


class ProviderMetadata(StrictModel):
    reported_model: str | None = None
    response_id: str | None = None
    request_id: str | None = None


class ProviderResult(StrictModel):
    output: ReviewOutput
    metadata: ProviderMetadata = Field(default_factory=ProviderMetadata)


class AIError(StrictModel):
    kind: str
    message: str


class AIReview(StrictModel):
    status: Literal["disabled", "skipped", "completed", "failed"] = "disabled"
    selected: bool = False
    skip_reason: str | None = None
    finding_id: str | None = None
    context_id: str | None = None
    context_chars: int | None = None
    truncation_notes: list[str] = Field(default_factory=list)
    result: ReviewOutput | None = None
    error: AIError | None = None
    provider_metadata: ProviderMetadata | None = None


class AISummary(StrictModel):
    ai_enabled: bool = False
    ai_findings_selected: int = 0
    ai_findings_requested: int = 0
    ai_findings_completed: int = 0
    ai_findings_failed: int = 0
    ai_findings_skipped: int = 0
    ai_findings_disabled: int = 0
    ai_verdict_counts: dict[str, int] = Field(default_factory=dict)
    ai_priority_counts: dict[str, int] = Field(default_factory=dict)
    ai_runtime_seconds: float = 0.0
    prompt_version: str | None = None
    configured_provider: str | None = None
    configured_model: str | None = None
    errors: list[AIError] = Field(default_factory=list)
    export_error: AIError | None = None
