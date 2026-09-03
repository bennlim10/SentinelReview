"""Scanner-independent execution contract."""
from typing import Protocol
from pydantic import Field
from app.models import Finding, ScannerError, ScannerMetadata


class ScanError(Exception):
    pass


class ScannerResult(ScannerMetadata):
    findings: list[Finding] = Field(default_factory=list)
    errors: list[ScannerError] = Field(default_factory=list)


class Scanner(Protocol):
    def __call__(self, files: dict[str, bytes], timeout: float) -> ScannerResult: ...
