from unittest.mock import AsyncMock

import pytest

from app.config import Settings


@pytest.fixture
def settings():
    return Settings(_env_file=None, github_token=None)


@pytest.fixture
def github():
    client = AsyncMock()
    client.pull_request.return_value = {
        "title": "Example PR", "user": {"login": "alice"}, "changed_files": 1,
        "base": {"ref": "main", "sha": "base123", "repo": {"private": False}},
        "head": {"ref": "feature", "sha": "head123", "repo": {"private": False, "full_name": "fork/demo"}},
    }
    client.changed_files.return_value = [{"filename": "demo.py", "status": "modified",
        "additions": 1, "deletions": 1, "patch": "@@ -1 +1 @@\n-x = 1\n+eval(input())"}]
    client.file_content.return_value = b"eval(input())\n"
    return client


@pytest.fixture
def offline_semgrep(monkeypatch):
    """Keep service/API tests offline; adapter tests exercise real output shapes."""
    from app.scanners.base import ScannerResult
    from app.scanners import semgrep
    def scan(files, timeout):
        valid = []
        from app.scanners.base import ScannerError
        errors = []
        import ast
        for name, content in files.items():
            try:
                ast.parse(content)
                valid.append(name)
            except SyntaxError:
                errors.append(ScannerError(scanner="semgrep", kind="parse_error", filename=name,
                                           message="Semgrep: syntax error"))
        return ScannerResult(scanner="semgrep", scanned_files=valid, errors=errors)
    monkeypatch.setattr(semgrep, "scan", scan)


@pytest.fixture
def ai_settings(settings):
    from pydantic import SecretStr
    settings.ai_enabled = True
    settings.ai_provider = "openai"
    settings.ai_model = "test-model"
    settings.ai_endpoint = "https://provider.example/responses"
    settings.ai_api_key = SecretStr("test-only-credential")
    return settings


@pytest.fixture
def ai_response():
    from app.models import AnalysisResponse, Finding
    findings = [Finding(severity=severity, confidence="HIGH", category="test-category", filename="a.py",
        line_number=line, description="A deterministic test finding", rule_id="B307", cwe_id=78,
        is_on_changed_line=changed) for line, severity, changed in
        [(2, "HIGH", False), (5, "LOW", True), (8, "MEDIUM", True), (11, "HIGH", None)]]
    return AnalysisResponse(repository="owner/repo", pull_request_number=1, title="Test PR",
        author="test-author", base_branch="main", head_branch="feature", head_sha="test-sha",
        files_changed=1, python_files_scanned=1, findings_count=len(findings), findings=findings,
        scanned_files=[], skipped_files=[], warnings=[], analysis_complete=True)


@pytest.fixture
def ai_contents():
    return {"a.py": b"\n".join(f"value_{n} = {n}".encode() for n in range(1, 20))}


@pytest.fixture
def ai_context(ai_response, ai_contents):
    from app.ai.context import build_context
    return build_context(ai_response.findings[0], ai_response, ai_contents["a.py"], None, 12000, 15)


@pytest.fixture
def review_output():
    return dict(verdict="needs_review", exploitability="unknown", impact="medium", priority="high",
        confidence=0.6, reasoning="The supplied evidence needs additional application context.",
        remediation="Validate the input boundary before using this operation.", evidence_used=["scanner:0"])
