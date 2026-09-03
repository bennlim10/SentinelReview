import pytest
from app.models import AnalysisRequest, Finding
from app.scanners.base import ScannerError, ScannerResult, ScanError
from app.services.analysis import analyze

REQUEST = AnalysisRequest(repository="o/r", pull_request_number=1)
RULE = "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true"


def result(scanner, severity="LOW"):
    return ScannerResult(scanner=scanner, version="known-version", config_identity="known-config",
        scanned_files=["demo.py"], findings=[Finding(source=scanner, severity=severity,
        confidence="HIGH" if scanner == "bandit" else None, category="shell", filename="demo.py",
        line_number=1, description="shell call", rule_id="B602" if scanner == "bandit" else RULE,
        cwe_id=78, is_on_changed_line=None)])


@pytest.mark.parametrize("patch_known", [True, False])
async def test_merge_metrics_and_changed_line(monkeypatch, github, settings, patch_known):
    if not patch_known:
        github.changed_files.return_value[0]["patch"] = None
    monkeypatch.setattr("app.services.analysis.run_scanners", lambda *args: [result("bandit"), result("semgrep", "HIGH")])
    response = await analyze(REQUEST, github, settings)
    assert response.raw_findings_count == 2
    assert response.deduplicated_findings_count == response.findings_count == 1
    assert response.findings_on_changed_lines == int(patch_known)
    assert response.findings[0].is_on_changed_line is (True if patch_known else None)
    assert response.findings_by_scanner == {"bandit": 1, "semgrep": 1}
    assert response.findings_by_severity == {"HIGH": 1}
    assert response.analysis_complete
    assert response.scanner_metadata[0].version == "known-version"


@pytest.mark.parametrize("survivor", ["bandit", "semgrep"])
async def test_partial_failure(monkeypatch, github, settings, survivor):
    failed = "semgrep" if survivor == "bandit" else "bandit"
    error = ScannerResult(scanner=failed, completed=False,
        errors=[ScannerError(scanner=failed, kind="timeout", message="timed out")])
    monkeypatch.setattr("app.services.analysis.run_scanners", lambda *args: [result(survivor), error])
    response = await analyze(REQUEST, github, settings)
    assert not response.analysis_complete and response.python_files_scanned == 1
    assert response.findings_by_scanner == {survivor: 1, failed: 0}
    assert response.findings[0].source == survivor
    assert response.scanner_errors[0].scanner == failed


async def test_all_failed(monkeypatch, github, settings):
    monkeypatch.setattr("app.services.analysis.run_scanners", lambda *args: [ScannerResult(scanner=name,
        completed=False, errors=[ScannerError(scanner=name, kind="timeout", message="timed out")])
        for name in ["bandit", "semgrep"]])
    with pytest.raises(ScanError, match="All scanners failed"):
        await analyze(REQUEST, github, settings)
