import json
from pathlib import Path
import subprocess

import pytest

from app.scanners import semgrep


def item(path="/safe/file.py", *, severity="WARNING", metadata=None):
    return {"check_id": "python.example", "path": path, "start": {"line": 3},
            "extra": {"severity": severity, "message": "Example finding",
                      "metadata": metadata or {}}}


@pytest.mark.parametrize("severity,expected", [("ERROR", "HIGH"), ("WARNING", "MEDIUM"),
    ("INFO", "LOW"), ("OTHER", "UNDEFINED"), ("CRITICAL", "HIGH")])
def test_normalization(severity, expected):
    finding = semgrep.normalize(item(severity=severity, metadata={"cwe": ["CWE-078: shell", "CWE-89: SQL"],
        "confidence": "HIGH", "category": "security"}), "repo/file.py")
    assert finding.severity == expected
    assert finding.cwe_ids == ["CWE-78", "CWE-89"]
    assert finding.sources == ["semgrep"] and finding.rule_ids == ["python.example"]
    assert finding.confidence == "HIGH"
    assert finding.filename == "repo/file.py" and finding.line_number == 3
    assert finding.evidence[0].severity == severity


def test_missing_confidence_and_cwe():
    finding = semgrep.normalize(item(), "a.py")
    assert finding.confidence is None and finding.cwe_id is None and finding.cwe_ids == []


@pytest.mark.parametrize("mode", ["success", "zero", "timeout", "failure", "invalid", "file_error", "missing_file"])
def test_execution(monkeypatch, mode):
    roots = []
    def run(command, **kwargs):
        assert Path(command[0]).name in {"semgrep", "semgrep.exe"}
        assert "-m" not in command
        root = Path(kwargs["cwd"])
        roots.append(root)
        path = str(root / "targets/file_0.py")
        assert Path(path).read_bytes() == b"eval(input())"
        assert "--metrics=off" in command and "--disable-nosem" in command
        assert kwargs.get("shell", False) is False
        assert kwargs["timeout"] == 2
        if mode == "timeout":
            raise subprocess.TimeoutExpired(command, 2)
        report = {"version": "test-version", "results": [item(path)] if mode == "success" else [],
                  "errors": [{"path": path, "type": "ParseError"}] if mode == "file_error" else [],
                  "paths": {"scanned": [] if mode == "missing_file" else [path]}}
        return subprocess.CompletedProcess(command, 2 if mode == "failure" else 0,
            stdout=b"invalid" if mode == "invalid" else json.dumps(report).encode())
    monkeypatch.setattr(subprocess, "run", run)
    result = semgrep.scan({"../../file.py": b"eval(input())"}, 2)
    assert not roots[0].exists()
    if mode in {"timeout", "failure", "invalid"}:
        assert not result.completed and result.errors and not result.findings
    elif mode in {"file_error", "missing_file"}:
        assert result.errors and not result.scanned_files
    else:
        assert result.completed and not result.errors
        assert result.version == "test-version"
        assert result.config_identity == "p/security-audit"
        assert result.scanned_files == ["../../file.py"]
        assert len(result.findings) == (1 if mode == "success" else 0)


def test_empty():
    result = semgrep.scan({}, 2)
    assert result.completed and not result.errors and not result.findings


def test_local_config_does_not_inherit_proxy(monkeypatch, tmp_path):
    rules = tmp_path / "rules.yml"
    rules.write_text("rules: []\n")
    monkeypatch.setenv("HTTPS_PROXY", "https://proxy.example")
    def run(command, **kwargs):
        assert "HTTPS_PROXY" not in kwargs["env"]
        assert Path(kwargs["env"]["SSL_CERT_FILE"]).is_file()
        root = Path(kwargs["cwd"])
        path = str(root / "targets/file_0.py")
        report = {"version": "test", "results": [], "errors": [],
                  "paths": {"scanned": [path]}}
        return subprocess.CompletedProcess(command, 0, stdout=json.dumps(report).encode())
    monkeypatch.setattr(subprocess, "run", run)
    result = semgrep.scan({"file.py": b"pass"}, 2, str(rules))
    assert result.completed and result.scanned_files == ["file.py"]
