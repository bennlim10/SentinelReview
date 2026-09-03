from pathlib import Path
import subprocess

import pytest

from app.scanners.bandit import ScanError, scan_files


def test_real_bandit():
    findings, errors = scan_files({"../../unsafe.py": b"eval(input()) # nosec\n", "safe.py": b"x = 1\n"}, 30)
    assert errors == {}
    finding = next(f for f in findings if f.rule_id == "B307")
    assert finding.filename == "../../unsafe.py"
    assert finding.line_number == 1
    assert finding.source == "bandit"
    assert finding.severity == "MEDIUM"
    assert finding.is_on_changed_line is None


def test_syntax_error():
    findings, errors = scan_files({"bad.py": b"def (\n"}, 30)
    assert findings == []
    assert "bad.py" in errors


def test_empty():
    assert scan_files({}, 30) == ([], {})


@pytest.mark.parametrize("mode", ["timeout", "failure", "invalid"])
def test_failure_cleanup(monkeypatch, mode):
    paths = []
    def run(*args, **kwargs):
        paths.append(Path(kwargs["cwd"]))
        assert paths[-1].exists()
        if mode == "timeout":
            raise subprocess.TimeoutExpired("bandit", 1)
        return subprocess.CompletedProcess([], 2 if mode == "failure" else 0, stdout=b"invalid")
    monkeypatch.setattr(subprocess, "run", run)
    with pytest.raises(ScanError):
        scan_files({"file.py": b"pass"}, 1)
    assert not paths[0].exists()
