import json
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory

from app.models import Finding
from app.scanners.base import ScanError, ScannerError, ScannerResult
from importlib.metadata import version, PackageNotFoundError


def scan_files(files: dict[str, bytes], timeout: float) -> tuple[list[Finding], dict[str, str]]:
    if not files:
        return [], {}
    with TemporaryDirectory(prefix="sentinelreview-") as directory:
        root = Path(directory)
        mapping = {}
        for index, (filename, content) in enumerate(files.items()):
            target = root / f"file_{index}.py"
            target.write_bytes(content)
            mapping[str(target)] = filename
        config = root / "bandit.yaml"
        config.write_text("{}\n")
        try:
            result = subprocess.run(
                [sys.executable, "-m", "bandit", "-r", str(root), "-f", "json",
                 "-c", str(config), "--ignore-nosec", "-q"],
                cwd=root, capture_output=True, timeout=timeout, check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise ScanError("Bandit scan timed out.") from exc
        except OSError as exc:
            raise ScanError("Bandit could not be started.") from exc
        if result.returncode not in (0, 1):
            raise ScanError("Bandit failed to complete.")
        try:
            report = json.loads(result.stdout)
            errors = {mapping[item["filename"]]: item["reason"] for item in report["errors"]}
            findings = [Finding(
                severity=item["issue_severity"], confidence=item["issue_confidence"],
                category=item["test_name"], filename=mapping[item["filename"]],
                line_number=item["line_number"], description=item["issue_text"],
                rule_id=item["test_id"], cwe_id=(item.get("issue_cwe") or {}).get("id"),
                is_on_changed_line=None,
            ) for item in report["results"]]
            processed = {mapping[path] for path in report["metrics"] if path in mapping}
            if processed | set(errors) != set(files):
                raise ScanError("Bandit did not account for every submitted file.")
            return findings, errors
        except (ValueError, KeyError, TypeError) as exc:
            raise ScanError("Bandit returned an invalid report.") from exc


def scan(files: dict[str, bytes], timeout: float) -> ScannerResult:
    try:
        tool_version = version("bandit")
    except PackageNotFoundError:
        tool_version = None
    result = ScannerResult(scanner="bandit", version=tool_version,
                           config_identity="application defaults; ignore-nosec")
    try:
        findings, errors = scan_files(files, timeout)
        result.findings = [f for f in findings if f.filename not in errors]
        result.scanned_files = sorted(set(files) - set(errors))
        result.errors = [ScannerError(scanner="bandit", kind="file_error", filename=name,
                                     message="Bandit: " + reason) for name, reason in errors.items()]
    except ScanError as exc:
        result.completed = False
        result.errors = [ScannerError(scanner="bandit", kind="timeout" if "timed out" in str(exc) else "execution_error",
                                      message=str(exc))]
    return result
