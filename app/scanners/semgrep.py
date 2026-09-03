"""Semgrep Community Edition adapter. No repository configuration is loaded."""
import json
import os
from pathlib import Path
import re
import subprocess
import sys
from tempfile import TemporaryDirectory
from importlib.metadata import version, PackageNotFoundError

from app.models import Evidence, Finding
from app.scanners.base import ScannerError, ScannerResult

CONFIG = "p/security-audit"
SEVERITIES = {"ERROR": "HIGH", "WARNING": "MEDIUM", "INFO": "LOW",
              "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW", "CRITICAL": "HIGH"}


def normalize(item: dict, filename: str) -> Finding:
    extra = item["extra"]
    metadata = extra.get("metadata") or {}
    cwes = metadata.get("cwe", [])
    if isinstance(cwes, str):
        cwes = [cwes]
    ids = sorted({f"CWE-{int(match.group(1))}" for value in cwes
                  if (match := re.match(r"^CWE-(\d+)\b", str(value)))})
    confidence = metadata.get("confidence")
    if confidence not in {"LOW", "MEDIUM", "HIGH", "UNDEFINED"}:
        confidence = None
    category = str(metadata.get("subcategory") or metadata.get("category") or item["check_id"])
    return Finding(severity=SEVERITIES.get(extra["severity"], "UNDEFINED"),
        confidence=confidence, category=category, filename=filename,
        line_number=item["start"]["line"], description=extra["message"],
        source="semgrep", rule_id=item["check_id"], cwe_ids=ids,
        cwe_id=int(ids[0][4:]) if ids else None, is_on_changed_line=None,
        evidence=[Evidence(source="semgrep", rule_id=item["check_id"], category=category,
            severity=extra["severity"], confidence=metadata.get("confidence"),
            description=extra["message"], cwe_ids=ids)])


def scan(files: dict[str, bytes], timeout: float) -> ScannerResult:
    try:
        tool_version = version("semgrep")
    except PackageNotFoundError:
        tool_version = None
    result = ScannerResult(scanner="semgrep", version=tool_version, config_identity=CONFIG)
    if not files:
        return result
    with TemporaryDirectory(prefix="sentinelreview-semgrep-") as directory:
        root = Path(directory)
        targets = root / "targets"
        targets.mkdir()
        mapping = {}
        for index, (filename, content) in enumerate(files.items()):
            path = targets / f"file_{index}.py"
            path.write_bytes(content)
            mapping[str(path)] = filename
        env = {key: value for key, value in os.environ.items()
               if not key.startswith("SEMGREP_") and key not in {"GITHUB_TOKEN", "GH_TOKEN"}}
        env.update(SEMGREP_SETTINGS_FILE=str(root / "settings.yml"),
                   SEMGREP_LOG_FILE=str(root / "semgrep.log"), SEMGREP_SEND_METRICS="off")
        try:
            process = subprocess.run([str(Path(sys.executable).with_name("semgrep.exe" if os.name == "nt" else "semgrep")),
                "scan", "--config", CONFIG,
                "--json", "--metrics=off", "--disable-version-check", "--disable-nosem",
                "--no-git-ignore", "--oss-only", "--jobs", "1", "--max-target-bytes", "0",
                "--timeout", str(max(1, int(timeout))), str(targets)],
                cwd=root, env=env, capture_output=True, timeout=timeout, check=False)
            if process.returncode != 0:
                result.completed = False
                result.errors.append(ScannerError(scanner="semgrep", kind="execution_error",
                    message=f"Semgrep exited with status {process.returncode}; scan/configuration failed."))
                return result
            report = json.loads(process.stdout)
            # Semgrep scan does not use --error: findings themselves do not change exit status.
            if not isinstance(report["results"], list) or not isinstance(report["errors"], list):
                raise ValueError("Invalid result arrays")
            if report.get("version"):
                result.version = report["version"]
            def filename(path):
                path = Path(path)
                return mapping[str(path if path.is_absolute() else root / path)]
            failed = set()
            for error in report["errors"]:
                path = error.get("path")
                name = filename(path) if path else None
                if name:
                    failed.add(name)
                result.errors.append(ScannerError(scanner="semgrep", kind=str(error.get("type", "scan_error")),
                    filename=name, message="Semgrep reported an analysis error; coverage may be incomplete."))
            scanned = {filename(path) for path in report["paths"]["scanned"]}
            for name in sorted(set(files) - scanned - failed):
                result.errors.append(ScannerError(scanner="semgrep", kind="file_skipped", filename=name,
                    message="Semgrep did not report this file as scanned."))
            result.scanned_files = sorted(scanned - failed)
            result.findings = [normalize(item, filename(item["path"])) for item in report["results"]]
            return result
        except subprocess.TimeoutExpired:
            kind, message = "timeout", "Semgrep scan timed out."
        except OSError:
            kind, message = "execution_error", "Semgrep could not be started."
        except (ValueError, KeyError, TypeError):
            kind, message = "invalid_report", "Semgrep returned an invalid report."
        result.completed = False
        result.findings = []
        result.scanned_files = []
        result.errors = [ScannerError(scanner="semgrep", kind=kind, message=message)]
        return result
