"""The only place that selects concrete scanners."""
from app.config import Settings
from app.scanners import bandit, semgrep
from app.scanners.base import ScannerResult


def run_scanners(files: dict[str, bytes], settings: Settings) -> list[ScannerResult]:
    return [bandit.scan(files, settings.scan_timeout_seconds),
            semgrep.scan(files, settings.semgrep_timeout_seconds)]
