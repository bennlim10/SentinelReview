from starlette.concurrency import run_in_threadpool

from app.config import Settings
from app.integrations.github import FileTooLarge, GitHubClient, GitHubError
from app.models import AnalysisRequest, AnalysisResponse, ScannedFile, SkippedFile
from app.scanners.runner import run_scanners
from app.scanners.base import ScanError
from app.services.dedup import deduplicate
from collections import Counter
from app.services.patches import changed_lines, line_ranges


async def analyze(request: AnalysisRequest, github: GitHubClient, settings: Settings) -> AnalysisResponse:
    repo, number = request.repository, request.pull_request_number
    pr = await github.pull_request(repo, number)
    files = await github.changed_files(repo, number)
    warnings = []
    complete = len(files) == pr["changed_files"] and len({f["filename"] for f in files}) == len(files)
    if not complete:
        warnings.append("GitHub file listing is incomplete or inconsistent (maximum 3,000 files).")
    contents = {}
    coverage = {}
    skipped = []
    total = 0
    head_repo = (pr["head"]["repo"] or {}).get("full_name", repo)
    for file in files:
        name = file["filename"]
        if not name.endswith(".py"):
            continue
        reason = None
        if file["status"] == "removed":
            reason = "Deleted file has no head-version content."
        elif len(contents) >= settings.max_python_files:
            reason = "Python file count limit exceeded."
        elif total >= settings.max_total_bytes:
            reason = "Total content byte limit exceeded."
        if reason is None:
            try:
                content = await github.file_content(head_repo, name, pr["head"]["sha"],
                    min(settings.max_file_bytes, settings.max_total_bytes - total))
            except FileTooLarge:
                reason = "File or remaining total content byte limit exceeded."
            except GitHubError as exc:
                if exc.status_code != 404:
                    raise
                reason = "Head-version file unavailable from GitHub."
        if reason is not None:
            skipped.append(SkippedFile(filename=name, reason=reason))
            if file["status"] != "removed":
                complete = False
            continue
        total += len(content)
        contents[name] = content
        coverage[name] = changed_lines(file.get("patch"), file["additions"], file["deletions"], content)
        if coverage[name] is None:
            warnings.append(f"{name}: changed-line coverage unknown; patch missing, incomplete, or inconsistent.")
    # PR-files pagination is not snapshot-addressable. Reject a moving PR rather than
    # mix patches from one revision with file contents from another.
    latest = await github.pull_request(repo, number)
    if any(latest[side]["sha"] != pr[side]["sha"] for side in ("base", "head")) or latest["changed_files"] != pr["changed_files"]:
        raise GitHubError("PR changed during retrieval; retry the analysis.", 409)
    results = await run_in_threadpool(run_scanners, contents, settings)
    if contents and not any(result.completed for result in results):
        raise ScanError("All scanners failed: " + "; ".join(
            f"{result.scanner}: {error.message}" for result in results for error in result.errors))
    errors = [error for result in results for error in result.errors]
    successful_files = set().union(*(set(result.scanned_files) for result in results))
    for name in contents:
        if name not in successful_files:
            reasons = [error.message for error in errors if error.filename == name]
            skipped.append(SkippedFile(filename=name, reason="; ".join(reasons) or "No scanner completed this file."))
    complete = complete and all(result.completed and not result.errors
                               and set(result.scanned_files) == set(contents) for result in results)
    raw_findings = [finding for result in results for finding in result.findings]
    findings = deduplicate(raw_findings)
    for finding in findings:
        lines = coverage[finding.filename]
        finding.is_on_changed_line = None if lines is None else finding.line_number in lines
    scanned = [ScannedFile(filename=name, changed_line_ranges=line_ranges(coverage[name]))
               for name in contents if name in successful_files]
    return AnalysisResponse(
        repository=repo, pull_request_number=number, title=pr["title"],
        author=(pr.get("user") or {}).get("login"), base_branch=pr["base"]["ref"],
        head_branch=pr["head"]["ref"], head_sha=pr["head"]["sha"],
        files_changed=pr["changed_files"], python_files_scanned=len(scanned),
        findings_count=len(findings), findings=findings, scanned_files=scanned,
        skipped_files=skipped, warnings=warnings, analysis_complete=complete,
        raw_findings_count=len(raw_findings), deduplicated_findings_count=len(findings),
        findings_on_changed_lines=sum(f.is_on_changed_line is True for f in findings),
        findings_by_scanner={r.scanner: len(r.findings) for r in results},
        findings_by_severity=dict(Counter(f.severity for f in findings)),
        scanner_errors=[e.model_dump() for e in errors],
        scanner_metadata=[r.model_dump(exclude={"findings", "errors"}) for r in results],
    )
