from starlette.concurrency import run_in_threadpool

from app.config import Settings
from app.integrations.github import FileTooLarge, GitHubClient, GitHubError
from app.models import AnalysisRequest, AnalysisResponse, ScannedFile, SkippedFile
from app.scanners.bandit import scan_files
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
    findings, errors = await run_in_threadpool(scan_files, contents, settings.scan_timeout_seconds)
    for filename, reason in errors.items():
        skipped.append(SkippedFile(filename=filename, reason=f"Bandit: {reason}"))
        complete = False
    findings = [finding for finding in findings if finding.filename not in errors]
    for finding in findings:
        lines = coverage[finding.filename]
        finding.is_on_changed_line = None if lines is None else finding.line_number in lines
    scanned = [ScannedFile(filename=name, changed_line_ranges=line_ranges(coverage[name]))
               for name in contents if name not in errors]
    return AnalysisResponse(
        repository=repo, pull_request_number=number, title=pr["title"],
        author=(pr.get("user") or {}).get("login"), base_branch=pr["base"]["ref"],
        head_branch=pr["head"]["ref"], head_sha=pr["head"]["sha"],
        files_changed=pr["changed_files"], python_files_scanned=len(scanned),
        findings_count=len(findings), findings=findings, scanned_files=scanned,
        skipped_files=skipped, warnings=warnings, analysis_complete=complete,
    )
