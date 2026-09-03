from copy import deepcopy

import pytest

from app.integrations.github import FileTooLarge, GitHubError
from app.models import AnalysisRequest
from app.services.analysis import analyze

REQUEST = AnalysisRequest(repository="owner/demo", pull_request_number=1)


@pytest.mark.parametrize("patch,expected", [
    ("@@ -1 +1 @@\n-x = 1\n+eval(input())", True),
    (None, None),
    ("@@ -1,2 +1,2 @@\n eval(input())\n-x = 1\n+x = 2", False),
])
async def test_findings_and_metadata(github, settings, patch, expected):
    github.changed_files.return_value[0]["patch"] = patch
    if expected is False:
        github.file_content.return_value = b"eval(input())\nx = 2\n"
    result = await analyze(REQUEST, github, settings)
    assert result.findings[0].is_on_changed_line is expected
    assert result.repository == "owner/demo"
    assert result.pull_request_number == 1
    assert result.title == "Example PR" and result.author == "alice"
    assert result.base_branch == "main" and result.head_branch == "feature"
    assert result.head_sha == "head123"
    assert result.python_files_scanned == 1 and result.findings_count == len(result.findings)
    assert result.analysis_complete
    assert bool(result.warnings) == (expected is None)
    assert github.file_content.call_args.args[:3] == ("fork/demo", "demo.py", "head123")


async def test_filtering(github, settings):
    github.changed_files.return_value = [{"filename": "a.js", "status": "modified"},
                                         {"filename": "gone.py", "status": "removed"}]
    github.pull_request.return_value["changed_files"] = 2
    result = await analyze(REQUEST, github, settings)
    assert result.python_files_scanned == 0
    assert result.skipped_files[0].filename == "gone.py"
    github.file_content.assert_not_called()


async def test_size_limit(github, settings):
    github.file_content.side_effect = FileTooLarge()
    result = await analyze(REQUEST, github, settings)
    assert not result.analysis_complete
    assert result.python_files_scanned == 0
    assert len(result.skipped_files) == 1


async def test_missing_listing(github, settings):
    github.pull_request.return_value["changed_files"] = 3001
    result = await analyze(REQUEST, github, settings)
    assert not result.analysis_complete
    assert "listing" in result.warnings[0]


async def test_moving_pr(github, settings):
    first = github.pull_request.return_value
    second = deepcopy(first)
    second["head"]["sha"] = "new"
    github.pull_request.side_effect = [first, second]
    with pytest.raises(GitHubError) as error:
        await analyze(REQUEST, github, settings)
    assert error.value.status_code == 409


@pytest.mark.parametrize("limit", ["count", "total"])
async def test_request_limits(github, settings, limit):
    first = github.changed_files.return_value[0]
    github.changed_files.return_value = [first, {**first, "filename": "second.py"}]
    github.pull_request.return_value["changed_files"] = 2
    if limit == "count":
        settings.max_python_files = 1
    else:
        settings.max_total_bytes = len(github.file_content.return_value)
    result = await analyze(REQUEST, github, settings)
    assert result.python_files_scanned == 1
    assert result.skipped_files[0].filename == "second.py"
    assert not result.analysis_complete
    assert github.file_content.call_count == 1


async def test_scan_error_is_partial(github, settings):
    github.file_content.return_value = b"def (\n"
    result = await analyze(REQUEST, github, settings)
    assert result.python_files_scanned == 0
    assert result.findings_count == 0
    assert not result.analysis_complete
    assert result.skipped_files[0].reason.startswith("Bandit:")


async def test_unavailable_file_is_partial(github, settings):
    github.file_content.side_effect = GitHubError("Missing", 404)
    result = await analyze(REQUEST, github, settings)
    assert not result.analysis_complete
    assert result.python_files_scanned == 0
    assert "unavailable" in result.skipped_files[0].reason
