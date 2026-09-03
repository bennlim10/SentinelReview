# SentinelReview

SentinelReview v0.1 is an independent personal cybersecurity software engineering
project. It analyzes changed Python files in public GitHub pull requests using
Bandit and returns structured findings through a FastAPI REST API. It uses no
proprietary or company code.

## Setup

Requires Python 3.12 or newer. From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
cp .env.example .env
```

Optionally set `GITHUB_TOKEN` in `.env`. It is sent only to the fixed GitHub API
host and is not included in responses. The application rejects private repositories,
even if the token can access them. Without a token, public API rate limits apply.
Do not commit `.env`.

```bash
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Open [interactive API docs](http://127.0.0.1:8000/docs).

## Example request

Replace `owner/repo` and `123` with an actual public repository and PR number:

```bash
curl -X POST http://127.0.0.1:8000/api/v1/analyze \
  -H 'Content-Type: application/json' \
  -d '{"repository":"owner/repo","pull_request_number":123}'
```

The service accepts `owner/repo`, not a URL. PR numbers must be positive integers.
The caller waits for the response; there is no background job or persisted result.

## Response contract

Top-level metadata includes `repository`, `pull_request_number`, `title`, `author`
(GitHub login, nullable for unavailable users), `base_branch`, `head_branch`,
`head_sha`, `files_changed`, `python_files_scanned`, and `findings_count`.
`files_changed` is GitHub's total across all file types; `python_files_scanned`
counts files successfully processed by Bandit. `findings_count` counts returned
findings. Counts are computed from the actual request, not performance estimates.

Each item in `findings` contains:

| Field | Meaning |
| --- | --- |
| `severity` | Bandit's LOW, MEDIUM, HIGH, or UNDEFINED rating |
| `confidence` | Bandit's confidence rating, using the same enum |
| `category` | Bandit test name (for example `blacklist`) |
| `filename` | Repository-relative head-version filename |
| `line_number` | One-based primary line reported by Bandit |
| `description` | Bandit's issue description |
| `source` | `bandit` |
| `rule_id` | Bandit test ID |
| `cwe_id` | CWE number when supplied by Bandit, otherwise null |
| `is_on_changed_line` | true, false, or null, as described below |

`scanned_files` records each successfully scanned filename and its
`changed_line_ranges`: inclusive `[start, end]` pairs in head-file coordinates,
`[]` for a verified patch containing no added lines, or `null` for unknown coverage.
`skipped_files` gives filenames and reasons for deleted, unavailable, oversized,
limit-excluded, or unparseable Python files. Non-Python files are outside scope and
are not included in this list. `warnings` reports file-list and patch limitations.

`analysis_complete` means the file listing was complete and all eligible,
non-deleted Python files were scanned successfully. It does **not** mean that
changed-line coverage is known, that the PR is safe, or that every vulnerability
has been found. Check warnings and skipped files even when there are no findings.

## Changed-line semantics

Bandit scans the **complete head version** of each changed `.py` file. A unified
patch separately maps added lines into that version; replacements count as added
head lines plus deleted base lines. Removed lines have no head line to classify.

- `true`: the finding's primary `line_number` is an added/replacement line.
- `false`: a sufficiently validated patch exists, but that line is outside its
  additions. The finding can still be relevant to review.
- `null`: the patch is unavailable or cannot be validated reliably.

**A finding on a changed line does not prove the PR introduced a vulnerability.**
No baseline scan, data-flow comparison, or vulnerability-introduction analysis is
implemented. For multi-line findings, only Bandit's primary line is classified.

The parser checks hunk syntax and lengths, ordered non-overlapping hunks, total
additions/deletions against GitHub's file metadata, and context/added text against
the downloaded file. Missing patches, truncated hunks, omitted hunks detected by
count mismatches, content mismatches, and unsupported encodings produce `null`
for all findings in that file. Scanning still proceeds. Patch validation currently
supports UTF-8 (including BOM); Bandit may scan other Python encodings while their
changed-line coverage remains unknown. Rename-only files without patches also
receive unknown coverage.

GitHub does not guarantee an atomic snapshot across paginated PR-file requests.
The service checks base/head SHAs and total file count again after retrieval and
returns HTTP 409 if they changed. This detects ordinary concurrent updates but
cannot rule out every race or an internally inconsistent upstream response.
Counts and content checks are conservative validation, not a guarantee against
arbitrary upstream patch corruption.

## Architecture

```text
HTTP request → API route → analysis service → GitHub REST API
                              ↓
                        patch parsing
                              ↓
                        Bandit subprocess
                              ↓
                     Pydantic JSON response
```

| File | Responsibility |
| --- | --- |
| `app/main.py` | FastAPI application and route registration |
| `app/config.py` | Validated environment settings |
| `app/models.py` | Request, finding, file-coverage and response schemas |
| `app/api/routes.py` | HTTP endpoint, dependency wiring and error mapping |
| `app/integrations/github.py` | PR metadata, pagination, bounded content downloads |
| `app/services/analysis.py` | File selection, retrieval, scan coordination, metadata and coverage |
| `app/services/patches.py` | Conservative patch parsing and inclusive line ranges |
| `app/scanners/bandit.py` | Temporary-file handling, Bandit execution and normalization |
| `tests/conftest.py` | Shared mocked PR and settings fixtures |
| `tests/test_api.py` | HTTP responses, validation and errors |
| `tests/test_github.py` | Mocked REST behavior and download limits |
| `tests/test_analysis.py` | Orchestration, coverage, metadata and partial results |
| `tests/test_patches.py` | Patch parsing, truncation and coordinate cases |
| `tests/test_bandit.py` | Real scanner checks and simulated scanner failures |
| `app/**/__init__.py` | Python package markers |
| `pyproject.toml` | Packaging, dependencies, Python version and pytest configuration |
| `.env.example` | Documented environment defaults |
| `.gitignore` | Local secrets, virtual environments and generated-file exclusions |

File contents are requested at the captured head SHA, using the fork repository
when applicable. GitHub-supplied raw/download URLs are never followed. Repository
paths are mapped to generated temporary filenames, preventing local path
traversal. Bandit receives an application-owned configuration and ignores `nosec`
comments so repository content cannot suppress checks. The repository is never
cloned, imported, installed or executed. A temporary directory is filesystem
isolation, **not an OS sandbox** for the scanner process.

Network I/O is asynchronous; the Bandit subprocess runs off the event loop. It has
a timeout and runs without a shell. Temporary files are removed on success or
failure. Syntax errors are reported as skipped files rather than clean scans.
Scanner startup failures, invalid reports and timeouts fail the request.

## Configuration and limits

| Variable | Default | Purpose |
| --- | --- | --- |
| `GITHUB_TOKEN` | unset | Optional GitHub API token |
| `GITHUB_TIMEOUT_SECONDS` | 20 | Per-network-operation HTTP timeout |
| `SCAN_TIMEOUT_SECONDS` | 30 | Bandit subprocess timeout |
| `MAX_PYTHON_FILES` | 50 | Maximum files submitted to Bandit per request |
| `MAX_FILE_BYTES` | 500000 | Maximum content bytes for one file |
| `MAX_TOTAL_BYTES` | 5000000 | Maximum retained content bytes per request |

GitHub PR-file pagination is limited to 3,000 entries. If the number retrieved does
not match PR metadata, results are explicitly marked incomplete. Downloads are
bounded while streaming; each metadata response also has a 20 MB cap. Limit-excluded
Python files are reported as skipped. Limits apply per request; there is no global
admission control, process memory sandbox, or overall request deadline. This
version is intended for local use and does not implement a public hosted service.

Expected errors use FastAPI's `{"detail": "..."}` format:

| Status | Meaning |
| --- | --- |
| 400 | Private repository outside supported scope |
| 404 | Repository or PR not found/accessible |
| 409 | PR changed during retrieval; retry |
| 422 | Invalid request input |
| 429 | GitHub rate limit exceeded |
| 502 | Upstream error or scanner failure/timeout |
| 504 | GitHub network timeout |

Individual unavailable head files produce partial results. Other upstream failures
abort the request. Bandit is a heuristic Python static analyzer: findings require
human review, and false positives and false negatives are possible. Full-file
scanning can report pre-existing issues. This version has no LLM, frontend,
database, authentication, additional scanner, background jobs, or deployment
infrastructure.

## Tests

```bash
python -m pytest -q
```

Tests use mocked GitHub HTTP responses and do not require network access or a
token. Scanner and API/service tests also execute the installed Bandit on small,
locally authored fixture snippets; those snippets are never executed as Python.
Test results should be taken from an actual local run. The suite does not prove
live GitHub availability or compatibility with every supported Python version.

References: [GitHub PR REST API](https://docs.github.com/en/rest/pulls/pulls),
[GitHub repository contents API](https://docs.github.com/en/rest/repos/contents),
and [Bandit JSON output](https://bandit.readthedocs.io/en/latest/formatters/json.html).
