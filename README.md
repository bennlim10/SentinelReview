# SentinelReview

**AI-assisted security analysis for GitHub pull requests.**

**[Live Demo](https://sentinel-review-rouge.vercel.app)**

SentinelReview combines deterministic static analysis, cross-scanner normalization,
contextual AI reasoning, and reproducible security evaluation to help identify and
prioritize security issues in code changes. The current development version is
**v0.5** and is an independent personal cybersecurity project.

Key capabilities:

- Public GitHub pull-request ingestion pinned to the PR head commit
- Bandit and Semgrep Community Edition static analysis
- A common normalized security-finding schema with scanner-specific evidence
- Conservative cross-scanner deduplication
- Changed-line classification with explicit incomplete-coverage handling
- Optional, disabled-by-default contextual AI security reasoning
- A reproducible evaluation harness with strict case-target matching
- A transparent real-world CVE benchmark methodology
- 189 automated tests covering deterministic, AI, API, and evaluation behavior

Given a public repository and PR number, SentinelReview scans complete changed
Python files, conservatively merges equivalent findings, and returns structured
JSON. The local Next.js interface presents the same real backend response. No
proprietary or company code is used.

The repository includes the deployed Next.js analysis interface and Docker-based
backend configuration. There is no database, authentication, background worker,
webhook, or repository cloning.

AI reviews do not replace scanners or change deterministic severity. Live OpenAI
validation is **pending** because API credentials are not configured; AI tests use
fake providers and mocked HTTP responses. No live AI response has been generated.

## Current validation status

- The full suite contains **189 automated tests** after adding the local frontend
  CORS checks.
- Evaluation includes synthetic harness validation and a real-world pilot benchmark.
- The pilot contains **3 vulnerable/fixed pairs (6 cases)** with immutable source
  references, explicit assessment scopes, hashes, provenance, and license metadata.
- Bandit, Semgrep, and the combined deterministic pipeline each detected **0 of 3**
  vulnerable pilot targets within the labeled scopes; all three fixed controls were
  true negatives.
- This pilot validates methodology and pipeline behavior. It is not an overall
  accuracy, production-effectiveness, false-positive-reduction, or AI-improvement
  benchmark.
- Contextual AI reasoning is implemented and covered with fake-provider tests, but
  live provider validation has not been performed.

## Setup

Requires Python 3.12+ and a platform supported by Semgrep's native engine. The live
v0.2 validation used Python 3.14 on macOS ARM64. From the repository root:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
cp .env.example .env
python -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000
```

Set `GITHUB_TOKEN` in `.env` optionally. Private repositories remain unsupported.
The token is sent only to GitHub's fixed API host; public access without a token is
subject to GitHub's unauthenticated rate limits. Do not commit `.env`.

The Semgrep adapter uses the `semgrep` console executable alongside the running
Python interpreter. It does not use the deprecated `python -m semgrep` entry point.
Semgrep fetches the maintained `p/security-audit` registry configuration, so live
analysis requires access to GitHub and the Semgrep registry. No Semgrep account or
token is required. A registry failure is a scanner error, not a clean result.

Open [interactive API documentation](http://127.0.0.1:8000/docs).

For the local web interface, start a second terminal after the backend is running:

```bash
cd frontend
cp .env.example .env.local
pnpm install
pnpm dev
```

Then open [the SentinelReview interface](http://localhost:3000). The frontend calls
the configured real backend and does not include mock findings.

```bash
curl -X POST http://127.0.0.1:8000/api/v1/analyze \
  -H 'Content-Type: application/json' \
  -d '{"repository":"PyCQA/bandit","pull_request_number":1116}'
```

The request still accepts `owner/repo` and a positive integer PR number. The caller
waits for the response; nothing is persisted by the service.

## Deployment

The public application uses a Vercel-hosted Next.js frontend and a Docker-based
FastAPI service on Render:

```text
Browser → https://sentinel-review-rouge.vercel.app
        → https://sentinelreview-api.onrender.com
        → GitHub REST API + Bandit + Semgrep
```

The production frontend sets
`NEXT_PUBLIC_SENTINELREVIEW_API_URL=https://sentinelreview-api.onrender.com`.
The backend sets `SENTINELREVIEW_CORS_ORIGINS` to the exact Vercel origin and
`AI_ENABLED=false`. `GITHUB_TOKEN` remains optional for public repositories and is
not configured in the public deployment. Render reads its assigned `PORT`; the
container binds Uvicorn to `0.0.0.0`. The health check is `GET /health`.

The Render free instance can spin down after inactivity, so its first request may
take 50 seconds or more. Local setup remains independent and continues to use the
localhost defaults in `.env.example` and `frontend/.env.example`. Deployment
credentials and provider-managed environment values must remain outside Git.

AI reasoning is optional and disabled in this public deployment. No AI provider
key, model, or endpoint is configured.

## Architecture

```text
POST /api/v1/analyze
  → GitHub metadata and paginated changed files
  → full Python contents at captured head SHA + validated patch line ranges
  → scanner runner
      → Bandit adapter → normalized scanner result
      → Semgrep adapter → normalized scanner result
  → conservative deduplication → changed-line classification
  → metadata, evidence, coverage, metrics, errors as JSON
```

| Module | Responsibility |
| --- | --- |
| `app/main.py` | FastAPI application |
| `app/config.py` | Validated environment settings |
| `app/models.py` | Common findings, evidence, coverage, metadata and API schemas |
| `app/api/routes.py` | Endpoint, dependencies and HTTP error mapping |
| `app/integrations/github.py` | GitHub metadata, pagination, bounded downloads |
| `app/scanners/base.py` | Common scanner interface and result |
| `app/scanners/bandit.py` | Bandit invocation, normalization and file errors |
| `app/scanners/semgrep.py` | Semgrep invocation, normalization and file coverage |
| `app/scanners/runner.py` | Select and run scanners independently |
| `app/services/analysis.py` | Retrieval, orchestration and response assembly |
| `app/services/patches.py` | Conservative unified-diff validation |
| `app/services/dedup.py` | Explicit cross-scanner equivalence matching |

Scanners run sequentially off the event loop. Each uses generated filenames in a
fresh temporary directory, subprocess argument lists without a shell, an explicit
configuration, and an execution timeout. Repository code is never imported,
installed, or executed. Repository configuration and `nosec`/`nosemgrep`
suppressions are not honored. Semgrep uses local Community Edition scanning;
metrics and version checks are disabled. Temporary settings/logs are cleaned up,
and GitHub/Semgrep token environment variables are not passed to Semgrep.
A temporary directory is not an OS sandbox for the scanner process.

GitHub-provided download URLs are not followed. Contents are requested from the
fork repository when applicable, pinned to the captured head SHA. Base/head SHAs
and changed-file count are rechecked after retrieval; observed changes return 409.
This detects normal concurrent updates but cannot guarantee an atomic snapshot
across GitHub's separate paginated requests.

## Findings and compatibility

Existing PR metadata remains: `repository`, `pull_request_number`, `title`,
`author` (nullable GitHub login), `base_branch`, `head_branch`, `head_sha`,
`files_changed`, `python_files_scanned`, and `findings_count`.

Each finding contains:

| Field | Meaning |
| --- | --- |
| `severity` | LOW, MEDIUM, HIGH or UNDEFINED |
| `confidence` | Scanner-provided normalized confidence, or null when unavailable |
| `category` | Representative scanner category/test name |
| `filename`, `line_number` | Repository filename and one-based primary line |
| `description` | Representative scanner message |
| `sources` | All contributing scanner names |
| `rule_ids` | All contributing rule IDs |
| `cwe_ids` | Normalized CWE strings, e.g. `CWE-78`; empty when unavailable |
| `evidence` | Each scanner's source, rule, category, original severity/confidence, message and CWE IDs |
| `is_on_changed_line` | true, false or null |

The v0.1 singular `source`, `rule_id`, and integer-or-null `cwe_id` remain as
compatibility fields identifying the representative finding. For a merged pair,
Bandit is the representative; Semgrep-only findings identify Semgrep. Existing
clients must allow `source="semgrep"` and nullable confidence. Plural fields and
evidence are authoritative for merged attribution; singular fields cannot describe
all contributing scanners. Evidence preserves rule/source associations.

Bandit severity and confidence retain their meanings. Semgrep ERROR/WARNING/INFO
map to HIGH/MEDIUM/LOW. Native HIGH/MEDIUM/LOW map directly, CRITICAL maps to HIGH,
and unknown values map to UNDEFINED. These are display normalization conventions,
not assertions that the scanners' risk ratings are equivalent. Missing or unknown
Semgrep confidence normalizes to null; raw confidence is retained in evidence.

`findings_count` counts final deduplicated findings rather than Bandit-only results.
`python_files_scanned` counts distinct files successfully scanned by at least one
scanner. Per-scanner coverage appears in `scanner_metadata`.

## Conservative deduplication

A pair is merged only if **all** conditions hold:

1. Different scanners (Bandit and Semgrep).
2. Exact same repository filename.
3. Exact same primary line number; adjacent lines do not match.
4. At least one shared normalized CWE.
5. An explicit equivalence mapping between the two rule IDs.
6. Each finding has exactly one eligible counterpart; ambiguous matches stay separate.

The initial mapping is Bandit `B602` ↔ Semgrep
`python.lang.security.audit.subprocess-shell-true.subprocess-shell-true`.
The Semgrep rule explicitly references B602 in its upstream metadata. It detects a
subset of shell=True calls; both scanners still must report the same primary line
and CWE before merging. Rules with similar wording, generic categories, or a
shared CWE alone are not mapped automatically. No transitive clustering occurs.

Merges union sources, rules and CWEs, keep the strongest normalized severity, retain
all evidence, and keep representative confidence without implying extra certainty.
Input findings are not mutated. This intentionally misses duplicates. Same-line
matching plus a rule mapping still cannot prove semantic identity in every program;
multiple statements on one line and evolving upstream rules remain limitations.

## Changed-line semantics

Bandit and Semgrep analyze the **complete head version** of each changed `.py`
file, including existing code. Added/replacement lines are identified separately
from GitHub's patch. Classification happens after deduplication:

- `true`: the finding's primary line is added/replaced by the PR.
- `false`: a validated patch exists and the primary line is outside additions.
- `null`: coverage cannot be determined reliably.

**On a changed line does not mean introduced by the PR.** No baseline analysis is
performed. Multi-line findings use the scanner's primary line only. Exact-line
merging preserves this coordinate. Deleted lines have no head coordinate.

`scanned_files[].changed_line_ranges` contains inclusive `[start,end]` pairs,
`[]` when a verified patch has no additions, or null for unknown coverage. The
parser checks hunk lengths/order, additions/deletions against GitHub metadata, and
context/added text against downloaded content. Missing/truncated/count-mismatched
patches or content mismatches produce null. Patch decoding supports UTF-8 including
BOM; other Python encodings can still be scanned but have unknown line coverage.
Rename-only files without patches also have unknown coverage.

## Metrics, coverage and errors

- `raw_findings_count`: normalized findings returned by scanners before merging.
- `deduplicated_findings_count`: final count, equal to `findings_count`.
- `findings_on_changed_lines`: final findings whose classification is true.
- `findings_by_scanner`: raw counts; a failed scanner's zero is not a clean scan.
- `findings_by_severity`: final counts for severities present in the response.
- `scanner_errors`: scanner, kind, optional filename, sanitized explanation.
- `scanner_metadata`: scanner version, configuration identity, completed flag and
  successfully scanned repository filenames. `completed` means an execution
  produced a usable report; inspect errors for partial file/rule failures.

`analysis_complete` requires a complete GitHub listing and successful coverage of
all downloaded eligible files by **both** scanners, with no scanner errors and no
eligible Python files excluded during download. Unknown patch coverage is reported
in warnings and does not by itself make scanning incomplete. A complete scan does
not imply that the code is safe or that every vulnerability was found.

`skipped_files` lists deleted/unavailable/limit-excluded Python files and files no
scanner successfully processed. Scanner-specific failures remain in
`scanner_errors`, even if another scanner succeeded. Non-Python files are outside
scope. Legitimate findings from a partial report remain visible with its errors.
One failed scanner returns HTTP 200 with available results and incomplete status;
if neither scanner completes, the request fails with HTTP 502. No-file requests
return empty successful results without launching scanners.

Tool versions come from installed package metadata and, for Semgrep, its actual
JSON report when available. Configuration identity is `p/security-audit` for
Semgrep and the application-owned defaults for Bandit. No registry ruleset version
is invented. The registry is mutable: configuration identity and tool versions
help auditing but do not guarantee bit-for-bit reproduction of future scans.
Dependencies are version-bounded rather than fully locked.

## Configuration and limits

| Variable | Default | Purpose |
| --- | --- | --- |
| `GITHUB_TOKEN` | unset | Optional public GitHub API credentials |
| `GITHUB_TIMEOUT_SECONDS` | 20 | Per-network-operation timeout |
| `SCAN_TIMEOUT_SECONDS` | 30 | Bandit process timeout |
| `SEMGREP_TIMEOUT_SECONDS` | 120 | Semgrep process timeout, including registry retrieval |
| `MAX_PYTHON_FILES` | 50 | Maximum downloaded Python files per request |
| `MAX_FILE_BYTES` | 500000 | Per-file content limit |
| `MAX_TOTAL_BYTES` | 5000000 | Retained content limit per request |
| `SENTINELREVIEW_CORS_ORIGINS` | local frontend origins | Comma-separated browser origin allowlist |

GitHub exposes at most 3,000 changed files; mismatches with PR metadata are reported
as incomplete. Downloads are bounded while streaming; metadata has a 20 MB
per-response cap. Limits are per request: no global admission control, OS memory
sandbox, or overall request deadline is implemented. Scanners see generated `.py`
paths, so path-dependent rules do not retain original directory context. Whole-
repository and cross-file context outside downloaded files is unavailable.

Expected HTTP errors: 400 unsupported private repository, 404 unavailable repo/PR,
409 moving PR, 422 invalid input, 429 GitHub rate limit, 502 upstream/all-scanner
failure, and 504 GitHub timeout. Individual unavailable files yield partial results.

## Testing and live examples

```bash
python -m pytest -q
```

Tests cover v0.1 behavior, scanner normalization/failures/timeouts, exact matching,
ambiguous/nonmatching pairs, evidence, severity, changed-line classification,
coverage and partial failures. GitHub and registry access are mocked in automated
tests; real Bandit tests run locally. Semgrep adapter tests inspect command safety
and emulate JSON reports. Live validation exercises both installed scanners with
GitHub and the maintained registry configuration.

`examples/live_analysis.json` preserves the v0.1 public PR response.
`examples/live_analysis_v0_2.json` records the v0.2 response for the same
[PyCQA/bandit PR #1116](https://github.com/PyCQA/bandit/pull/1116). Its intentionally
unsafe scanner examples are useful fixtures, not evidence of production exploits.
See `examples/live_validation_v0_2.md` for actual versions, counts and measured
request duration. Runtime is a single observation, not a benchmark.

References: [GitHub PR API](https://docs.github.com/en/rest/pulls/pulls),
[Bandit JSON](https://bandit.readthedocs.io/en/latest/formatters/json.html),
[Semgrep audit rule](https://github.com/semgrep/semgrep-rules/blob/develop/python/lang/security/audit/subprocess-shell-true.yaml).


## Optional AI review (v0.3)

The existing endpoint and request remain unchanged. `analysis_complete` still
means deterministic scanner coverage only. Findings, their ordering, scanner
severity/confidence, evidence, deduplication, and scanner metrics are preserved.
The only per-finding addition is `ai_review`; the response adds `ai_summary` and
`ai_complete`.

The AI path runs after deduplication and changed-line classification, reusing the
already-downloaded head-version contents. It never executes repository code or
creates patches. Its architecture is:

| Module | Responsibility |
| --- | --- |
| `app/ai/base.py` | Async provider interface and typed provider errors |
| `app/ai/models.py` | Strict review input/output, status and metadata schemas |
| `app/ai/provider.py` | Provider factory and isolated OpenAI Responses HTTP adapter |
| `app/ai/prompts.py` | Versioned contextual-review system prompt |
| `app/ai/context.py` | Context windows, evidence references, redaction and hashing |
| `app/services/reasoning.py` | Selection, isolated calls, validation, metrics, optional export |

### Configuration

AI remains disabled unless explicitly enabled. No key, model name or endpoint is
hardcoded into application logic. To configure a future live run, set these in the
ignored `.env` file; do not paste keys into source, test fixtures or shared output:

| Variable | Default / requirement |
| --- | --- |
| `AI_ENABLED` | `false` |
| `AI_PROVIDER` | unset; use `openai` for the implemented adapter |
| `AI_MODEL` | unset; choose an accessible model supporting structured outputs |
| `AI_ENDPOINT` | unset; full HTTPS Responses API URL from provider documentation |
| `AI_API_KEY` | unset; provider credential |
| `AI_TIMEOUT_SECONDS` | 30 per attempted review |
| `AI_MAX_FINDINGS` | 3; maximum 50; zero selects no findings |
| `AI_MAX_CONTEXT_CHARS` | 12000; counts the entire serialized per-finding input |
| `AI_CONTEXT_LINES` | 15 lines before and after the primary line |
| `AI_CHANGED_LINES_ONLY` | `false` |
| `AI_MAX_OUTPUT_TOKENS` | 1200 |
| `AI_MAX_RESPONSE_BYTES` | 65536; bounded while streaming |
| `AI_EVALUATION_OUTPUT` | unset; optional local JSON destination |

The endpoint is operator configuration, not accepted in the REST request. It must
use HTTPS without embedded credentials, query parameters or fragments. Redirects
and environment proxy discovery are disabled. Calls are sequential with no retries,
no tools, and `store=false`. A selected finding gets at most one provider call.
These are per-request bounds, not an account spending limit or global rate limit.
Missing provider configuration only affects AI; disabled AI creates no provider
and makes no AI network requests.

### Context, selection and prompt

Selection prefers findings with changed-line status `true`, then stronger scanner
severity, then stable filename/line/rule ordering. It never reorders the API's
deterministic findings. Changed-line-only mode excludes both `false` and `null`.
Findings beyond the limit remain in the response with a skip reason.

Each input contains the normalized finding, scanner evidence, limited PR metadata,
numbered nearby code and, when patch coverage is verified, nearby diff lines. It
omits PR bodies, author details and unrelated files. Evidence IDs such as
`scanner:0`, `code:29` and `diff:4` are scoped to that input. Deleted diff lines have
no head-line number. Unverified patches are omitted rather than treated as facts.

The character bound covers the canonical serialized input including metadata,
evidence and truncation notes, not just code. The fixed system prompt and output
schema are additional bounded request content. If necessary the builder removes
diff context, then the furthest code lines, then shortens verbose messages/title.
It retains scanner evidence and the primary code line. If essential context still
cannot fit, the selected finding is skipped instead of sending an oversized call.
Truncation and unavailable-context notes are exposed on its review wrapper.

Common credential patterns receive best-effort redaction. This is not a complete
secret detector. Raw contexts are not included in normal API responses or local
evaluation exports. A `finding_id` identifies the finding at its head SHA; a
`context_id` is SHA-256 of canonical bounded input excluding `context_id` itself.
The hash includes prompt version and identifies the input, not model behavior.

Prompt version `sentinelreview-security-review-v1` states that scanners generated
the finding; AI only reviews its contextual validity and priority. It requires
uncertainty over unsupported certainty, prohibits inventing vulnerabilities or
application context, and explains that a changed line does not prove introduction.
Repository text, PR titles, scanner messages and code comments are untrusted data,
never instructions. Tests check instruction separation; they cannot establish
complete prompt-injection resistance against a live model.

### Structured results and evidence

A completed review has strict, extra-fields-forbidden output:

- `verdict`: `likely_valid`, `likely_false_positive`, or `needs_review`.
- `exploitability` and `impact`: `low`, `medium`, `high`, or `unknown`.
- `priority`: `low`, `medium`, `high`, or `critical`.
- `confidence`: finite numeric value from 0 to 1.
- `reasoning` and `remediation`: nonempty strings of at most 1500 characters each.
- `evidence_used`: 1–20 unique references, all present in that finding's input.

Provider responses are validated locally even when a provider requests strict
structured output. Extra keys, invalid enums, malformed JSON, invalid references,
refusals, incomplete outputs and unexpected tool output do not become reviews.
Credential-like output is rejected. No arbitrary provider payload is returned.
Checking references establishes that evidence was supplied, not that the model's
interpretation is correct. Model confidence is self-reported and uncalibrated.
AI priority is independent of scanner severity; there is no combined score.

### Completion and failure semantics

Each `ai_review` exposes `status` (`disabled`, `skipped`, `completed`, `failed`),
`selected`, skip reason, context identifiers/size/notes, validated `result` or null,
a sanitized error or null, and optional safe provider metadata.

| Situation | `ai_complete` |
| --- | --- |
| AI disabled | true: no AI work was expected; all findings marked disabled |
| AI enabled, no findings selected (including zero limit) | true: no AI work was expected |
| Every selected finding completed | true |
| Any selected finding failed or was skipped | false |

Unselected findings excluded by limits/filters do not make AI incomplete. A
selected finding skipped because of context limits or provider configuration does.
`ai_complete=true` therefore does **not** mean every deterministic finding was
reviewed. `ai_summary` and individual statuses are authoritative.

`ai_summary` records enabled state, selected count, requested (actual attempted
calls), completed, failed, skipped and disabled counts, verdict/priority counts,
AI-phase elapsed seconds, prompt version, configured provider/model, systemic
errors and optional export error. Skipped counts include selected and unselected
skips; use per-finding `selected` to distinguish them. Completed plus failed equals
attempted calls. AI runtime is zero when disabled and otherwise measures selection,
context building and review processing, excluding optional export time.

Timeouts and individual malformed/failed responses preserve deterministic findings
and allow later reviews. Authentication/rate-limit failures stop further calls:
the attempted finding fails and remaining selected findings are skipped. Missing
configuration skips selected findings with a systemic error and attempts no calls.
AI failures never change `analysis_complete` or erase scanner results.

Successful reviews may retain reported model, response ID and request ID from an
explicit allowlist. These identifiers are optional and filtered; credentials,
headers as a whole, endpoints, provider response bodies and unnecessary internals
are not exposed. Configured model/provider are recorded separately in the summary.
Versions and context hashes support traceability but cannot make AI deterministic.

### Optional evaluation export

Set `AI_EVALUATION_OUTPUT` to a local file inside an existing directory, preferably
under ignored `evaluations/`. While AI is enabled, the service atomically writes a
sanitized JSON snapshot there after reasoning. A fixed destination is replaced by
later requests; use separate operator-selected paths when retaining multiple runs.
The file contains deterministic findings, review results/status, context IDs and
safe reproducibility metadata. No raw code contexts or HTTP payloads are persisted.
`expected_label` is null because this version has no supplied labeled dataset;
labels can be joined later using identifiers and must never be inferred from AI.
Export errors are reported separately and do not change review or scanner success.

### Validation status

Automated tests use fake providers and mocked HTTP. They cover success, multiple
reviews, schema/JSON validation, evidence references, timeouts, provider failures,
partial failures, limits/truncation, changed-line selection, completion semantics,
unchanged deterministic results, metadata, safe-output handling and local export.
The existing v0.2 test suite remains part of the full run.

**Live OpenAI validation is pending due to unavailable API credentials.** No live
OpenAI call has been made, and `examples/live_analysis_v0_3.json` has not
been created. Real provider authentication, model access, acceptance of the
structured-output schema, model judgments, latency and token usage remain
unvalidated. No accuracy, false-positive reduction, or prioritization improvement
is claimed. Those require a labeled evaluation phase.

## Evaluation harness and real-world pilot (v0.5)

The standalone `evaluation` package evaluates Bandit, Semgrep, and their combined
output against strictly scoped manifests without starting FastAPI or invoking AI.
It supports conservative line/CWE matching, explicit reviewed rule mappings,
case-target confusion metrics with null zero-denominator values, changed-line
comparisons, scanner agreement/errors, deduplication counts, reproducibility hashes,
and JSON/Markdown reports.

Six intentionally constructed synthetic harness fixtures validate harness behavior
and must not be presented as real benchmark performance. The separately identified
[real-world pilot](evaluation/benchmarks/real-world-pilot-v1/) contains the tracked
manifest and provenance metadata for three vulnerable/fixed CVE pairs. Fetched
third-party source under `evaluation/cache/` and generated reports under
`evaluation/results/` remain untracked. No Semgrep registry snapshot is committed.
See
[`evaluation/README.md`](evaluation/README.md) for the required distinction among
unit tests, synthetic harness validation, scanner-conformance checks, real-world
benchmarking, and optional recorded-AI evaluation. Generated collections under
`evaluation/results/` are ignored by Git.

## License

SentinelReview source code authored for this repository is available under the
[MIT License](LICENSE). Third-party tools, external rules, advisories, and fetched
benchmark source remain subject to their respective licenses and are not relicensed
by SentinelReview.
