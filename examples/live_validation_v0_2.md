# SentinelReview v0.2 live validation

A real `POST /api/v1/analyze` to the local FastAPI server returned HTTP 200 for
[PyCQA/bandit PR #1116](https://github.com/PyCQA/bandit/pull/1116), at head commit
`071a539fae6fc4652d276523c1e772f402437b2f`.

| Observation | Actual result |
| --- | --- |
| Changed files | 3 |
| Python files scanned by each scanner | 3 |
| Bandit raw findings | 35 |
| Semgrep raw findings | 4 |
| Combined raw findings | 39 |
| Cross-scanner pairs merged | 4 |
| Final deduplicated findings | 35 |
| Final findings on changed lines | 2 |
| Final findings outside changed lines | 33 |
| Unknown changed-line classifications | 0 |
| Scanner errors | 0 |
| Skipped files / coverage warnings | 0 / 0 |
| Analysis complete | true |
| Total HTTP request duration measured by curl | 3.043324 seconds |

Runtime includes the localhost POST, GitHub requests, registry retrieval, both
scanner executions, and response processing. This is one observation, not a
benchmark or a claim about uncached network performance.

- Bandit: **1.9.4**, application defaults with `ignore-nosec`.
- Semgrep: **1.176.0**, Community Edition, configuration **p/security-audit**.
- Python: **3.14.6**, macOS ARM64.
- Registry ruleset version: **not recorded; no immutable version supplied**.

The four merged pairs are B602 and
`python.lang.security.audit.subprocess-shell-true.subprocess-shell-true` at lines
36, 37, 40, and 51 of `examples/subprocess_shell.py`. Each pair shares CWE-78.
The changed-line findings remain B605 at lines 29 and 30. Changed-line status does
not establish vulnerability introduction.

The 35 raw Bandit findings match the saved v0.1 example by filename, primary line,
rule, severity, confidence, and description. The PR head and changed-line ranges
also match. Semgrep contributes corroborating evidence for four existing findings;
it does not increase the final finding count for this PR.

An initial attempt exposed an invocation bug: Semgrep 1.176 rejects the deprecated
`python -m semgrep` entry point. That request correctly returned Bandit findings
with a Semgrep execution error and `analysis_complete=false`. The adapter now uses
the installed console executable, with regression assertions for this invocation.
The saved JSON is the subsequent successful run, not the failed attempt.

The response contains public PR metadata, normalized findings and evidence,
versions, configuration identities, and coverage; it contains no credentials,
headers, local temporary paths, or downloaded source contents.
