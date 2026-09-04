# Real-world Python pilot v1

**REAL-WORLD PILOT — 3 VULNERABILITY PAIRS / 6 CASES**

This pilot validates SentinelReview's real-world benchmark workflow. Its three
vulnerability pairs are too small and narrow to support a general accuracy claim.
Labels received one single source-assisted reviewer, OpenAI Codex; independent
human adjudication and inter-rater agreement are absent.

The manifest stores immutable upstream references and hashes. Source is fetched
into gitignored `evaluation/cache/`, hash-checked before use, and never executed.
No third-party source is committed.

## Verification record

| Pair | Vulnerable parent | Fixing commit | CWE | Assessment ranges |
| --- | --- | --- | --- | --- |
| aiohttp CVE-2024-23334 / GHSA-5h86-8mv2-jq9f | `33ccdfb0a12690af5bb49bda2319ec0907fa7827` | `1c335944d6a8b1298baf179b7c0b3069f10c514b` | CWE-22 | vulnerable `aiohttp/web_urldispatcher.py:634-648`; fixed `:639-658` |
| aiohttp CVE-2024-42367 / GHSA-jwhx-xcg6-8xhj | `6a778061eb3d66146012ceef760c8d84b7be6cf3` | `ce2e9758814527589b10759a20783fb03b98339f` | CWE-61 | vulnerable `aiohttp/web_fileresponse.py:173-183`; fixed `:173-186` |
| Poetry CVE-2022-36069 / GHSA-9xgj-fcgf-x6mw | `37deae62c6dc64fcaaea26e61e3fe98ae041eebe` | `cc84be60ac9af549664051c2684621db51d05ff1` | CWE-88 | vulnerable `poetry/core/vcs/git.py:245-246`; fixed `:250-253` |

Public GitHub commit metadata confirmed that each fixing commit has the listed
vulnerable revision as its sole parent. The ranges were checked against the full
immutable source blobs rather than copied from diff hunk positions.

- [CVE-2024-23334 reviewed advisory](https://github.com/advisories/GHSA-5h86-8mv2-jq9f)
- [CVE-2024-23334 fix](https://github.com/aio-libs/aiohttp/commit/1c335944d6a8b1298baf179b7c0b3069f10c514b)
- [CVE-2024-42367 reviewed advisory](https://github.com/advisories/GHSA-jwhx-xcg6-8xhj)
- [CVE-2024-42367 fix](https://github.com/aio-libs/aiohttp/commit/ce2e9758814527589b10759a20783fb03b98339f)
- [CVE-2022-36069 reviewed advisory](https://github.com/advisories/GHSA-9xgj-fcgf-x6mw)
- [CVE-2022-36069 fix](https://github.com/python-poetry/poetry-core/commit/cc84be60ac9af549664051c2684621db51d05ff1)

## Licensing

aiohttp's `LICENSE.txt` at all four selected revisions has SHA-256
`9f80d0db7d755a941db4572172c270ecbd8f082ba215ddd095985942ed94a9eb`
and identifies Apache-2.0. Poetry-core's `LICENSE` at both revisions has SHA-256
`f1978133782b90f4733bc308ddb19267c3fe04797c88d9ed3bc219032495a982`
and contains the MIT license grant. Reference-and-fetch remains the source policy.

## Pilot result record

Bandit, Semgrep, and the combined deterministic pipeline each detected **0 of 3**
vulnerable targets under strict range and exact-CWE matching. Each mode recorded
three false negatives and all **3 fixed controls remained true negatives**. No AI
provider was invoked.

Bandit produced 58 raw findings across the six full-file scans; Semgrep produced
zero. None were in an assessment range with the expected CWE. The 58 findings are
scan-event counts, not unique vulnerabilities: unchanged out-of-scope alerts may
repeat across vulnerable and fixed revisions. Deduplication merged zero findings.

These outcomes are preliminary pipeline-validation observations from three pairs.
They are not an overall SentinelReview accuracy or effectiveness claim.

## Known methodology limits

- `p/security-audit` is a mutable registry identity; the registry does not provide
  an immutable snapshot hash in this run. A reviewed, license-compatible rules
  snapshot is needed for stronger reproducibility before scaling.
- Full files are scanned to preserve syntax and context, so unrelated alerts remain
  visible as out-of-scope findings and repeat across paired revisions.
- Strict filename, assessment-range, and exact-CWE matching is unchanged.
- These three vulnerabilities exercise path/symlink and Git argument handling,
  leaving most planned categories unrepresented.
