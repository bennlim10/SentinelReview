# SentinelReview evaluation harness

This package runs independently from FastAPI and GitHub ingestion. It loads an
explicitly scoped manifest, runs the existing Bandit and Semgrep adapters on each
fixture without executing it, applies the production deduplicator, matches findings
to one target, computes case-target metrics, and writes JSON and Markdown reports.

```bash
python -m evaluation run \
  --manifest evaluation/fixtures/manifest.json \
  --semgrep-config evaluation/fixtures/semgrep/synthetic-security.yaml \
  --output-dir evaluation/results \
  --run-id synthetic-v0.4
```

`evaluation/results/` is gitignored. The bundled Semgrep YAML is a tiny authored
test rule, not a registry snapshot. Evaluation accepts `p/security-audit` or an
explicit local configuration/snapshot. Local file identity and SHA-256 are recorded;
no snapshot is downloaded by the harness. Pinning and redistributing upstream rules
requires a separate licensing and provenance decision.

## Five distinct validation activities

1. **Evaluation-harness unit tests** use mocked scanners and small models to verify
   loading, matching, metrics, errors, AI policy, metadata, and report formatting.
   They measure code behavior only.
2. **Synthetic harness validation** runs the harness and installed scanners against
   the six locally authored fixtures in this repository. It verifies integration,
   report generation, and reproducibility metadata, but it is not a measurement of
   real-world scanner performance.
3. **Scanner-conformance evaluation** uses deliberately constructed or scanner-
   authored positive/negative examples to check known rule behavior. It is biased
   toward those rules and is not representative scanner accuracy.
4. **Real-world vulnerability benchmarking** uses separately identified,
   authoritative, localized labels, negative assessment scopes, source revisions,
   content hashes, and license review. The existing six-case pilot is documented in
   [`benchmarks/real-world-pilot-v1/`](benchmarks/real-world-pilot-v1/); its small,
   single-reviewer results validate methodology rather than overall accuracy.
5. **Optional AI-assisted evaluation** consumes already recorded, validated AI
   reviews. It never invokes a provider. `needs_review` is abstention; missing,
   failed, skipped, and disabled reviews are unavailable. AI cannot recover scanner
   misses and no AI output may create an expected label.

Results from these activities must remain separately identified by `report_kind`.
They must not be pooled into a single performance or improvement claim.

## Matching and metrics

Every case labels one assessment target, not an entire file. Both positive and
negative cases require an assessment line range. Positive cases additionally
require a vulnerable range inside it. Detection requires the exact filename,
primary line in the assessment scope, and either a shared normalized CWE or an
explicit mapping from scanner/rule ID to expected category under a versioned policy.
No nearby-line, related-CWE, or message-similarity matching is performed.

An insufficient target mapping is `unscorable`. A scanner error is
`scanner_error`, never TN/FN. With partial combined coverage, a target detection can
remain TP/FP, but absence becomes `scanner_error`. Other alerts remain visible as
unadjudicated findings. Multiple matching alerts count once per case-target.

TP, FP, TN, and FN produce case-target precision, recall, false-positive rate, and
F1. Zero denominators produce JSON `null` and Markdown `undefined`. Raw findings,
scanner/CWE counts, agreement, deduplication, changed-line filtered outcomes,
runtime, excluded/error cases, and reproducibility metadata remain separate.
Changed-line results are unscorable when annotations are absent.

AI verdict policy is fixed: `likely_valid` is positive,
`likely_false_positive` is negative, and `needs_review` abstains. Coverage and
correctness of decisive reviews are separate. A true detected target labeled
likely-false-positive is recorded as down-ranking risk; low priority alone is not
called a false negative. Confidence is grouped by correctness without claiming
calibration.

## Provenance and reproducibility

The strict schema requires case/source IDs, revision when known, Python filename,
label, target scope, CWE/category target, content hash, code or contained fixture
path, notes, label provenance, and license reference. Inline and file fixtures are
hash-verified and size-bounded. Paths cannot escape the manifest directory.

Reports record the SentinelReview commit and dirty state, manifest and fixture
hashes, dataset identity/version, scanner versions, Semgrep config identity/hash,
UTC timestamp, Python/platform, allowlisted matching/runtime configuration, and
optional recorded AI provider/model/prompt identifiers. Generated reports contain
no credentials. A mutable registry identity is weaker than an immutable local hash.

Real-world manifests may use `immutable_reference_fetch`. The loader accepts only
full GitHub commit SHAs, derives a contained cache path, verifies whole-file and
assessment-region hashes, and rejects corrupted cache entries or mismatched
downloads. Cached third-party source lives under gitignored `evaluation/cache/`.

The six bundled cases and local rule are synthetic controls explicitly designed to
exercise harness branches. Their numeric output is not benchmark performance,
accuracy, false-positive reduction, or AI improvement evidence.

The real-world pilot is analytically separate from synthetic and scanner-conformance
runs. Its tracked directory contains only the manifest and provenance documentation;
immutable third-party source is fetched into `evaluation/cache/`, and generated JSON
and Markdown reports remain under `evaluation/results/`. Both directories are
gitignored.
