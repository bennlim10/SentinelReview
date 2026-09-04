# Synthetic evaluation fixtures

These six tiny Python files and the local Semgrep rule were intentionally authored
for SentinelReview harness tests. They are never executed. Their labels exercise
matching and metric branches; they are not public benchmark cases, real-world
vulnerabilities, or evidence of scanner performance.

The shell and hashing snippets represent scoped positive controls. The subprocess
and clean snippets are scoped negative controls. The path snippet intentionally
exercises a miss under this limited scanner configuration. The unmapped case is
unscorable by design. Comments in this document are provenance, not model-created
labels. No public dataset content or Semgrep registry snapshot is included.
