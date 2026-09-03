"""Exact-line, unambiguous, cross-scanner equivalence matching only."""
from app.models import Finding

# Exact rule IDs, not generic category names or substring matches. Extend only
# after checking the upstream rule behavior and adding equivalence tests.
EQUIVALENT_RULES = {
    ("B602", "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true"),
}
RANK = {"UNDEFINED": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3}


def equivalent(a: Finding, b: Finding) -> bool:
    if {a.source, b.source} != {"bandit", "semgrep"}:
        return False
    bandit, semgrep = (a, b) if a.source == "bandit" else (b, a)
    return (a.filename == b.filename and a.line_number == b.line_number
            and bool(set(a.cwe_ids) & set(b.cwe_ids))
            and (bandit.rule_id, semgrep.rule_id) in EQUIVALENT_RULES)


def deduplicate(findings: list[Finding]) -> list[Finding]:
    candidates = {i: [j for j, other in enumerate(findings) if i != j and equivalent(finding, other)]
                  for i, finding in enumerate(findings)}
    consumed = set()
    output = []
    for i, finding in enumerate(findings):
        if i in consumed:
            continue
        matches = candidates[i]
        if len(matches) == 1 and candidates[matches[0]] == [i]:
            j = matches[0]
            other = findings[j]
            representative = finding if finding.source == "bandit" else other
            merged = representative.model_copy(deep=True)
            merged.sources = sorted(set(finding.sources + other.sources))
            merged.rule_ids = sorted(set(finding.rule_ids + other.rule_ids))
            merged.cwe_ids = sorted(set(finding.cwe_ids + other.cwe_ids))
            merged.severity = max((finding.severity, other.severity), key=RANK.__getitem__)
            merged.evidence = finding.evidence + other.evidence
            output.append(merged)
            consumed.add(j)
        else:
            output.append(finding.model_copy(deep=True))
        consumed.add(i)
    return output
