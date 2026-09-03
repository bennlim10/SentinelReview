import pytest
from app.models import Finding
from app.services.dedup import deduplicate

RULE = "python.lang.security.audit.subprocess-shell-true.subprocess-shell-true"


def finding(source="bandit", **changes):
    values = dict(severity="LOW", confidence="HIGH" if source == "bandit" else None,
        category="subprocess_popen_with_shell_equals_true" if source == "bandit" else "audit",
        filename="a.py", line_number=10, description=f"{source} message", source=source,
        rule_id="B602" if source == "bandit" else RULE, cwe_id=78, is_on_changed_line=None)
    values.update(changes)
    return Finding(**values)


def test_equivalent_merge():
    a, b = finding(), finding("semgrep", severity="HIGH")
    merged, = deduplicate([b, a])
    assert merged.sources == ["bandit", "semgrep"]
    assert set(merged.rule_ids) == {"B602", RULE}
    assert merged.cwe_ids == ["CWE-78"]
    assert merged.severity == "HIGH"
    assert merged.source == "bandit" and merged.rule_id == "B602"
    assert merged.confidence == "HIGH"
    assert {e.description for e in merged.evidence} == {"bandit message", "semgrep message"}
    assert a.severity == "LOW"  # no mutation of raw findings


@pytest.mark.parametrize("changes", [{"filename": "b.py"}, {"line_number": 11}, {"cwe_id": 89},
    {"cwe_id": None}, {"rule_id": "unmapped.rule"}])
def test_no_loose_merges(changes):
    assert len(deduplicate([finding(), finding("semgrep", **changes)])) == 2


def test_same_scanner_and_ambiguous_pairs():
    assert len(deduplicate([finding(), finding()])) == 2
    assert len(deduplicate([finding(), finding("semgrep"), finding("semgrep")])) == 3


@pytest.mark.parametrize("source", ["bandit", "semgrep"])
def test_single_scanner(source):
    raw = finding(source)
    assert deduplicate([raw]) == [raw]
