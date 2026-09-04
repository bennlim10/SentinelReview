from app.models import Finding
from evaluation.models import BenchmarkCase, FindingRecord, MatchingPolicy


def on_changed_line(case: BenchmarkCase, line: int) -> bool | None:
    if case.changed_line_ranges is None:
        return None
    return any(span.contains(line) for span in case.changed_line_ranges)


def target_match(case: BenchmarkCase, finding: Finding, policy: MatchingPolicy) -> bool:
    if finding.filename != case.filename or not case.assessment_line_range.contains(finding.line_number):
        return False
    if set(case.cwe_ids) & set(finding.cwe_ids):
        return True
    if case.expected_category:
        return any(entry.scanner in finding.sources and entry.rule_id in finding.rule_ids
                   and entry.expected_category == case.expected_category
                   for entry in policy.mappings)
    return False


def scorable(case: BenchmarkCase, policy: MatchingPolicy) -> bool:
    return bool(case.cwe_ids or (case.expected_category and any(
        entry.expected_category == case.expected_category for entry in policy.mappings)))


def record(case: BenchmarkCase, finding: Finding, policy: MatchingPolicy) -> FindingRecord:
    return FindingRecord(source=finding.source, sources=finding.sources, filename=finding.filename,
        line_number=finding.line_number, rule_id=finding.rule_id, rule_ids=finding.rule_ids,
        cwe_ids=finding.cwe_ids, severity=finding.severity,
        in_assessment_scope=(finding.filename == case.filename
                             and case.assessment_line_range.contains(finding.line_number)),
        target_match=target_match(case, finding, policy),
        changed_line=on_changed_line(case, finding.line_number), ai_review=finding.ai_review)


def classify(case: BenchmarkCase, records: list[FindingRecord], policy: MatchingPolicy,
             *, scanner_error: bool = False, changed_only: bool = False):
    if scanner_error:
        return "scanner_error", None
    if not scorable(case, policy):
        return "unscorable", None
    matches = [item for item in records if item.target_match]
    if changed_only:
        if case.changed_line_ranges is None:
            return "unscorable", None
        matches = [item for item in matches if item.changed_line]
    detected = bool(matches)
    if case.vulnerability_present:
        return ("tp" if detected else "fn"), detected
    return ("fp" if detected else "tn"), detected
