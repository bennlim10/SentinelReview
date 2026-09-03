"""Conservative unified-diff parsing in head-file coordinates."""
import re

HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@.*$")


def changed_lines(patch: str | None, additions: int, deletions: int,
                  content: bytes) -> set[int] | None:
    """Reject missing, malformed, count-mismatched or content-mismatched patches."""
    if not patch:
        return None
    try:
        lines = content.decode("utf-8-sig").splitlines()
    except UnicodeDecodeError:
        return None
    changed: set[int] = set()
    added = removed = 0
    old_left = new_left = 0
    old_end = new_end = -1
    head_line = 0
    seen = False
    for line in patch.splitlines():
        match = HUNK.match(line)
        if match:
            if old_left or new_left:
                return None
            old_start, old_count, new_start, new_count = match.groups()
            old_start, new_start = int(old_start), int(new_start)
            old_left = int(old_count) if old_count is not None else 1
            new_left = int(new_count) if new_count is not None else 1
            if old_start < old_end or new_start < new_end:
                return None
            old_end, new_end = old_start + old_left, new_start + new_left
            head_line = new_start
            seen = True
            continue
        if line == r"\ No newline at end of file":
            continue
        if not seen or not line or line[0] not in " +-":
            return None
        kind = line[0]
        if kind in " +":
            if new_left <= 0 or not 1 <= head_line <= len(lines):
                return None
            if lines[head_line - 1] != line[1:]:
                return None
            if kind == "+":
                changed.add(head_line)
                added += 1
            new_left -= 1
            head_line += 1
        if kind in " -":
            if old_left <= 0:
                return None
            old_left -= 1
            if kind == "-":
                removed += 1
    if not seen or old_left or new_left or added != additions or removed != deletions:
        return None
    return changed


def line_ranges(lines: set[int] | None) -> list[tuple[int, int]] | None:
    if lines is None:
        return None
    ranges: list[tuple[int, int]] = []
    for number in sorted(lines):
        if ranges and number == ranges[-1][1] + 1:
            ranges[-1] = (ranges[-1][0], number)
        else:
            ranges.append((number, number))
    return ranges
