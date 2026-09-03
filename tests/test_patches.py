import pytest

from app.services.patches import changed_lines, line_ranges


@pytest.mark.parametrize("patch,added,deleted,content,expected", [
    ("@@ -1 +1 @@\n-old\n+new", 1, 1, b"new\n", {1}),
    ("@@ -0,0 +1,2 @@\n+a\n+b", 2, 0, b"a\nb\n", {1, 2}),
    ("@@ -1,2 +1 @@\n a\n-b", 0, 1, b"a\n", set()),
    ("@@ -1 +1 @@\n-a\n+b\n\\ No newline at end of file", 1, 1, b"b", {1}),
    ("@@ -1 +1 @@\n-a\n+b\n@@ -4 +4 @@\n-d\n+e", 2, 2, b"b\nx\ny\ne\n", {1, 4}),
    (None, 1, 0, b"a", None),
    ("", 0, 0, b"a", None),
    ("@@ -1 +1,2 @@\n-a\n+b", 1, 1, b"b", None),
    ("@@ -1 +1 @@\n-a\n+b", 2, 1, b"b", None),
    ("@@ -1 +1 @@\n-a\n+b", 1, 1, b"c", None),
    ("truncated", 1, 0, b"a", None),
    ("@@ -1 +1 @@\n-a\n+b\n+c", 2, 1, b"b\nc", None),
    ("@@ -1 +1 @@\n-a\n+b", 1, 1, b"\xff", None),
])
def test_patch(patch, added, deleted, content, expected):
    assert changed_lines(patch, added, deleted, content) == expected


def test_ranges():
    assert line_ranges({1, 2, 4, 6, 7}) == [(1, 2), (4, 4), (6, 7)]
    assert line_ranges(None) is None
    assert line_ranges(set()) == []


def test_overlapping_hunks_are_unknown():
    patch = "@@ -1 +1 @@\n-a\n+b\n@@ -1 +1 @@\n-a\n+b"
    assert changed_lines(patch, 2, 2, b"b") is None


def test_context_mismatch_is_unknown():
    patch = "@@ -1,2 +1,2 @@\n wrong\n-a\n+b"
    assert changed_lines(patch, 1, 1, b"right\nb") is None
