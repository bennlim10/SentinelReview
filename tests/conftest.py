from unittest.mock import AsyncMock

import pytest

from app.config import Settings


@pytest.fixture
def settings():
    return Settings(_env_file=None, github_token=None)


@pytest.fixture
def github():
    client = AsyncMock()
    client.pull_request.return_value = {
        "title": "Example PR", "user": {"login": "alice"}, "changed_files": 1,
        "base": {"ref": "main", "sha": "base123", "repo": {"private": False}},
        "head": {"ref": "feature", "sha": "head123", "repo": {"private": False, "full_name": "fork/demo"}},
    }
    client.changed_files.return_value = [{"filename": "demo.py", "status": "modified",
        "additions": 1, "deletions": 1, "patch": "@@ -1 +1 @@\n-x = 1\n+eval(input())"}]
    client.file_content.return_value = b"eval(input())\n"
    return client
