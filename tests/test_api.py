from fastapi.testclient import TestClient
import pytest

from app.api.routes import get_github, get_settings
from app.integrations.github import GitHubError
from app.main import app


@pytest.fixture
def client(github, settings):
    app.dependency_overrides[get_github] = lambda: github
    app.dependency_overrides[get_settings] = lambda: settings
    with TestClient(app) as client:
        yield client
    app.dependency_overrides.clear()


def test_request(client):
    response = client.post("/api/v1/analyze", json={"repository": "owner/repo", "pull_request_number": 1})
    assert response.status_code == 200
    data = response.json()
    assert data["findings"][0]["is_on_changed_line"] is True
    assert data["scanned_files"][0]["changed_line_ranges"] == [[1, 1]]


@pytest.mark.parametrize("repo,number", [("https://github.com/a/b", 1), ("../x", 1), ("a/b", 0), ("a/b", True), ("a/b", "1")])
def test_validation(client, repo, number):
    assert client.post("/api/v1/analyze", json={"repository": repo, "pull_request_number": number}).status_code == 422


def test_github_error(client, github):
    github.pull_request.side_effect = GitHubError("Not found", 404)
    assert client.post("/api/v1/analyze", json={"repository": "a/b", "pull_request_number": 1}).status_code == 404
