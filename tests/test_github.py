import httpx
import pytest

from app.integrations.github import GitHubClient, GitHubError, FileTooLarge


async def test_pagination(settings):
    pages = []
    def handler(request):
        pages.append(request.url.params["page"])
        return httpx.Response(200, json=[{}] * (100 if len(pages) == 1 else 1))
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        assert len(await GitHubClient(client, settings).changed_files("owner/repo", 1)) == 101
    assert pages == ["1", "2"]


@pytest.mark.parametrize("status,headers,expected", [(404, {}, 404), (429, {}, 429),
    (403, {"x-ratelimit-remaining": "0"}, 429), (401, {}, 502), (500, {}, 502)])
async def test_errors(settings, status, headers, expected):
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(status, headers=headers))) as client:
        with pytest.raises(GitHubError) as error:
            await GitHubClient(client, settings).changed_files("o/r", 1)
        assert error.value.status_code == expected


async def test_content_pinned_and_limited(settings):
    def handler(request):
        assert request.url.host == "api.github.com"
        assert request.url.params["ref"] == "abc123"
        assert "Authorization" not in request.headers
        return httpx.Response(200, content=b"12345")
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        github = GitHubClient(client, settings)
        assert await github.file_content("fork/r", "a b.py", "abc123", 5) == b"12345"
        with pytest.raises(FileTooLarge):
            await github.file_content("fork/r", "a.py", "abc123", 4)


async def test_timeout(settings):
    def handler(request):
        raise httpx.ReadTimeout("timeout")
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        with pytest.raises(GitHubError) as error:
            await GitHubClient(client, settings).changed_files("o/r", 1)
        assert error.value.status_code == 504


async def test_private_rejected(settings, github):
    pr = github.pull_request.return_value
    pr["base"]["repo"]["private"] = True
    async with httpx.AsyncClient(transport=httpx.MockTransport(lambda r: httpx.Response(200, json=pr))) as client:
        with pytest.raises(GitHubError, match="public"):
            await GitHubClient(client, settings).pull_request("o/r", 1)


async def test_pagination_cap(settings):
    calls = 0
    def handler(request):
        nonlocal calls
        calls += 1
        return httpx.Response(200, json=[{}] * 100)
    async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as client:
        assert len(await GitHubClient(client, settings).changed_files("o/r", 1)) == 3000
    assert calls == 30
