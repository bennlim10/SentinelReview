import json
from urllib.parse import quote

import httpx

from app.config import Settings


class GitHubError(Exception):
    def __init__(self, message: str, status_code: int = 502):
        super().__init__(message)
        self.status_code = status_code


class FileTooLarge(Exception):
    pass


class GitHubClient:
    def __init__(self, client: httpx.AsyncClient, settings: Settings):
        self.client = client
        self.settings = settings

    async def _get(self, path: str, *, params=None, raw=False, limit=20_000_000):
        headers = {"Accept": "application/vnd.github.raw+json" if raw else "application/vnd.github+json",
                   "X-GitHub-Api-Version": "2022-11-28"}
        token = self.settings.github_token
        if token and token.get_secret_value():
            headers["Authorization"] = f"Bearer {token.get_secret_value()}"
        try:
            async with self.client.stream("GET", f"https://api.github.com{path}",
                                          headers=headers, params=params,
                                          timeout=self.settings.github_timeout_seconds,
                                          follow_redirects=False) as response:
                if response.status_code != 200:
                    status = response.status_code
                    if status == 404:
                        raise GitHubError("GitHub repository, PR, or file was not found.", 404)
                    if status == 429 or (status == 403 and response.headers.get("x-ratelimit-remaining") == "0"):
                        raise GitHubError("GitHub rate limit exceeded; retry later.", 429)
                    raise GitHubError(f"GitHub returned HTTP {status}.")
                data = bytearray()
                async for chunk in response.aiter_bytes():
                    data.extend(chunk)
                    if len(data) > limit:
                        if raw:
                            raise FileTooLarge()
                        raise GitHubError("GitHub response exceeded the metadata size limit.")
                if raw:
                    return bytes(data)
                try:
                    return json.loads(data)
                except ValueError as exc:
                    raise GitHubError("GitHub returned invalid JSON.") from exc
        except httpx.TimeoutException as exc:
            raise GitHubError("GitHub request timed out.", 504) from exc
        except httpx.RequestError as exc:
            raise GitHubError("Could not reach GitHub.") from exc

    async def pull_request(self, repository: str, number: int):
        pr = await self._get(f"/repos/{repository}/pulls/{number}")
        if pr["base"]["repo"]["private"] or (pr["head"]["repo"] and pr["head"]["repo"]["private"]):
            raise GitHubError("Only public repositories are supported.", 400)
        return pr

    async def changed_files(self, repository: str, number: int):
        files = []
        # GitHub's PR-files endpoint exposes at most 3,000 files.
        for page in range(1, 31):
            batch = await self._get(f"/repos/{repository}/pulls/{number}/files",
                                    params={"per_page": 100, "page": page})
            files.extend(batch)
            if len(batch) < 100:
                break
        return files

    async def file_content(self, repository: str, filename: str, sha: str, limit: int):
        path = quote(filename, safe="")
        return await self._get(f"/repos/{repository}/contents/{path}",
                               params={"ref": sha}, raw=True, limit=limit)
