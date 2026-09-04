import os
import re
import io
import tokenize
from pathlib import Path, PurePosixPath
from urllib.parse import quote, urlparse

import httpx

from evaluation.loader import sha256
from evaluation.models import BenchmarkCase


_REVISION = re.compile(r"^[0-9a-f]{40}$")


def cache_path(case: BenchmarkCase, cache_root: str | Path) -> Path:
    root = Path(cache_root).resolve()
    parsed = urlparse(case.repository or "")
    if parsed.scheme != "https" or parsed.netloc != "github.com":
        raise ValueError("immutable source repository must be https://github.com/<owner>/<repo>")
    parts = [part for part in parsed.path.strip("/").split("/") if part]
    if len(parts) != 2 or not _REVISION.fullmatch(case.source_revision or ""):
        raise ValueError("immutable source requires owner/repo and a full commit SHA")
    filename = PurePosixPath(case.filename)
    if filename.is_absolute() or ".." in filename.parts:
        raise ValueError("source filename must remain repository-relative")
    target = (root / parts[0] / parts[1] / case.source_revision / Path(*filename.parts)).resolve()
    if not target.is_relative_to(root):
        raise ValueError("cache path escapes cache root")
    return target


def raw_url(case: BenchmarkCase) -> str:
    parsed = urlparse(case.repository or "")
    owner, repository = [part for part in parsed.path.strip("/").split("/") if part]
    path = quote(case.filename, safe="/")
    return f"https://raw.githubusercontent.com/{owner}/{repository}/{case.source_revision}/{path}"


def assessment_fingerprints(case: BenchmarkCase, data: bytes) -> tuple[str, str]:
    lines = data.splitlines(keepends=True)
    selected = b"".join(lines[case.assessment_line_range.start - 1:
                              case.assessment_line_range.end])
    tokens = []
    ignored = {tokenize.ENCODING, tokenize.COMMENT, tokenize.NL, tokenize.NEWLINE,
               tokenize.INDENT, tokenize.DEDENT, tokenize.ENDMARKER}
    try:
        for token in tokenize.tokenize(io.BytesIO(selected).readline):
            if token.type not in ignored:
                tokens.append(f"{token.type}:{token.string}")
    except tokenize.TokenError:
        pass
    normalized = "\n".join(tokens).encode()
    return sha256(selected), sha256(normalized)


def retrieve(case: BenchmarkCase, cache_root: str | Path, *, timeout: float = 30,
             client: httpx.Client | None = None) -> bytes:
    target = cache_path(case, cache_root)
    if target.exists():
        data = target.read_bytes()
        if sha256(data) != case.code_sha256:
            raise ValueError(f"cached source hash mismatch: {case.case_id}")
        return data
    owns_client = client is None
    client = client or httpx.Client(timeout=timeout, follow_redirects=False,
                                    trust_env=False)
    try:
        response = client.get(raw_url(case), headers={"Accept": "text/plain"})
        response.raise_for_status()
        data = response.content
    finally:
        if owns_client:
            client.close()
    if sha256(data) != case.code_sha256:
        raise ValueError(f"downloaded source hash mismatch: {case.case_id}")
    target.parent.mkdir(parents=True, exist_ok=True)
    temporary = target.with_name(f".{target.name}.tmp-{os.getpid()}")
    temporary.write_bytes(data)
    temporary.replace(target)
    return data
