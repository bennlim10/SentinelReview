"""Bound the entire serialized input, retaining valid references and primary line."""
import hashlib
import io
import json
import re
import tokenize

from app.ai.models import ReviewInput
from app.ai.prompts import PROMPT_VERSION
from app.services.patches import HUNK

# Best-effort redaction of common credential formats, not a secrets detector.
SECRET = re.compile(r"(?:gh[pousr]_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|sk-[A-Za-z0-9_-]{16,}|(?:AKIA|ASIA)[A-Z0-9]{16}|xox[baprs]-[A-Za-z0-9-]{15,})")
ASSIGNMENT = re.compile(r'''(?i)((?:password|passwd|api_key|secret_key|access_token|github_token)\s*[:=]\s*["'])([^"'\n]+)(["'])''')
PRIVATE_KEY = re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)


def sanitize(text: str) -> str:
    text = PRIVATE_KEY.sub(lambda m: "[REDACTED PRIVATE KEY]" + "\n" * m.group(0).count("\n"), text)
    text = SECRET.sub("[REDACTED]", text)
    return ASSIGNMENT.sub(r"\1[REDACTED]\3", text)


def canonical(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


class ContextError(Exception):
    pass


def build_context(finding, response, content: bytes, patch: str | None,
                  max_chars: int, radius: int) -> ReviewInput:
    try:
        encoding, _ = tokenize.detect_encoding(io.BytesIO(content).readline)
        original = content.decode(encoding)
        redacted_source = sanitize(original)
        lines = redacted_source.splitlines()
    except (UnicodeError, SyntaxError, LookupError):
        raise ContextError("code_encoding_unavailable") from None
    line = finding.line_number
    if not 1 <= line <= len(lines):
        raise ContextError("finding_line_unavailable")
    identity = [response.repository, response.head_sha, finding.filename, line, sorted(finding.rule_ids)]
    fid = hashlib.sha256(canonical(identity).encode()).hexdigest()
    fields = ["filename", "line_number", "severity", "confidence", "category", "description",
              "sources", "rule_ids", "cwe_ids", "is_on_changed_line"]
    data = dict(finding_id=fid, context_id="0" * 64, prompt_version=PROMPT_VERSION,
        pr={key: getattr(response, key) for key in ["repository", "pull_request_number", "title",
            "base_branch", "head_branch", "head_sha"]},
        finding={key: getattr(finding, key) for key in fields},
        scanner_evidence=[dict(ref=f"scanner:{i}", **e.model_dump()) for i, e in enumerate(finding.evidence)],
        code=[dict(ref=f"code:{n}", line=n, text=lines[n-1])
              for n in range(max(1, line-radius), min(len(lines), line+radius)+1)],
        diff=[], truncation_notes=[])
    # Only include diff when the existing parser established reliable coverage.
    if patch is not None and finding.is_on_changed_line is not None:
        head = None
        for i, text in enumerate(patch.splitlines()):
            match = HUNK.match(text)
            if match:
                head = int(match.group(3))
                continue
            if head is not None and text and text[0] in " +-":
                if abs(head-line) <= radius:
                    data['diff'].append(dict(ref=f"diff:{i}", head_line=None if text[0] == "-" else head, text=text))
                if text[0] in " +":
                    head += 1
    else:
        data['truncation_notes'].append('Nearby diff unavailable or patch coverage unverified.')
    def redact(value):
        if isinstance(value, str):
            return sanitize(value)
        if isinstance(value, list):
            return [redact(item) for item in value]
        if isinstance(value, dict):
            return {key: redact(item) for key, item in value.items()}
        return value
    redacted = redact(data)
    if redacted != data or original != redacted_source:
        redacted['truncation_notes'].append('Common credential patterns redacted; context may be incomplete.')
    data = redacted
    # Mark omitted file context even when the character budget was not reached.
    if len(data['code']) < len(lines):
        data['truncation_notes'].append('Code limited to the configured line window; remaining file omitted.')
    if len(canonical(data)) > max_chars:
        data['truncation_notes'].append('Input reduced to fit the serialized character budget.')
    while len(canonical(data)) > max_chars:
        if data['diff']:
            data['diff'].pop()
        elif len(data['code']) > 1:
            furthest = max(range(len(data['code'])), key=lambda i: abs(data['code'][i]['line']-line))
            data['code'].pop(furthest)
        else:
            # Shorten verbose messages/title, never identity or the primary code line.
            options = [(data['pr'], 'title'), (data['finding'], 'description')]
            options += [(e, 'description') for e in data['scanner_evidence']]
            obj, key = max(options, key=lambda pair: len(pair[0][pair[1]]))
            if len(obj[key]) <= 80:
                raise ContextError('essential_context_exceeds_limit')
            obj[key] = obj[key][:max(80, len(obj[key])//2)]
    payload = {key: value for key, value in data.items() if key != 'context_id'}
    data['context_id'] = hashlib.sha256(canonical(payload).encode()).hexdigest()
    return ReviewInput.model_validate(data)
