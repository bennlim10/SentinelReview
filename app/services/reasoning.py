"""Optional reasoning, isolated from deterministic findings and scanner coverage."""
import asyncio
from collections import Counter
from pathlib import Path
from tempfile import NamedTemporaryFile
from time import perf_counter
import json
import os

from app.ai.base import ProviderError
from app.ai.context import ContextError, build_context, canonical, sanitize
from app.ai.models import AIError, AIReview, AISummary, ProviderResult
from app.ai.prompts import PROMPT_VERSION
from app.ai.provider import create_provider, safe_identifier

RANK = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "UNDEFINED": 0}


def export_evaluation(response, path: str):
    """Opt-in operator path; no raw contexts, headers, credentials or invented labels."""
    records = [{"deterministic_finding": f.model_dump(exclude={"ai_review"}),
                "ai_review": f.ai_review.model_dump(), "expected_label": None}
               for f in response.findings]
    data = {"repository": response.repository, "head_sha": response.head_sha,
            "ai_summary": response.ai_summary.model_dump(), "ai_complete": response.ai_complete,
            "records": records}
    # Best-effort sanitize every string, not serialized JSON (which escapes quotes).
    def clean(value):
        if isinstance(value, str):
            return sanitize(value)
        if isinstance(value, list):
            return [clean(v) for v in value]
        if isinstance(value, dict):
            return {k: clean(v) for k, v in value.items()}
        return value
    target = Path(path)
    tmp = None
    try:
        with NamedTemporaryFile(mode="w", dir=target.parent, prefix=".evaluation-", delete=False) as file:
            tmp = file.name
            json.dump(clean(data), file, indent=2, allow_nan=False)
            file.write("\n")
        os.replace(tmp, target)
    finally:
        if tmp and os.path.exists(tmp):
            os.unlink(tmp)


async def review_findings(response, contents, patches, settings):
    started = perf_counter()
    configured_secret = settings.ai_api_key.get_secret_value() if settings.ai_api_key else ""
    summary = AISummary(ai_enabled=settings.ai_enabled, prompt_version=PROMPT_VERSION,
        configured_provider=safe_identifier(settings.ai_provider, configured_secret),
        configured_model=safe_identifier(settings.ai_model, configured_secret))
    response.ai_summary = summary
    response.ai_complete = True  # Disabled/zero-selected: no AI work was expected.
    if not settings.ai_enabled:
        summary.ai_findings_disabled = len(response.findings)
        for finding in response.findings:
            finding.ai_review = AIReview(status="disabled")
        return
    eligible = []
    for index, finding in enumerate(response.findings):
        finding.ai_review = AIReview(status="skipped", skip_reason="finding_limit")
        if settings.ai_changed_lines_only and finding.is_on_changed_line is not True:
            finding.ai_review.skip_reason = "changed_line_filter"
        else:
            eligible.append(index)
    eligible.sort(key=lambda i: (response.findings[i].is_on_changed_line is not True,
        -RANK[response.findings[i].severity], response.findings[i].filename,
        response.findings[i].line_number, tuple(response.findings[i].rule_ids), i))
    selected = eligible[:settings.ai_max_findings]
    summary.ai_findings_selected = len(selected)
    for i in selected:
        response.findings[i].ai_review.selected = True
    provider = None
    halted = None
    if selected:
        try:
            provider = create_provider(settings)
        except ProviderError as exc:
            halted = exc.error
            summary.errors.append(halted)
        except Exception:
            halted = AIError(kind="configuration", message="AI provider initialization failed.")
            summary.errors.append(halted)
    for index in selected:
        finding = response.findings[index]
        review = finding.ai_review
        if halted:
            review.skip_reason = "provider_unavailable"
            review.error = halted
            continue
        try:
            context = build_context(finding, response, contents[finding.filename], patches.get(finding.filename),
                                    settings.ai_max_context_chars, settings.ai_context_lines)
        except (ContextError, KeyError) as exc:
            review.skip_reason = str(exc) if isinstance(exc, ContextError) else "code_unavailable"
            continue
        except Exception:
            review.skip_reason = "context_construction_failed"
            continue
        review.skip_reason = None
        review.finding_id = context.finding_id
        review.context_id = context.context_id
        review.context_chars = len(canonical(context.model_dump()))
        review.truncation_notes = list(context.truncation_notes)
        summary.ai_findings_requested += 1
        try:
            async with asyncio.timeout(settings.ai_timeout_seconds):
                result = await provider.review(context)
            # Revalidate even fake/custom provider results, including instances
            # constructed without validation; provider interfaces are a trust boundary.
            result = ProviderResult.model_validate(result.model_dump() if isinstance(result, ProviderResult) else result)
            refs = result.output.evidence_used
            if len(set(refs)) != len(refs) or not set(refs).issubset(context.references()):
                raise ProviderError("invalid_evidence", "AI review cited duplicate or unavailable evidence references.")
            secret = settings.ai_api_key.get_secret_value() if settings.ai_api_key else ""
            for text in (result.output.reasoning, result.output.remediation):
                if sanitize(text) != text or (secret and secret in text):
                    raise ProviderError("unsafe_output", "AI review contained a credential-like value and was rejected.")
            review.status = "completed"
            review.result = result.output
            review.provider_metadata = type(result.metadata)(**{
                key: safe_identifier(value, secret) for key, value in result.metadata.model_dump().items()})
        except TimeoutError:
            review.status = "failed"
            review.error = AIError(kind="timeout", message="AI review timed out.")
        except ProviderError as exc:
            review.status = "failed"
            review.error = exc.error
            if exc.stop:
                halted = exc.error
                summary.errors.append(halted)
        except Exception:
            review.status = "failed"
            review.error = AIError(kind="invalid_or_failed_review", message="AI review failed or did not satisfy its schema.")
    reviews = [f.ai_review for f in response.findings]
    summary.ai_findings_completed = sum(r.status == "completed" for r in reviews)
    summary.ai_findings_failed = sum(r.status == "failed" for r in reviews)
    summary.ai_findings_skipped = sum(r.status == "skipped" for r in reviews)
    summary.ai_verdict_counts = dict(Counter(r.result.verdict for r in reviews if r.result))
    summary.ai_priority_counts = dict(Counter(r.result.priority for r in reviews if r.result))
    response.ai_complete = all(response.findings[i].ai_review.status == "completed" for i in selected)
    summary.ai_runtime_seconds = perf_counter() - started
    if settings.ai_evaluation_output:
        try:
            export_evaluation(response, settings.ai_evaluation_output)
        except Exception:
            summary.export_error = AIError(kind="export_failed", message="Optional evaluation export could not be written.")
