"""First provider adapter. No provider wire formats escape this module."""
import json
import re
from urllib.parse import urlsplit

import httpx
from pydantic import ValidationError

from app.ai.base import ProviderError, ReviewProvider
from app.ai.context import canonical, sanitize
from app.ai.models import ProviderMetadata, ProviderResult, ReviewInput, ReviewOutput
from app.ai.prompts import SYSTEM_PROMPT


def safe_identifier(value, secret: str = "") -> str | None:
    if not isinstance(value, str) or not value or len(value) > 200:
        return None
    if (secret and secret in value) or sanitize(value) != value or "://" in value:
        return None
    return value if re.fullmatch(r"[A-Za-z0-9_.:/-]+", value) else None


class OpenAIProvider:
    def __init__(self, settings, transport=None):
        self.settings = settings
        self.transport = transport  # Test seam; no runtime alternate provider.

    async def review(self, context: ReviewInput) -> ProviderResult:
        settings = self.settings
        secret = settings.ai_api_key.get_secret_value()
        payload = {
            "model": settings.ai_model,
            "instructions": SYSTEM_PROMPT,
            "input": [{"role": "user", "content": canonical(context.model_dump())}],
            "text": {"format": {"type": "json_schema", "name": "security_review",
                                  "strict": True, "schema": ReviewOutput.model_json_schema()}},
            "max_output_tokens": settings.ai_max_output_tokens,
            "store": False,
            "tools": [],
        }
        try:
            async with httpx.AsyncClient(transport=self.transport, trust_env=False,
                                         follow_redirects=False) as client:
                async with client.stream("POST", settings.ai_endpoint, json=payload,
                        headers={"Authorization": f"Bearer {secret}"},
                        timeout=settings.ai_timeout_seconds) as response:
                    status = response.status_code
                    if status in (401, 403):
                        raise ProviderError("authentication", "AI provider rejected authentication or access.", stop=True)
                    if status == 429:
                        raise ProviderError("rate_limit", "AI provider rate limit reached.", stop=True)
                    if status != 200:
                        raise ProviderError("provider_http_error", f"AI provider returned HTTP {status}.")
                    body = bytearray()
                    async for chunk in response.aiter_bytes():
                        body.extend(chunk)
                        if len(body) > settings.ai_max_response_bytes:
                            raise ProviderError("response_too_large", "AI response exceeded the configured byte limit.")
                    request_id = safe_identifier(response.headers.get("x-request-id"), secret)
            data = json.loads(body)
            if data.get("status") != "completed":
                raise ProviderError("incomplete_response", "AI provider did not complete the response.")
            texts = []
            for item in data["output"]:
                if item.get("type") == "reasoning":
                    continue
                if item.get("type") != "message" or item.get("role") != "assistant":
                    raise ProviderError("unexpected_output", "AI provider returned an unexpected output type.")
                for block in item["content"]:
                    if block.get("type") == "refusal":
                        raise ProviderError("refusal", "AI provider declined the review.")
                    if block.get("type") != "output_text":
                        raise ProviderError("unexpected_output", "AI provider returned an unexpected content type.")
                    texts.append(block["text"])
            if len(texts) != 1:
                raise ProviderError("invalid_response", "Expected exactly one structured review.")
            output = ReviewOutput.model_validate_json(texts[0])
            return ProviderResult(output=output, metadata=ProviderMetadata(
                reported_model=safe_identifier(data.get("model"), secret),
                response_id=safe_identifier(data.get("id"), secret), request_id=request_id))
        except httpx.TimeoutException:
            raise ProviderError("timeout", "AI provider request timed out.") from None
        except httpx.RequestError:
            raise ProviderError("unavailable", "AI provider could not be reached.") from None
        except (ValueError, KeyError, TypeError, AttributeError, ValidationError):
            raise ProviderError("invalid_response", "AI provider returned malformed or schema-invalid output.") from None


def create_provider(settings) -> ReviewProvider:
    if settings.ai_provider != "openai":
        raise ProviderError("configuration", "AI_PROVIDER must select a supported provider.", stop=True)
    if not settings.ai_model or not settings.ai_endpoint or not settings.ai_api_key or not settings.ai_api_key.get_secret_value():
        raise ProviderError("configuration", "AI model, endpoint and API key must be configured.", stop=True)
    try:
        url = urlsplit(settings.ai_endpoint)
        if url.scheme != "https" or not url.hostname or url.username or url.password or url.query or url.fragment:
            raise ValueError()
    except ValueError:
        raise ProviderError("configuration", "AI endpoint must be an HTTPS URL without embedded credentials, query or fragment.", stop=True) from None
    return OpenAIProvider(settings)
