from typing import Protocol
from app.ai.models import ReviewInput, ProviderResult, AIError


class ProviderError(Exception):
    def __init__(self, kind: str, message: str, *, stop: bool = False):
        super().__init__(message)
        self.error = AIError(kind=kind, message=message)
        self.stop = stop


class ReviewProvider(Protocol):
    async def review(self, context: ReviewInput) -> ProviderResult: ...
