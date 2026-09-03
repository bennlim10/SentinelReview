from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException
import httpx

from app.config import Settings
from app.integrations.github import GitHubClient, GitHubError
from app.models import AnalysisRequest, AnalysisResponse
from app.scanners.base import ScanError
from app.services.analysis import analyze

router = APIRouter(prefix="/api/v1")


def get_settings() -> Settings:
    return Settings()


async def get_github(settings: Annotated[Settings, Depends(get_settings)]):
    async with httpx.AsyncClient() as client:
        yield GitHubClient(client, settings)


@router.post("/analyze", response_model=AnalysisResponse)
async def analyze_pr(request: AnalysisRequest,
                     github: Annotated[GitHubClient, Depends(get_github)],
                     settings: Annotated[Settings, Depends(get_settings)]):
    try:
        return await analyze(request, github, settings)
    except GitHubError as exc:
        raise HTTPException(status_code=exc.status_code, detail=str(exc)) from exc
    except ScanError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
