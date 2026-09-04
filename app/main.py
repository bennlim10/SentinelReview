from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.routes import router

app = FastAPI(title="SentinelReview", version="0.5.0",
              description="Bandit and Semgrep analysis of changed Python files in public GitHub pull requests.")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
    allow_methods=["POST", "OPTIONS"],
    allow_headers=["Content-Type"],
)
app.include_router(router)
