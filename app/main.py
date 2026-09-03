from fastapi import FastAPI

from app.api.routes import router

app = FastAPI(title="SentinelReview", version="0.2.0",
              description="Bandit and Semgrep analysis of changed Python files in public GitHub pull requests.")
app.include_router(router)
