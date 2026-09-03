from fastapi import FastAPI

from app.api.routes import router

app = FastAPI(title="SentinelReview", version="0.1.0",
              description="Bandit analysis of changed Python files in public GitHub pull requests.")
app.include_router(router)
