from contextlib import asynccontextmanager

from fastapi import FastAPI

from app.db.models import init_db
from app.routes import agent, logs, proxy


@asynccontextmanager
async def lifespan(app: FastAPI):
    init_db()
    yield


app = FastAPI(
    title="DGuard",
    description="Self-hosted compliance proxy for Anthropic API calls",
    version="0.1.0",
    lifespan=lifespan,
)

app.include_router(proxy.router)
app.include_router(logs.router)
app.include_router(agent.router)


@app.get("/health")
def health():
    return {"status": "ok"}
