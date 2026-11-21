from __future__ import annotations

from fastapi import FastAPI
from .routes import router

app = FastAPI(
    title="Malbox REMnux Deterministic Sandbox Gateway",
    description="Deterministic forensic execution and evidence packaging gateway on REMnux.",
    version="1.0.0",
)

app.include_router(router)


def create_app() -> FastAPI:
    return app

