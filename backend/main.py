from contextlib import asynccontextmanager
from typing import AsyncIterator, Optional

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from backend.api.routes.scan import router as scan_router
from backend.config import Settings, get_settings
from backend.database import Database


def create_app(settings: Optional[Settings] = None) -> FastAPI:
    resolved_settings = settings or get_settings()

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        app.state.database.create_tables()
        yield

    app = FastAPI(title="TraceLens", version="0.4.0-alpha4", lifespan=lifespan)
    app.state.settings = resolved_settings
    app.state.database = Database(resolved_settings)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["http://localhost:5173", "http://127.0.0.1:5173"],
        allow_credentials=False,
        allow_methods=["GET", "POST"],
        allow_headers=["Content-Type"],
    )

    @app.get("/health")
    def health() -> dict:
        return {"status": "ok"}

    app.include_router(scan_router)
    return app


app = create_app()
