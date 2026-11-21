from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from app.core.config import settings
from app.core.database import init_db, SessionLocal
from app.api.router import api_router
from app.workers.job_queue import job_queue_manager
from app.services.static_analysis.worker import static_worker_manager

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Initialize database tables and private storage directories safely on startup
    init_db()
    db = SessionLocal()
    try:
        recovered = job_queue_manager.recover_stale_jobs(db)
        static_recovered = static_worker_manager.recover_stale_jobs(db)
        if recovered > 0 or static_recovered > 0:
            print(f"[*] malbox-ai startup: Safely recovered {recovered} dynamic and {static_recovered} static task(s).")
    finally:
        db.close()

    # Start background job queue consumers
    static_worker_manager.start()
    job_queue_manager.start()
    yield
    # Stop background consumers gracefully (propagate cancellation to any active Ghidra subprocess)
    static_worker_manager.stop(wait_seconds=5.0)
    job_queue_manager.stop()

app = FastAPI(
    title=settings.PROJECT_NAME,
    version=settings.VERSION,
    description=settings.DESCRIPTION,
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc",
)

# CORS configuration for development and frontend integration
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.CORS_ORIGINS,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(api_router)

@app.get("/", tags=["Root"])
def root():
    return {
        "project": settings.PROJECT_NAME,
        "version": settings.VERSION,
        "status": "online",
        "documentation": "/docs",
        "health_check": "/api/v1/health",
    }

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("app.main:app", host=settings.HOST, port=settings.PORT, reload=settings.DEBUG)
