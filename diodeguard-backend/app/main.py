"""
DiodeGuard Backend — FastAPI Application Entry Point
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.core.config import settings
from app.database import engine, Base
from app.seed import seed_database
from app.routers import auth, traffic, detection, threats, alerts, dashboard, users, ws


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup: create tables and seed default admin/analyst and models
    try:
        Base.metadata.create_all(bind=engine)
        seed_database(engine)
    except Exception as e:
        print(f"[Startup WARNING] Database initialization error: {e}")
    yield


app = FastAPI(
    title="DiodeGuard API",
    description="AI-Based Detection of Cyber Threats in Unidirectional IP Traffic",
    version="1.0.0",
    docs_url="/docs",
    redoc_url="/redoc",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.backend_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth.router, prefix="/api/auth", tags=["Auth"])
app.include_router(traffic.router, prefix="/api/traffic", tags=["Traffic"])
app.include_router(detection.router, prefix="/api/detection", tags=["Detection"])
app.include_router(threats.router, prefix="/api/threats", tags=["Threats"])
app.include_router(alerts.router, prefix="/api/alerts", tags=["Alerts"])
app.include_router(dashboard.router, prefix="/api/dashboard", tags=["Dashboard"])
app.include_router(users.router, prefix="/api/users", tags=["Users"])
app.include_router(ws.router, prefix="/api", tags=["WebSocket"])
app.include_router(ws.router, prefix="", tags=["WebSocket"])


@app.get("/", tags=["Health"])
def root():
    return {"status": "ok", "service": "DiodeGuard API", "version": "1.0.0"}


@app.get("/health", tags=["Health"])
def health():
    return {"status": "healthy"}
