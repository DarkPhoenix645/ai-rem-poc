from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.api.endpoints import scans, config
from app.config import get_settings
from app.services.cache_service import CacheService
from app.services.database_service import database_service

settings = get_settings()


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan management"""
    # Startup
    settings = get_settings()
    
    # Initialize services
    cache_service = CacheService()
    
    # Health check connections
    redis_healthy = await cache_service.health_check()
    db_healthy = await database_service.health_check()
    
    if not redis_healthy:
        raise RuntimeError("Redis connection failed")
    if not db_healthy:
        raise RuntimeError("Database connection failed")
    
    print("IAM Scanner started successfully")
    
    yield
    
    # Shutdown
    print("IAM Scanner shutdown complete")


# Create FastAPI app
app = FastAPI(
    title="IAM Security Scanner",
    description="AI-powered IAM policy analysis and security scanning",
    version="1.0.0",
    lifespan=lifespan
)

# CORS middleware - allow from anywhere for development
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allow from anywhere
    allow_credentials=False,  # Must be False when allow_origins=["*"]
    allow_methods=["*"],
    allow_headers=["*"],
)

# Include routers
app.include_router(scans.router, prefix="/api/v1", tags=["scans"])
app.include_router(config.router, prefix="/api/v1", tags=["config"])


@app.get("/health")
async def health_check():
    """Health check endpoint"""
    return {"status": "healthy", "service": "iam-scanner"}


@app.get("/")
async def root():
    """Root endpoint"""
    return {
        "message": "IAM Security Scanner API",
        "version": "1.0.0",
        "docs": "/docs"
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
