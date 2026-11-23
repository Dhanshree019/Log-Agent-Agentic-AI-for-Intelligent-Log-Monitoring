from fastapi import FastAPI
from app.api.logs import router as logs_router

app = FastAPI(
    title="Log Agent API",
    description="AI-powered intelligent log monitoring and incident investigation",
    version="1.0.0",
)

# Include routes under /api/v1/logs as well as direct /analyze for easy access
app.include_router(logs_router, prefix="/api/v1/logs", tags=["Log Analysis"])
app.include_router(logs_router, tags=["Log Analysis"])


@app.get("/", tags=["General"])
async def root():
    return {
        "message": "Welcome to Log Agent API",
        "status": "running",
        "version": "1.0.0",
        "docs_url": "/docs",
    }


@app.get("/health", tags=["General"])
async def health_check():
    return {
        "status": "healthy",
        "service": "log-agent-backend",
    }
