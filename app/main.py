from fastapi import FastAPI

app = FastAPI(
    title="Log Agent API",
    description="AI-powered intelligent log monitoring and incident investigation",
    version="1.0.0",
)


@app.get("/")
async def root():
    return {
        "message": "Welcome to Log Agent API",
        "status": "running",
        "version": "1.0.0",
    }


@app.get("/health")
async def health_check():
    return {
        "status": "healthy",
        "service": "log-agent-backend",
    }