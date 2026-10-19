from fastapi import APIRouter
from fastapi.responses import JSONResponse
from ..database import client

router = APIRouter(tags=["Health"])

@router.get("/health")
def health_check():
    try: 
        client.admin.command("ping")
        return {
            "status": "healthy",
            "database": "Connected"
        }
    except Exception:
        return JSONResponse(
            status_code=503,
            content={
                "status": "unhealthy",
                "database": "disconnected"
            }
        )

