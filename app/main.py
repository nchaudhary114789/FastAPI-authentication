from fastapi import FastAPI
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from .database import Base, engine
from .routes.auth_routes import router as auth_router
from .routes.user_routes import router as user_router
from .rate_limit import limiter

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title = "FastAPI Authentication API",
    version = "1.0.0"
)

app.state.limiter = limiter

app.add_exception_handler(
    RateLimitExceeded,
    _rate_limit_exceeded_handler
)

app.include_router(auth_router)
app.include_router(user_router)

@app.get("/")
def root():
    return {
        "message": "Authentication API is running"
    }
