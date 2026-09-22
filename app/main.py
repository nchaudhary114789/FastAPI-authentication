from fastapi import FastAPI
from .database import Base, engine
from .routes.auth_routes import router as auth_router
from .routes.user_routes import router as user_router

Base.metadata.create_all(bind=engine)

app = FastAPI(
    title = "FastAPI Authentication API",
    version = "1.0.0"
)

app.include_router(auth_router)
app.include_router(user_router)

@app.get("/")
def root():
    return {
        "message": "Authentication API is running"
    }
