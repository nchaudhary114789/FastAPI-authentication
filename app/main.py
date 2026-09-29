from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
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

MAX_BODY_SIZE = 1 * 1024 * 1024  # 1 MB

@app.middleware("http")
async def limit_request_body_size(
   request: Request,
   call_next
):
   content_length = request.headers.get("content-length")
   if content_length:
       try:
           content_length = int(content_length)
       except ValueError:
           return JSONResponse(
               status_code=400,
               content={
                   "detail": "Invalid Content-Length header"
               }
           )
       if content_length > MAX_BODY_SIZE:
           return JSONResponse(
               status_code=413,
               content={
                   "detail": "Request body too large. Maximum size is 1 MB."
               }
           )
   response = await call_next(request)
   return response

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
