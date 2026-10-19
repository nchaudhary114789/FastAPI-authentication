import logging
import time
import uuid
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded
from starlette.middleware.cors import CORSMiddleware
from starlette.middleware.httpsredirect import HTTPSRedirectMiddleware
from .routes.auth_routes import router as auth_router
from .routes.user_routes import router as user_router
from .routes.health_routes import router as health_router
from .rate_limit import limiter
from .auth import settings
from .logging_config import configure_logging

configure_logging()
logger = logging.getLogger("app.requests")

ENABLE_API_DOCS = settings.ENABLE_API_DOCS
ENABLE_HTTPS_REDIRECT = settings.ENABLE_HTTPS_REDIRECT
ALLOWED_ORIGINS = [
   origin.strip()
   for origin in settings.ALLOWED_ORIGINS.split(",")
   if origin.strip()
]

app = FastAPI(
   title="FastAPI Authentication API",
   version="1.0.0",
   docs_url="/docs" if ENABLE_API_DOCS else None,
   redoc_url="/redoc" if ENABLE_API_DOCS else None,
   openapi_url="/openapi.json" if ENABLE_API_DOCS else None
)

app.add_middleware(
   CORSMiddleware,
   allow_origins=ALLOWED_ORIGINS,
   allow_credentials=True,
   allow_methods=[
       "GET",
       "POST",
       "PATCH",
       "PUT",
       "DELETE",
       "OPTIONS"
   ],
   allow_headers=[
       "Authorization",
       "Content-Type"
   ],
   expose_headers=["X-Request-ID"]
)

if ENABLE_HTTPS_REDIRECT:
   app.add_middleware(
       HTTPSRedirectMiddleware
   )

@app.middleware("http")
async def security_headers(
   request: Request,
   call_next
):
   response = await call_next(request)
   response.headers["X-Content-Type-Options"] = "nosniff"
   response.headers["X-Frame-Options"] = "DENY"
   response.headers["Referrer-Policy"] = (
       "strict-origin-when-cross-origin"
   )
   response.headers["Permissions-Policy"] = (
       "geolocation=(), "
       "microphone=(), "
       "camera=()"
   )
   if ENABLE_HTTPS_REDIRECT:
       response.headers["Strict-Transport-Security"] = (
           "max-age=31536000; "
           "includeSubDomains"
       )
   return response

MAX_BODY_SIZE = 1 * 1024 * 1024

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
                   "detail": (
                       "Request body too large. "
                       "Maximum size is 1 MB."
                   )
               }
           )
   response = await call_next(request)
   return response

@app.middleware("http")
async def request_logging(
   request: Request,
   call_next
):
   request_id = str(uuid.uuid4())
   request.state.request_id = request_id
   start_time = time.perf_counter()
   status_code = 500
   try:
       response = await call_next(request)
       status_code = response.status_code
   except Exception:
       logger.exception(
           "Request processing failed",
           extra={
               "event": "request_error",
               "request_id": request_id,
               "method": request.method,
               "path": request.url.path
           }
       )
       raise
   finally:
       duration_ms = round(
           (time.perf_counter() - start_time) * 1000,
           2
       )
   logger.info(
            "HTTP request completed",
            extra={
                "event": "http_request",
                "request_id": request_id,
                "method": request.method,
                "path": request.url.path,
                "status_code": status_code,
                "duration_ms": duration_ms
            }
        )
   response.headers["X-Request-ID"] = request_id
   return response

app.state.limiter = limiter
app.add_exception_handler(
   RateLimitExceeded,
   _rate_limit_exceeded_handler
)

app.include_router(auth_router)
app.include_router(user_router)
app.include_router(health_router)

@app.get("/")
def root():
   return {
       "message": "Authentication API is running"
   }