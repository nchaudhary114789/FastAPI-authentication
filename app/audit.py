import logging
from datetime import datetime, timezone
from typing import Any
from .database import audit_logs_collection

logger = logging.getLogger("app.audit")

def log_audit_event(
   event: str,
   outcome: str,
   request_id: str | None = None,
   user_id: str | None = None,
   details: dict[str, Any] | None = None
) -> None:
   """
   Record a security-related event in MongoDB.
   Never include passwords, tokens, or other secrets
   in the details dictionary.
   """
   audit_record = {
       "event": event,
       "outcome": outcome,
       "timestamp": datetime.now(timezone.utc),
       "request_id": request_id,
       "user_id": user_id,
       "details": details or {}
   }
   try:
       audit_logs_collection.insert_one(audit_record)
   except Exception:
       logger.exception(
           "Failed to persist audit event",
           extra={
               "event": "audit_persistence_failed",
               "request_id": request_id,
               "audit_event": event,
               "outcome": outcome
           }
       )