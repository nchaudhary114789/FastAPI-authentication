from app.audit import log_audit_event

log_audit_event(
   event="test_audit",
   outcome="success",
   request_id="test-request-001",
   user_id=None,
   details={
       "message": "Audit logging test"
   }
)
print("Audit logging test completed.")