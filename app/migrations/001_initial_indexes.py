def up(db):
   """
   Create indexes required by the authentication system.
   """
   db.users.create_index(
       "email",
       unique=True,
       name="unique_user_email"
   )
   db.users.create_index(
       "role",
       name="user_role_index"
   )
   db.revoked_tokens.create_index(
       "jti",
       unique=True,
       name="unique_revoked_token_jti"
   )
   db.revoked_tokens.create_index(
       "expires_at",
       expireAfterSeconds=0,
       name="revoked_token_expiry"
   )