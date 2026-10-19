import smtplib
from email.message import EmailMessage
from .auth import settings

def send_verification_email(
   recipient_email: str,
   verification_url: str
) -> None:
   message = EmailMessage()
   message["Subject"] = "Verify your email address"
   message["From"] = settings.SMTP_FROM_EMAIL
   message["To"] = recipient_email
   message.set_content(
       "Hello,\n\n"
       "Please verify your email address using the link below:\n\n"
       f"{verification_url}\n\n"
       "This link expires in "
       f"{settings.EMAIL_VERIFICATION_EXPIRE_MINUTES} minutes.\n\n"
       "If you did not create this account, you can ignore this email."
   )
   with smtplib.SMTP(
       settings.SMTP_HOST,
       settings.SMTP_PORT,
       timeout=15
   ) as smtp:
       smtp.ehlo()
       if settings.SMTP_USE_TLS:
           smtp.starttls()
           smtp.ehlo()
       smtp.login(
           settings.SMTP_USERNAME,
           settings.SMTP_PASSWORD
       )
       smtp.send_message(message)