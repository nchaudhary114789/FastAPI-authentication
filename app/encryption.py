from cryptography.fernet import Fernet
from .auth import settings

fernet = Fernet(settings.FERNET_KEY.encode())

def encrypt_data(data: str) -> str:
    return fernet.encrypt(
        data.encode()
    ).decode()

def decrypt_data(data: str) -> str:
    return fernet.decrypt(
        data.encode()
    ).decode()