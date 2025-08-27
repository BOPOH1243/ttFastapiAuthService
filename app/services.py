# app/security.py
from datetime import datetime, timedelta,timezone
from typing import Tuple, Any, Dict
from passlib.context import CryptContext
from jose import jwt, JWTError, ExpiredSignatureError
from .settings import settings

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def get_password_hash(password: str) -> str:
    """
    Хэширует пароль с использованием bcrypt.
    """
    return pwd_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """
    Проверяет соответствие пароля и его хэша.
    """
    return pwd_context.verify(plain_password, hashed_password)


def create_tokens(subject: str) -> Tuple[str, str]:
    """
    Создает пару JWT токенов (access и refresh) для указанного субъекта.
    """
    now = datetime.now(timezone.utc)
    access_exp = int((now + timedelta(minutes=int(settings.ACCESS_TOKEN_EXPIRE_MINUTES))).timestamp())
    refresh_exp = int((now + timedelta(minutes=int(settings.REFRESH_TOKEN_EXPIRE_MINUTES))).timestamp())

    access_payload: Dict[str, Any] = {
        "sub": subject,
        "exp": access_exp,
        "type": "access"
    }

    refresh_payload: Dict[str, Any] = {
        "sub": subject,
        "exp": refresh_exp,
        "type": "refresh"
    }

    access_token: str = jwt.encode(access_payload, settings.SECRET_KEY, algorithm="HS256")
    refresh_token: str = jwt.encode(refresh_payload, settings.SECRET_KEY, algorithm="HS256")

    return access_token, refresh_token


def decode_token(token: str, expected_type: str|None = None) -> Dict[str, Any]:
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=["HS256"])
        if expected_type and payload.get("type") != expected_type:
            raise JWTError(f"Invalid token type: expected {expected_type}")
        return payload
    except ExpiredSignatureError:
        raise JWTError("Token has expired")
    except JWTError:
        raise JWTError("Invalid token")
