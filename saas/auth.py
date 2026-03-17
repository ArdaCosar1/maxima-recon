"""
Maxima SaaS — JWT Kimlik Dogrulama
"""
import hashlib
import hmac
from datetime import datetime, timedelta
from typing import Optional

from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from jose import JWTError, jwt
from sqlalchemy.orm import Session

from saas.config import SECRET_KEY, ALGORITHM, ACCESS_TOKEN_EXPIRE_MINUTES
from saas.models import User, get_db

security = HTTPBearer(auto_error=False)


# ── Sifre hashleme (stdlib — harici paket gerektirmez) ────────
def _hash_password(password: str) -> str:
    salt = hashlib.sha256(SECRET_KEY.encode()).hexdigest()[:16]
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt.encode(), 100_000
    ).hex()


def verify_password(plain: str, hashed: str) -> bool:
    return hmac.compare_digest(_hash_password(plain), hashed)


def hash_password(password: str) -> str:
    return _hash_password(password)


# ── JWT Token ─────────────────────────────────────────────────
def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    expire = datetime.utcnow() + (expires_delta or timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES))
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)


def decode_token(token: str) -> dict:
    return jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])


# ── Kullanici dogrulama dependency ────────────────────────────
async def get_current_user(
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(security),
    db: Session = Depends(get_db),
) -> User:
    if credentials is None:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Kimlik dogrulama gerekli",
        )

    token = credentials.credentials
    # API key kontrolu (mx_ ile baslar)
    if token.startswith("mx_"):
        user = db.query(User).filter(User.api_key == token, User.is_active == True).first()
        if not user:
            raise HTTPException(status_code=401, detail="Gecersiz API anahtari")
        return user

    # JWT token kontrolu
    try:
        payload = decode_token(token)
        user_id: str = payload.get("sub")
        if user_id is None:
            raise HTTPException(status_code=401, detail="Gecersiz token")
    except JWTError:
        raise HTTPException(status_code=401, detail="Token suresi dolmus veya gecersiz")

    user = db.query(User).filter(User.id == user_id, User.is_active == True).first()
    if not user:
        raise HTTPException(status_code=401, detail="Kullanici bulunamadi")
    return user


async def get_admin_user(user: User = Depends(get_current_user)) -> User:
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Admin yetkisi gerekli")
    return user
