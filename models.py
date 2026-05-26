import re
from pydantic import BaseModel, validator
from typing import List
from passlib.context import CryptContext
from sqlalchemy import Column, Integer, String, Boolean, DateTime, ForeignKey
from sqlalchemy.sql import func
from sqlalchemy.orm import relationship
from db import Base

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

class Role(Base):
    __tablename__ = "roles"
    id = Column(Integer, primary_key=True, index=True)
    name = Column(String, unique=True, index=True)

class User(Base):
    __tablename__ = "users"
    id = Column(Integer, primary_key=True, index=True)
    username = Column(String, unique=True, index=True, nullable=False)
    email = Column(String, unique=True, index=True, nullable=False)
    hashed_password = Column(String, nullable=False)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime(timezone=True), server_default=func.now())
    updated_at = Column(DateTime(timezone=True), onupdate=func.now())

    def verify_password(self, plain_password):
        return pwd_context.verify(plain_password, self.hashed_password)

class RefreshToken(Base):
    __tablename__ = "refresh_tokens"
    id = Column(Integer, primary_key=True)
    token = Column(String, unique=True, nullable=False)
    user_id = Column(Integer, ForeignKey("users.id"))
    expires_at = Column(DateTime(timezone=True), nullable=False)
    is_revoked = Column(Boolean, default=False)
    created_at = Column(DateTime(timezone=True), server_default=func.now())

# --- SCHÉMAS PYDANTIC (Validation des flux de données) ---

class RoleSchema(BaseModel):
    name: str

class UserCreate(BaseModel):
    username: str
    email: str
    password: str

    @validator("password")
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError("Minimum 8 caractères")
        if not re.search(r"[A-Z]", v):
            raise ValueError("Au moins une majuscule")
        if not re.search(r"[0-9]", v):
            raise ValueError("Au moins un chiffre")
        if not re.search(r"[!@#$%^&*]", v):
            raise ValueError("Au moins un caractère spécial")
        return v

# Sécurité : On ne renvoie JAMAIS le hashed_password au client
class UserOut(BaseModel):
    id: int
    username: str
    email: str
    is_active: bool

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str

class UserRoles(BaseModel):
    roles: List[RoleSchema] = []