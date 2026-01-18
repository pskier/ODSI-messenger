from pydantic import BaseModel, validator
from typing import Optional
from datetime import datetime
import re

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    username: Optional[str] = None

class UserBase(BaseModel):
    username: str

class UserCreate(UserBase):
    password: str
    public_key: str
    encrypted_private_key: str
    
    @validator('password')
    def validate_password(cls, v):
        if len(v) < 8:
            raise ValueError('Hasło musi mieć minimum 8 znaków')
        if not re.search(r"[A-Z]", v):
            raise ValueError('Hasło musi zawierać dużą literę')
        if not re.search(r"\d", v):
            raise ValueError('Hasło musi zawierać cyfrę')
        if not re.search(r"[!@#$%^&*(),.?\":{}|<>]", v):
            raise ValueError('Hasło musi zawierać znak specjalny')
        return v

class User(UserBase):
    id: int
    public_key: str
    encrypted_private_key: str

    class Config:
        from_attributes = True

class MessageCreate(BaseModel):
    recepient_id: int
    encrypted_content: str
    signature: str

class MessageResponse(BaseModel):
    id: int
    sender_username: str
    encrypted_content: str
    signature: str
    attachment_path: Optional[str] = None
    created_at: datetime    

    class Config:
        from_attributes = True