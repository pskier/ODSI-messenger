from pydantic import BaseModel
from typing import Optional
from datetime import datetime

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