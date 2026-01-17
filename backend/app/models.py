from sqlalchemy import Column, Integer, String, ForeignKey, DateTime, Text, Boolean
from sqlalchemy.orm import relationship
from sqlalchemy.sql import func
from .database import Base

class User(Base):
    __tablename__ = "users"

    id=Column(Integer, primary_key=True, index=True)
    username=Column(String, unique=True, index=True, nullable=False)
    hashed_password=Column(String, nullable=False)
    public_key=Column(Text, nullable=False)
    encrypted_private_key=Column(Text, nullable=False)
    totp_secret=Column(String, nullable=True)

    messages_sent = relationship("Message", foreign_keys="[Message.sender_id]", back_populates="sender")
    messages_received = relationship("Message", foreign_keys="[Message.recipient_id]", back_populates="recipient")

class Message(Base):
    __tablename__ = "messages"

    id=Column(Integer, primary_key=True, index=True)
    sender_id=Column(Integer, ForeignKey("users.id"), nullable=False)
    recipient_id=Column(Integer, ForeignKey("users.id"), nullable=False)

    # Treść zaszyfrowanej wiadomości AES
    encrypted_content=Column(Text, nullable=False)
    signature=Column(String, nullable=False)
    attachment_path=Column(String, nullable=True)
    created_at=Column(DateTime(timezone=True), server_default=func.now())
    is_read=Column(Boolean, default=False)

    sender=relationship("User", foreign_keys=[sender_id], back_populates="messages_sent")
    recipient=relationship("User", foreign_keys=[recipient_id], back_populates="messages_received")