from sqlalchemy.orm import Session
from . import models, schemas,auth

def get_user(db: Session, user_id: int):
    return db.query(models.User).filter(models.User.id == user_id).first()

def get_user_by_username(db: Session, username: str):
    return db.query(models.User).filter(models.User.username == username).first()

def create_user(db: Session, user: schemas.UserCreate):
    hashed_password = auth.get_password_hash(user.password)
    db_user = models.User(username=user.username, hashed_password=hashed_password, public_key=user.public_key, encrypted_private_key=user.encrypted_private_key)
    
    db.add(db_user)
    db.commit()
    db.refresh(db_user)
    return db_user

def create_message(db: Session, message: schemas.MessageCreate, sender_id: int):
    recepient = get_user_by_username(db, message.recipient_username)
    if not recepient:
        return None
    
    db_message = models.Message(
        sender_id=sender_id,
        recipient_id=recepient.id,
        encrypted_content=message.encrypted_content,
        signature=message.signature
    )

    db.add(db_message)
    db.commit()
    db.refresh(db_message)
    return db_message

def get_messages_for_user(db: Session, user_id: int):
    return db.query(models.Message).filter(models.Message.recipient_id == user_id).all()