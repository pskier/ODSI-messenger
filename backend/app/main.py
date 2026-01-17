from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form, Response, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import session
from typing import List, Optional
import shutil
import os
import uuid
from . import models, schemas, crud, auth, database

models.Base.metadata.create_all(bind=database.engine)   
app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def get_current_user(token: str = Depends(oauth2_scheme), db: session.Session = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Brak autoryzacji (ciasteczko nieprawidłowe lub wygasło)",
        )
    
    token_cookie = request.cookies.get("access_token")

    if not token_cookie:
        raise credentials_exception
    
    token=token_cookie.replace("Bearer ", "") if token_cookie.startswith("Bearer ") else token_cookie

    try:
        payload = auth.jwt.decode(token, auth.SECRET_KEY, algorithms=[auth.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
    except auth.JWTError:
        raise credentials_exception

    user = crud.get_user_by_username(db, username=username)
    if user is None:
        raise credentials_exception
    return user

# Endpointy API i logika aplikacji
@app.post("/register", response_model=schemas.User)
def register(user: schemas.UserCreate, db: session.Session = Depends(get_db)):
    db_user = crud.get_user_by_username(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Nazwa użytkownika jest już zajęta")
    return crud.create_user(db=db, user=user)

@app.post("/token")
def login_for_access_token(response:Response,form_data: OAuth2PasswordRequestForm = Depends(), db: session.Session = Depends(get_db)):
    user = crud.get_user_by_username(db,form_data.username)

    if not user or not auth.verify_password(form_data.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nieprawidłowa nazwa użytkownika lub hasło"
        )
    
    access_token=auth.create_access_token(data={"sub": user.username})

    response.set_cookie(
        key="access_token", 
        value=f"Bearer {access_token}", 
        httponly=True, 
        samesite="Lax",
        secure=False 
    )

    return {"message": "Zalogowano pomyślnie"}

@app.get("/users/me", response_model=schemas.User)
def read_users_me(current_user: schemas.User = Depends(get_current_user)):
    return current_user

@app.post("/messages", response_model=schemas.MessageResponse)
def send_message(message: schemas.MessageCreate, current_user: schemas.User = Depends(get_current_user), db: session.Session = Depends(get_db)):
    msg= crud.create_message(db=db, message=message, sender_id=current_user.id)

    if not msg:
        raise HTTPException(status_code=404, detail="Odbiorca nie istnieje")
    
    msg.sender_username = current_user.username
    return msg

@app.get("/messages", response_model=List[schemas.MessageResponse])
def get_my_messages(db: session.Session = Depends(get_db), current_user: schemas.User = Depends(get_current_user)):
    messages = crud.get_messages_for_user(db, current_user.id)

    for msg in messages:
        msg.sender_username = msg.sender.username

    return messages
