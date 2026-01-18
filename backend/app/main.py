from fastapi import FastAPI, Depends, HTTPException, status, UploadFile, File, Form, Response, Request
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from sqlalchemy.orm import session
from typing import List, Optional
import shutil
import os
import uuid
from . import models, schemas, crud, auth, database
import pyotp
import qrcode
import io
from fastapi.responses import StreamingResponse
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

limiter = Limiter(key_func=get_remote_address)
app = FastAPI()
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

models.Base.metadata.create_all(bind=database.engine)   
app = FastAPI()

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def get_db():
    db = database.SessionLocal()
    try:
        yield db
    finally:
        db.close()

async def get_current_user(request: Request, db: session.Session = Depends(get_db)):
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
@limiter.limit("5/minute")
def register(user: schemas.UserCreate, db: session.Session = Depends(get_db)):
    db_user = crud.get_user_by_username(db, username=user.username)
    if db_user:
        raise HTTPException(status_code=400, detail="Nazwa użytkownika jest już zajęta")
    return crud.create_user(db=db, user=user)

@app.post("/token")
@limiter.limit("5/minute")
def login_for_access_token(
    request: Request,
    response:Response,
    form_data: OAuth2PasswordRequestForm = Depends(),
    db: session.Session = Depends(get_db),
    totp_code: str = Form(None)
    ):

    invalid_credentials_exc = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Nieprawidłowe dane logowania",
    )

    user = crud.get_user_by_username(db, form_data.username)
    if not user:
        auth.verify_password("fake", "$2b$12$EixZaYVK1fsbw1ZfbX3OXePaWxwKc.60rScphF.17yDAHJ8.s.jOi")
        raise invalid_credentials_exc
    
    if not auth.verify_password(form_data.password, user.hashed_password):
        raise invalid_credentials_exc

    if user.totp_secret and not totp_code:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Wymagany kod 2FA"
        )

    if user.totp_secret and not pyotp.TOTP(user.totp_secret).verify(totp_code):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Nieprawidłowy kod 2FA"
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
def send_message(
    recipient_username: str = Form(...),
    encrypted_content: str = Form(...),
    signature: str = Form(...),
    file: UploadFile = File(None),
    db: session.Session = Depends(get_db),
    current_user: schemas.User = Depends(get_current_user)
    ):

    attachment_path = None

    if file:
        os.makedirs("uploads", exist_ok=True)

        file_extension = os.path.splitext(file.filename)[1]
        unique_filename = f"{uuid.uuid4()}{file_extension}"
        file_location = f"uploads/{unique_filename}"

        with open(file_location, "wb") as buffer:
            shutil.copyfileobj(file.file, buffer)

        attachment_path = file_location

    msg = crud.create_message(
        db=db,
        recipient_username=recipient_username,
        encrypted_content=encrypted_content,
        signature=signature,
        sender_id=current_user.id,
        attachment_path=attachment_path
    )

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

@app.get("/2fa/setup")
def setup_2fa(current_user: models.User = Depends(get_current_user), db: session.Session = Depends(get_db)):
    if current_user.totp_secret:
        raise HTTPException(status_code=400, detail="2FA jest już skonfigurowane")

    totp_secret = pyotp.random_base32()
    totp_uri = pyotp.totp.TOTP(totp_secret).provisioning_uri(name=current_user.username, issuer_name="ODSI Messenger")

    qr = qrcode.QRCode(version=1, box_size=10, border=5)
    qr.add_data(totp_uri)
    qr.make(fit=True)
    img = qr.make_image(fill_color='black', back_color='white')

    buf = io.BytesIO()
    img.save(buf)
    buf.seek(0)

    current_user.totp_secret = totp_secret
    db.commit()
    
    return StreamingResponse(buf, media_type="image/png")

@app.delete("/messages/{message_id}")
def delete_message(
    message_id: int, 
    db: session.Session = Depends(get_db), 
    current_user: models.User = Depends(get_current_user)
):
    msg = db.query(models.Message).filter(models.Message.id == message_id).first()
    if not msg:
        raise HTTPException(status_code=404, detail="Nie znaleziono wiadomości")
    
    if msg.recipient_username != current_user.username and msg.sender_username != current_user.username:
         raise HTTPException(status_code=403, detail="Brak uprawnień")

    db.delete(msg)
    db.commit()
    return {"message": "Usunięto wiadomość"}

@app.post("/messages/{message_id}/read")
def mark_message_as_read(
    message_id: int, 
    db: session.Session = Depends(get_db), 
    current_user: models.User = Depends(get_current_user)
):
    msg = db.query(models.Message).filter(models.Message.id == message_id).first()
    if not msg or msg.recipient_username != current_user.username:
        raise HTTPException(status_code=404, detail="Nie znaleziono wiadomości")
    
    msg.is_read = True
    db.commit()
    return {"message": "Oznaczono jako przeczytane"}