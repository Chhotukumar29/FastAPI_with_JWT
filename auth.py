from datetime import timedelta, datetime
from typing import Annotated
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.orm import Session
from starlette import status
from database import SessionLocal
from models import Users
from passlib.context import CryptContext
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from jose import jwt, JWTError

router = APIRouter(
    prefix='/auth',
    tags=['auth']
)

SECRET_KEY = 'bfbf786e5ada106c497112aa6e052ca9c5ee828ea98269a883cb747f2564ae25'
ALGORITHM = 'HS256'

bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='auth/token')

class CreateUserRequest(BaseModel):
    username: str
    password: str

class Token(BaseModel):
    access_token: str
    token_type: str

# Define the get_db function
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

db_dependencies = Annotated[Session, Depends(get_db)]

@router.post('/register', status_code=status.HTTP_201_CREATED)
async def create_user(db: db_dependencies, create_user_request: CreateUserRequest):
    create_user_model = Users(
        username=create_user_request.username,
        password=bcrypt_context.hash(create_user_request.password),
    )
    
    db.add(create_user_model)
    db.commit()
    db.refresh(create_user_model)  # Refresh the instance to get the new ID
    return {"message": "User created successfully", "user_id": create_user_model.id}

@router.post('/token', response_model=Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: db_dependencies):
    user = authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid credentials")
    token = create_access_token(user.username, user.id, timedelta(minutes=20))
    return {'access_token': token, 'token_type': 'bearer'}

def authenticate_user(username: str, password: str, db):
    user = db.query(Users).filter(Users.username == username).first()
    if not user:
        return None
    if not bcrypt_context.verify(password, user.password):
        return None
    return user

def create_access_token(username: str, user_id: int, expires_delta: timedelta):
    encode = {'sub': username, 'id': user_id}
    expires = datetime.utcnow() + expires_delta
    encode.update({'exp': expires})
    return jwt.encode(encode, SECRET_KEY, algorithm=ALGORITHM)

@router.get('/users/me')
async def read_users_me(token: Annotated[str, Depends(oauth2_bearer)]):
    payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
    username: str = payload.get("sub")
    if username is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    return {"username": username}


