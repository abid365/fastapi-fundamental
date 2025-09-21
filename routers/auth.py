from fastapi import APIRouter, status, Depends, HTTPException
from pydantic import BaseModel
from models import Users
from passlib.context import CryptContext
from database import SessionLocal
from typing import Annotated
from sqlalchemy.orm import Session
from fastapi.security import OAuth2PasswordRequestForm, OAuth2PasswordBearer
from jose import jwt, JWTError
from datetime import timedelta, datetime, timezone
from icecream import ic

router = APIRouter(
    prefix='/auth',
    tags=['auth']
)

bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')
oauth2_bearer = OAuth2PasswordBearer(tokenUrl='/auth/token')

SECRET_KEY = '9f75db78571450a4a74ccf8ec6bc8f84420c1fd969393309db159828da614157'
ALGORITHM = 'HS256'


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]


def authenticate_users(username: str, password: str, db):
    user = db.query(Users).filter(Users.username == username).first()
    if not user:
        return False
    if not bcrypt_context.verify(password, user.hashed_password):
        return False
    return user


def create_access_token(username: str, user_id: int, role: str, expires_delta: timedelta):
    encode = {'sub': username, 'id': user_id, 'role': role}
    expires = datetime.now(timezone.utc) + expires_delta
    encode.update({'exp': expires})
    return jwt.encode(encode, SECRET_KEY, ALGORITHM)


async def get_current_user(token: Annotated[str, Depends(oauth2_bearer)]):
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get('sub')
        user_id: int = payload.get('id')
        role: str = payload.get('role')
        ic('Inside get_current_user')
        ic(username)
        ic(user_id)
        if (username is None or user_id is None):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED, detail='Invalid token')
        return {'username': username, 'id': user_id, 'user_role': role}
    except JWTError as e:
        ic(token)
        ic(e)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail=f'{e}')


class create_user(BaseModel):
    user_name: str
    email: str
    first_name: str
    last_name: str
    password: str
    role: str


class Token(BaseModel):
    access_token: str
    token_type: str


@router.post("/", status_code=status.HTTP_201_CREATED)
async def create_user(db: db_dependency, create_user_req: create_user):

    create_user_model = Users(
        email=create_user_req.email,
        username=create_user_req.user_name,
        first_name=create_user_req.first_name,
        last_name=create_user_req.last_name,
        hashed_password=bcrypt_context.hash(create_user_req.password),
        role=create_user_req.role,
        is_active=True
    )

    db.add(create_user_model)
    db.commit()


@router.post("/token/", response_model=Token)
async def login_for_access_token(form_data: Annotated[OAuth2PasswordRequestForm, Depends()], db: db_dependency):
    user = authenticate_users(
        form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED, detail='Failed to authorize')
    else:
        token = create_access_token(
            username=user.username, user_id=user.id, role=user.role, expires_delta=timedelta(minutes=30))
        return {'access_token': token, 'token_type': 'bearer'}
