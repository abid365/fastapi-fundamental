from typing import Annotated
from sqlalchemy.orm import Session
from database import SessionLocal
from fastapi import APIRouter, HTTPException, status, Depends
from .auth import get_current_user
from passlib.context import CryptContext
from models import Users
from pydantic import BaseModel, Field


router = APIRouter(
    prefix='/user',
    tags=['user']
)


def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


db_dependency = Annotated[Session, Depends(get_db)]
user_dependency = Annotated[dict, Depends(get_current_user)]
bcrypt_context = CryptContext(schemes=['bcrypt'], deprecated='auto')


class UpdatePassword(BaseModel):
    password: str
    new_password: str = Field(min_length=6)


@router.get('/', status_code=status.HTTP_200_OK)
async def get_user(db: db_dependency, user: user_dependency):
    if user is None:
        raise HTTPException(status_code=404, detail='Authentication failed')
    return db.query(Users).filter(Users.id == user.get('id')).first()


@router.put('/password', status_code=status.HTTP_204_NO_CONTENT)
async def update_password(user: user_dependency, db: db_dependency, password: UpdatePassword):
    if user is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND, detail='User not found')
    user_model = db.query(Users).filter(Users.id == user.get('id')).first()
    if not bcrypt_context.verify(password.password, user_model.hashed_password):
        raise HTTPException(status_code=404, detail='Password does not mathc')
    user_model.hashed_password = bcrypt_context.hash(password.new_password)
    db.add()
    db.commit()
