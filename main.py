from fastapi import FastAPI, status, Depends, HTTPException
import models
from database import engine, SessionLocal
from typing import Annotated
from sqlalchemy.orm import Session
import auth

app = FastAPI()

app.include_router(auth.router)

models.Base.metadata.create_all(bind=engine)

def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()
        
db_dependencies = Annotated[Session, Depends(get_db)]

@app.get('/', status_code=status.HTTP_200_OK)
async def user(db: db_dependencies):
    user = None  
    if user is None:
        raise HTTPException(status_code=401, detail='Authentication Failed')
    return {'User': user}


