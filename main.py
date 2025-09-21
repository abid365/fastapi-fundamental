from fastapi import FastAPI
import models
from models import Todos
from database import engine
from routers import auth, todos, admin, users


app = FastAPI(
    title="Todo CRUD with authentication and alembic data migration",
    description="This API was developed by Jawad Bin Azam aka abid365.",
    version="1.0.0",
    contact={
        "name": "Jawad Bin Azam",
        "url": "https://github.com/abid365",
        "email": "c241215@ugrad.iiuc.ac.bd"
    }
)

models.Base.metadata.create_all(bind=engine)

app.include_router(auth.router)
app.include_router(todos.router)
app.include_router(admin.router)
app.include_router(users.router)
