from fastapi import FastAPI

from app.routes.auth import router

app = FastAPI()
app.include_router(router, prefix="/auth")
