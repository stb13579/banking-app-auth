from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from app.database import engine, Base
from app.routes import auth as auth_routes
from app.routes import mfa as mfa_routes
from app.routes import sessions as sessions_routes

app = FastAPI(
    title="Banking Auth Service",
    description="Authentication service — register, login, JWT issuance, MFA, session history",
    version="1.0.0",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(auth_routes.router, tags=["Auth"])
app.include_router(mfa_routes.router, prefix="/mfa", tags=["MFA"])
app.include_router(sessions_routes.router, tags=["Sessions"])


@app.on_event("startup")
def startup():
    Base.metadata.create_all(bind=engine)


@app.get("/health")
def health():
    return {"status": "ok", "service": "banking-app-auth"}
