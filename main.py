from fastapi import FastAPI, Depends, HTTPException, status, Request, Cookie, Response
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from fastapi.responses import RedirectResponse, JSONResponse
from urllib.parse import urlencode
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, EmailStr, Field
from passlib.context import CryptContext
from fastapi.middleware.cors import CORSMiddleware
from jose import JWTError, jwt
from datetime import datetime, timedelta, timezone
from sqlalchemy import create_engine, Column, Integer, String, Boolean, text
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy.orm import sessionmaker, Session
from starlette.middleware.sessions import SessionMiddleware
import httpx
import time
import os
import logging
from authlib.integrations.starlette_client import OAuth, OAuthError
import secrets
from contextlib import asynccontextmanager


# temporary storage for refresh tokens, use redis in production
refresh_tokens = {}
# Logger setup
def setup_logger():
    logger = logging.getLogger("savvi-auth")
    logger.setLevel(logging.DEBUG)

    # Create console handler
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.DEBUG)

    # Create file handler
    file_handler = logging.FileHandler("savvi-auth.log")
    file_handler.setLevel(logging.DEBUG)

    # Create formatter
    formatter = logging.Formatter("%(asctime)s - %(name)s - %(levelname)s - %(message)s")
    console_handler.setFormatter(formatter)
    file_handler.setFormatter(formatter)

    # Add handlers to logger
    logger.addHandler(console_handler)
    logger.addHandler(file_handler)

    return logger

ENV = os.environ.get("ENV", "dev")

# Google OAuth setup
GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
GOOGLE_TOKEN_URL = "https://oauth2.googleapis.com/token"
GOOGLE_USERINFO_URL = "https://www.googleapis.com/oauth2/v2/userinfo"
GOOGLE_CLIENT_ID = os.environ.get("GOOGLE_CLIENT_ID", "dev")
GOOGLE_CLIENT_SECRET = os.environ.get("GOOGLE_CLIENT_SECRET", "dev")
GOOGLE_REDIRECT_URI = os.environ.get("GOOGLE_REDIRECT_URI", "dev")
if not GOOGLE_CLIENT_ID:
    raise ValueError("GOOGLE_CLIENT_ID is not set")
if not GOOGLE_CLIENT_SECRET:
    raise ValueError("GOOGLE_CLIENT_SECRET is not set")
if not GOOGLE_REDIRECT_URI:
    raise ValueError("GOOGLE_REDIRECT_URI is not set")
oauth = OAuth()
oauth.register(
    name='google',
    server_metadata_url='https://accounts.google.com/.well-known/openid-configuration',
    client_id=GOOGLE_CLIENT_ID,
    client_secret=GOOGLE_CLIENT_SECRET,
    client_kwargs={
        'scope': 'openid email profile',
    }
)

# Database setup
DB_USER = os.environ.get("DB_USER")
DB_PASSWORD = os.environ.get("DB_PASSWORD")
DB_NAME = os.environ.get("DB_NAME")
DATABASE_URL = f"postgresql://{DB_USER}:{DB_PASSWORD}@db:5432/{DB_NAME}"

engine = create_engine(DATABASE_URL)
SessionLocal = sessionmaker(autocommit=False, autoflush=False, bind=engine)
Base = declarative_base()

# Dependency to get DB session
def get_db():
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()

# Secret key for JWT (in production, use a proper secret management system)
SECRET_KEY = os.environ.get("SECRET_KEY", "dev")
if not SECRET_KEY:
    raise ValueError("SECRET_KEY is not set")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 30

# Password hashing
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

# OAuth2 scheme
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def lifespan(app: FastAPI):
    app.start_time = time.time()
    app.title = "Savvi-Auth"
    app.version = "0.0.1"
    app.logger = setup_logger()

    if ENV == "dev":
        app.logger.info("Seeding database...")
        seed_db(get_db())

    yield

app = FastAPI(lifespan=lifespan)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
app.add_middleware(
    SessionMiddleware,
    secret_key=SECRET_KEY,
)

# log request and response
@app.middleware("http")
async def log_request_and_response(request: Request, call_next):
    """
    Log request and response
    """
    ip = request.client.host
    app.logger.info(f"Request: {ip} {request.method} {request.url}")
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    app.logger.info(f"Response: {response.status_code} {process_time}")
    return response

# User model
class User(Base):
    __tablename__ = "users"

    id = Column(Integer, primary_key=True, index=True)
    email = Column(String, unique=True, index=True)
    first_name = Column(String)
    last_name = Column(String)
    hashed_password = Column(String)
    disabled = Column(Boolean, default=False)
    google_id = Column(String, unique=True, index=True, nullable=True)

# Pydantic models
class UserResponse(BaseModel):
    id: int
    email: EmailStr
    first_name: str
    last_name: str

    class Config:
        from_attributes = True

class UserRegistration(BaseModel):
    email: EmailStr
    first_name: str
    last_name: str
    password: str

    class Config:
        from_attributes = True

class Token(BaseModel):
    access_token: str
    token_type: str

class TokenData(BaseModel):
    # email: str | None = None
    email: str

def seed_db(db):
    # Delete tables
    Base.metadata.drop_all(bind=engine)
    # Create tables
    Base.metadata.create_all(bind=engine)

def create_access_token(data: dict):
    """
    Create access token
    """
    expires_delta = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + expires_delta
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)

def get_password_hash(password):
    return pwd_context.hash(password)

def get_user(db: Session, email: str):
    return db.query(User).filter(User.email == email).first()

def authenticate_user(db: Session, email: str, password: str):
    user = get_user(db, email)
    if not user or not verify_password(password, user.hashed_password):
        return False
    return user

async def get_current_user(token: str = Depends(oauth2_scheme), db: Session = Depends(get_db)):
    """
    Get current user
    """
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        email: str = payload.get("sub")
        if email is None:
            raise credentials_exception

        token_data = TokenData(email=email)
    except JWTError:
        raise credentials_exception
    user = get_user(db, email=token_data.email)
    if user is None:
        raise credentials_exception
    return user

async def get_current_active_user(current_user: User = Depends(get_current_user)):
    """
    Get current active user
    """
    if current_user.disabled:
        raise HTTPException(status_code=400, detail="Inactive user")
    return current_user

@app.get("/login/google")
async def login_google(request: Request):
    params = {
        "client_id": GOOGLE_CLIENT_ID,
        "response_type": "code",
        "scope": "openid email profile",
        "redirect_uri": GOOGLE_REDIRECT_URI,
        "access_type": "offline",
        "prompt": "consent",
    }
    url = f"{GOOGLE_AUTH_URL}?{urlencode(params)}"
    return RedirectResponse(url)

@app.get('/auth/google/callback')
async def auth_google_callback(request: Request, db: Session = Depends(get_db)):
    """
    Google OAuth callback
    """
    async with httpx.AsyncClient() as client:
        try:
            app.logger.info(f"Auth callback: {request.method} {request.url}")
            code = request.query_params.get('code')
            if not code:
                raise HTTPException(status_code=400, detail="Code not provided by Google")

            token_params = {
                'code': code,
                'grant_type': 'authorization_code',
                'redirect_uri': GOOGLE_REDIRECT_URI,
                'client_id': GOOGLE_CLIENT_ID,
                'client_secret': GOOGLE_CLIENT_SECRET,
            }
            token_response = await client.post(GOOGLE_TOKEN_URL, data=token_params)

            if token_response.status_code != 200:
                raise HTTPException(status_code=400, detail="Failed to get access token from Google")

            token_data = token_response.json()
            user_info_response = await client.get(GOOGLE_USERINFO_URL, headers={'Authorization': f'Bearer {token_data["access_token"]}'})

            # get user info
            user_info = user_info_response.json()
            email = user_info.get('email')
            if not email:
                raise HTTPException(status_code=400, detail="Email not provided by Google")

            db_user = get_user(db, email)
            if not db_user:
                # Create new user if not exists
                db_user = User(email=email, first_name=user_info.get('given_name', ''), last_name=user_info.get('family_name', ''), google_id=user_info.get('sub'))
                db.add(db_user)
                db.commit()
                db.refresh(db_user)

            # Create access token
            access_token = create_access_token(
                data={"sub": db_user.email}
            )

            return {"access_token": access_token, "token_type": "bearer"}
        except Exception as e:
            app.logger.error(f"Error in auth_google_callback: {e}")
            raise HTTPException(status_code=500, detail="Internal server error")

@app.post("/register", response_model=UserResponse)
async def register(user: UserRegistration, db: Session = Depends(get_db)):
    """
    Register a new user
    """
    db_user = get_user(db, email=user.email)
    if db_user:
        raise HTTPException(status_code=400, detail="Email already registered")
    hashed_password = get_password_hash(user.password)
    new_user = User(email=user.email, first_name=user.first_name, last_name=user.last_name, hashed_password=hashed_password)
    db.add(new_user)
    db.commit()
    db.refresh(new_user)
    return new_user

@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db: Session = Depends(get_db)):
    """
    Login for access token
    """
    user = authenticate_user(db, form_data.username, form_data.password)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect email or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token = create_access_token(
        data={"sub": user.email}
    )
    # generate refresh token
    refresh_token = secrets.token_urlsafe(32)
    refresh_tokens[user.email] = refresh_token
    response = JSONResponse(
        content={
            "access_token": access_token,
            "token_type": "bearer"
        }
    )
    response.set_cookie(
        key="refresh_token", 
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=60 * 60 * 24 * 1, # 1 day
    )
    return response

@app.post("/refresh")
async def refresh_token(
    request: Request,
    refresh_token: str = Cookie(None)
):
    """
    Refresh access token, for frontend only authentication
    """
    if refresh_token is None:
        raise HTTPException(status_code=401, detail="Refresh token not provided")
    user_email = None
    for email, token in refresh_tokens.items():
        if token == refresh_token:
            user_email = email
            break

    if user_email is None:
        raise HTTPException(status_code=401, detail="Invalid refresh token")

    new_access_token = create_access_token(
        data={"sub": user_email}
    )
    new_refresh_token = secrets.token_urlsafe(32)
    refresh_tokens[user_email] = new_refresh_token
    response = JSONResponse(
        content={
            "access_token": new_access_token,
            "token_type": "bearer"
        }
    )

    response.set_cookie(
        key="refresh_token", 
        value=refresh_token,
        httponly=True,
        secure=True,
        samesite="strict",
        max_age=60 * 60 * 24 * 1, # 1 day
    )
    return response

@app.get("/users/me", response_model=UserResponse)
async def read_users_me(current_user: User = Depends(get_current_active_user)):
    """
    Get current user
    """
    return current_user

@app.get("/health")
async def root():
    """
    Health check
    """
    return {
        "status": "healthy",
        "app_name": app.title,
        "version": app.version,
        "total_routes": len(app.routes),
        "uptime": time.time() - app.start_time
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
