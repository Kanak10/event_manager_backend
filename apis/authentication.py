from fastapi import HTTPException, status, Request, Cookie, APIRouter, Header, Depends
from fastapi.responses import JSONResponse, RedirectResponse
from authlib.integrations.starlette_client import OAuth
from datetime import datetime, timedelta
from jose import jwt, ExpiredSignatureError, JWTError
from dotenv import load_dotenv
import os
import uuid
import traceback
import logging as logger
import requests
from db_utils.database import get_connection
from queries.user_queries.user_queries import UserQueries
from queries.authorization.authorization_queries import AuthorizationQueries
from psycopg2 import Error
from models.authorization_model import IssuedTokens
from passlib.context import CryptContext
from db_utils.database import session, engine, get_db
from sqlalchemy.orm import Session
import db_utils.db_tabel_models as db_tabel_models
from sqlalchemy.exc import SQLAlchemyError

db_tabel_models.Base.metadata.create_all(bind=engine)

load_dotenv(override=True)

router = APIRouter()

# Setup OAuth2
oauth = OAuth()
oauth.register(
    name="auth_demo",
    client_id=os.getenv("GOOGLE_CLIENT_ID"),
    client_secret=os.getenv("GOOGLE_CLIENT_SECRET"),
    authorize_url="https://accounts.google.com/o/oauth2/auth",
    authorize_params=None,
    access_token_url="https://accounts.google.com/o/oauth2/token",
    access_token_params=None,
    refresh_token_url=None,
    authorize_state=os.getenv("SECRET_KEY"),
    redirect_uri=os.getenv("REDIRECT_URL"),
    jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
    client_kwargs={"scope": "openid profile email"},
)

# Secret key used to encode JWT tokens (should be kept secret)
SECRET_KEY = os.getenv("JWT_SECRET_KEY")
ALGORITHM = "HS256"
REDIRECT_URL = os.getenv("REDIRECT_URL")
FRONTEND_URL = os.getenv("FRONTEND_URL")
pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now() + expires_delta
    else:
        expire = datetime.now() + timedelta(minutes=30)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@router.get("/login/")
async def login(request: Request):
    request.session.clear()
    referer = request.headers.get("referer") # It tells you which page or URL triggered the request (useful for redirecting users back after login).
    FRONTEND_URL = os.getenv("FRONTEND_URL")
    redirect_url = os.getenv("REDIRECT_URL")
    request.session["login_redirect"] = FRONTEND_URL 
    # This line saves the frontend URL (where the user should go after login) into the session, so it can be retrieved later after Google authentication completes.

    return await oauth.auth_demo.authorize_redirect(request, redirect_url, prompt="consent")

def hash_password(password: str) -> str:
    return pwd_context.hash(password)

def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)

@router.get("/signup")
async def signup(email: str, password: str, user_name: str, db: Session = Depends(get_db)):
    try:
        existing_user = db.query(db_tabel_models.User).filter(db_tabel_models.User.user_email == email).first()
        
        if existing_user:
            raise HTTPException(status_code=400, detail="Email already registered.")
        
        existing_user_for_user_name = db.query(db_tabel_models.User).filter(db_tabel_models.User.user_name == user_name).first()

        if existing_user_for_user_name:
            raise HTTPException(status_code=400, detail="User name already registered.")

        hashed_pw = hash_password(password)
        
        user = db_tabel_models.User(
            user_email=email.strip().lower(),
            user_name=user_name.strip().lower(),
            hashed_password=hashed_pw,
            auth_provider="email",
            created_at=datetime.now(),
            updated_at=datetime.now(),
        )

        db.add(user)
        db.commit()

        return JSONResponse(content={
            "user_email": user.user_email,
            "user_name": user.user_name,
            "auth_provider": user.auth_provider,
            "created_at": user.created_at.isoformat(),
            "updated_at": user.updated_at.isoformat()
        })
    except Error as e:
        raise HTTPException(status_code=500, detail="Database error")

@router.get("/signin")
async def signin(email: str, password: str, db: Session = Depends(get_db)):
    try:
        existing_user = db.query(db_tabel_models.User).filter(db_tabel_models.User.user_email == email).first()

        if existing_user:
            is_correct_password = verify_password(password, existing_user.hashed_password)

            if is_correct_password:
                return JSONResponse(content={
                    "google_id": existing_user.google_id,
                    "user_email": existing_user.user_email,
                    "user_name": existing_user.user_name,
                    "user_pic": existing_user.user_pic ,
                    "auth_provider": existing_user.auth_provider,
                    "created_at": existing_user.created_at.isoformat(),
                    "updated_at": existing_user.updated_at.isoformat()
                })
            else:
                return HTTPException(status_code=401, detail="Invalid password")
        else:
            return HTTPException(status_code=400, detail="Invalid email")
    except Error as e:
        return HTTPException(status_code=500, detail="Database error")

@router.get("/logout")
async def logout(request: Request):
    request.session.clear()
    response = JSONResponse(content={"message": "Logged out successfully."})
    response.delete_cookie("token")
    return response

@router.get("/auth")
async def auth(request: Request, db: Session = Depends(get_db)):
    try:
        token = await oauth.auth_demo.authorize_access_token(request)
    except Exception as e:
        logger.info(str(e))
        raise HTTPException(status_code=401, detail="Google authentication failed.")

    try:
        user_info_endpoint = "https://www.googleapis.com/oauth2/v2/userinfo" # Sets the Google API URL to fetch the user’s profile info (email, name, picture, etc.).
        headers = {"Authorization": f'Bearer {token["access_token"]}'} # Prepares the Authorization header with the access token you got from Google so the API knows who’s asking.
        google_response = requests.get(user_info_endpoint, headers=headers) # Makes a GET request to Google’s API to retrieve the user’s profile data.
        user_info = google_response.json()
    except Exception as e:
        logger.info(str(e))
        raise HTTPException(status_code=401, detail="Google authentication failed.")

    user = token.get("userinfo")
    expires_in = token.get("expires_in")
    user_id = user.get("sub")
    iss = user.get("iss")
    user_email = user.get("email")
    created_at = datetime.now()
    updated_at = datetime.now()

    user_name = user_info.get("name")
    user_pic = user_info.get("picture")

    logger.info(f"User name:{user_name}")
    logger.info(f"User Email:{user_email}")

    if iss not in ["https://accounts.google.com", "accounts.google.com"]:
        raise HTTPException(status_code=401, detail="Google authentication failed.")

    if user_id is None:
        raise HTTPException(status_code=401, detail="Google authentication failed.")

    access_token_expires = timedelta(seconds=expires_in)
    access_token = create_access_token(data={"sub": user_id, "email": user_email}, expires_delta=access_token_expires)

    session_id = str(uuid.uuid4())    
    is_new_user = log_user(db=db, **{
        "google_id": user_id,
        "user_email": user_email.strip().lower(),
        "user_name": user_name.strip().lower(),
        "user_pic": user_pic,
        "auth_provider": "google",
        "hashed_password": None,
        "created_at": created_at,
        'updated_at': updated_at
    })
    if is_new_user:
        logger.info(f"New user signed up: {user_email}")
    else:
        logger.info(f"Existing user signed in: {user_email}")

    log_token(db=db, **{
        "access_token": access_token,
        "user_email": user_email.strip().lower(),
        "session_id": session_id,
        "created_at": created_at,
        'updated_at': updated_at
    })

    redirect_url = request.session.pop("login_redirect", FRONTEND_URL)
    logger.info(f"Redirecting to: {redirect_url}")
    response = RedirectResponse(redirect_url)
    response.set_cookie(
        key="token",
        value=access_token,
        httponly=True,
        secure=True,  # Ensure you're using HTTPS
        samesite="strict",  # Set the SameSite attribute to None
    )

    return response

def log_user(db: Session, **kwargs):
    try:
        existing_user = (
            db.query(db_tabel_models.User)
            .filter(db_tabel_models.User.user_email == kwargs["user_email"])
            .first()
        )

        if existing_user:
            existing_user.updated_at = datetime.now()
            db.commit()
            return False
        
        new_user = db_tabel_models.User(
            google_id=kwargs["google_id"],
            user_email=kwargs["user_email"],
            user_name=kwargs["user_name"],  
            user_pic=kwargs["user_pic"],
            hashed_password=kwargs["hashed_password"],
            auth_provider=kwargs["auth_provider"] or "email",
            role = db_tabel_models.UserRole.ATTENDEE,
            created_at=kwargs["created_at"],
            updated_at=kwargs["updated_at"]
        )

        db.add(new_user)
        db.commit()
        db.refresh(new_user)
        return True
    except SQLAlchemyError as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {e}")

def log_token(db: Session, **kwargs):
    try:
        existing_token = (
            db.query(db_tabel_models.IssuedToken)
            .filter(db_tabel_models.IssuedToken.user_email == kwargs["user_email"])
            .first()
        )
        if existing_token:
            existing_token.access_token = kwargs["access_token"]
            existing_token.session_id = kwargs["session_id"]
            existing_token.updated_at = datetime.now()
            db.commit()
            return
        
        new_issued_token = db_tabel_models.IssuedToken(
            access_token=kwargs["access_token"],
            user_email=kwargs["user_email"],
            session_id=kwargs["session_id"],
            created_at=kwargs["created_at"],
            updated_at=kwargs["updated_at"]
        )

        db.add(new_issued_token)
        db.commit()
        db.refresh(new_issued_token)
    except SQLAlchemyError as e:
        db.rollback()
        raise HTTPException(status_code=500, detail=f"Database error: {e}")
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Unexpected error: {e}")

        # conn = get_connection()

        # if conn.closed == 0:
        #     cur = conn.cursor()

        #     cur.execute(AuthorizationQueries.create_issued_token_tabel)

        #     cur.execute(AuthorizationQueries.insert_in_issued_token_tabel, (issued_token.access_token, issued_token.user_email, issued_token.session_id))

        #     conn.commit()

    # except Error as e:
    #     logger.error(f"Database operation failed: {e}")
    #     raise HTTPException(status_code=500, detail="Database operation failed")    
    # except Exception as e:
    #     logger.error(f"Unexpected error: {e}")
    #     raise HTTPException(status_code=500, detail="Internal Server Error")
    # finally:
    #     if conn.closed == 0:
    #         cur.close()
    #         conn.close()
    #         logger.info("Postgres connection is closed")

def get_current_user(authorization: str = Header(None)):
    if not authorization or not authorization.startswith("Bearer "):
        raise HTTPException(status_code=401, detail="Not authenticated")

    token = authorization.split(" ")[1]  # extract the token
    
    credentials_exception = HTTPException(
        status_code=401,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])

        user_id: str = payload.get("sub")
        user_email: str = payload.get("email")

        if user_id is None or user_email is None:
            raise credentials_exception

        return {"user_id": user_id, "user_email": user_email}

    except ExpiredSignatureError:
        # Specifically handle expired tokens
        traceback.print_exc()
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Session expired. Please login again.")
    except JWTError:
        # Handle other JWT-related errors
        traceback.print_exc()
        raise credentials_exception
    except Exception as e:
        traceback.print_exc()
        raise HTTPException(status_code=401, detail="Not Authenticated")

def validate_user_request(token: str = Cookie(None)):
    session_details = get_current_user(token)

    return session_details
