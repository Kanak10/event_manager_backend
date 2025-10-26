from fastapi import HTTPException, status, Request, Cookie, APIRouter, Header
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
from models.user_model import UserModel
from models.authorization_model import IssuedTokens
from passlib.context import CryptContext

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

@router.get("/login/{auth_provider}")
async def login(auth_provider: str, request: Request):
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
async def signup(email: str, password: str, user_name: str):
    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute(UserQueries.create_user_table)

        cur.execute(UserQueries.count_user, (email,))
        existing = cur.fetchone()
        if existing and existing["count"] > 0:
            raise HTTPException(status_code=400, detail="Email already registered.")
        

        cur.execute(UserQueries.find_user_with_user_name, (user_name.lower(),))
        existing_with_user_name = cur.fetchone()
        if existing_with_user_name and existing_with_user_name["count"] > 0:
            raise HTTPException(status_code=400, detail="User name already registered.")

        hashed_pw = hash_password(password)
        
        user_model = UserModel(
            google_id=None,
            user_email=email.strip().lower(),
            user_name=user_name.strip().lower(),
            user_pic=None,
            hashed_password=hashed_pw,
            auth_provider="email",
            created_at=datetime.now(),
            updated_at=datetime.now(),
        )

        cur.execute(UserQueries.insert_user, (
            user_model.google_id,
            user_model.user_email,
            user_model.user_name,
            user_model.user_pic,
            user_model.hashed_password,
            user_model.auth_provider,
            user_model.created_at,
            user_model.updated_at
        ))

        conn.commit()

        JSONResponse(content={"message": "User registered successfully."})
    except Error as e:
        raise HTTPException(status_code=500, detail="Database error")
    finally:
        cur.close()
        conn.close()

@router.get("/signin")
async def signin(email: str, password: str):
    try:
        conn = get_connection()
        cur = conn.cursor()

        cur.execute(UserQueries.fetch_user_for_signin, (email.strip().lower(),))
        existing = cur.fetchone()

        if existing and existing['user_email']:
            user_data = dict(existing)
            user = UserModel(**user_data)
            is_correct_password = verify_password(password, user.hashed_password)

            if is_correct_password:
                return JSONResponse(content={
                    "google_id": user.google_id,
                    "user_email": user.user_email,
                    "user_name": user.user_name,
                    "user_pic": user.user_pic ,
                    "auth_provider": user.auth_provider,
                    "created_at": user.created_at.isoformat(),
                    "updated_at": user.updated_at.isoformat()
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

@router.route("/auth")
async def auth(request: Request):
    state_in_request = request.query_params.get("state")

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

    # Create JWT token
    access_token_expires = timedelta(seconds=expires_in)
    access_token = create_access_token(data={"sub": user_id, "email": user_email}, expires_delta=access_token_expires)

    session_id = str(uuid.uuid4())
    is_new_user = log_user(UserModel(
        google_id=user_id,
        user_email=user_email.strip().lower(),
        user_name=user_name.strip().lower(),
        user_pic=user_pic,
        auth_provider="google",
        hashed_pw=None,
        created_at=created_at,
        updated_at=updated_at,
    ))
    if is_new_user:
        logger.info(f"New user signed up: {user_email}")
    else:
        logger.info(f"Existing user signed in: {user_email}")

    log_token(IssuedTokens(
        access_token=access_token,
        user_email=user_email,
        session_id=session_id
    ))

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

def log_user(user: UserModel):
    try:
        conn = get_connection()
        if conn.closed == 0:
            cur = conn.cursor()

            cur.execute(UserQueries.create_user_table)

            cur.execute(UserQueries.count_user, (user.user_email,))
            row = cur.fetchone()

            if row and row['count'] > 0:
                cur.execute(
                    UserQueries.update_updated_at_column,
                    (user.updated_at, user.user_email)
                )
                conn.commit()
                return False 
            else:
                cur.execute(
                    UserQueries.insert_user,
                    (user.user_id, user.google_id, user.user_email, user.user_name,
                     user.user_pic,  user.hashed_password, user.auth_provider, user.created_at, user.updated_at)
                )
                conn.commit()
                return True
    except Error as e:
        logger.error(f"Database operation failed: {e}")
        raise HTTPException(status_code=500, detail="Database operation failed")    
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        if conn.closed == 0:
            cur.close()
            conn.close()

def log_token(issued_token: IssuedTokens):
    try:
        conn = get_connection()

        if conn.closed == 0:
            cur = conn.cursor()

            cur.execute(AuthorizationQueries.create_issued_token_tabel)

            cur.execute(AuthorizationQueries.insert_in_issued_token_tabel, (issued_token.access_token, issued_token.user_email, issued_token.session_id))

            conn.commit()

    except Error as e:
        logger.error(f"Database operation failed: {e}")
        raise HTTPException(status_code=500, detail="Database operation failed")    
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        raise HTTPException(status_code=500, detail="Internal Server Error")
    finally:
        if conn.closed == 0:
            cur.close()
            conn.close()
            logger.info("Postgres connection is closed")

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
