from fastapi import FastAPI, Depends, HTTPException, status, Request, Cookie, APIRouter, Header
from fastapi.responses import JSONResponse, RedirectResponse
from authlib.integrations.starlette_client import OAuth
from starlette.middleware.sessions import SessionMiddleware
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
from psycopg2 import Error

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

def create_access_token(data: dict, expires_delta: timedelta = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.now() + expires_delta
    else:
        expire = datetime.now() + timedelta(minutes=30)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)
    return encoded_jwt

@router.get("/login")
async def login(request: Request):
    request.session.clear()
    referer = request.headers.get("referer") # It tells you which page or URL triggered the request (useful for redirecting users back after login).
    FRONTEND_URL = os.getenv("FRONTEND_URL")
    redirect_url = os.getenv("REDIRECT_URL")
    request.session["login_redirect"] = FRONTEND_URL 
    # This line saves the frontend URL (where the user should go after login) into the session, so it can be retrieved later after Google authentication completes.

    return await oauth.auth_demo.authorize_redirect(request, redirect_url, prompt="consent")

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
    first_logged_in = datetime.now()
    last_accessed = datetime.now()

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
    log_user(user_id, user_email, user_name, user_pic, first_logged_in, last_accessed)
    # log_token(access_token, user_email, session_id)

    redirect_url = request.session.pop("login_redirect", FRONTEND_URL)
    # logger.info(f"Redirecting to: {redirect_url}")
    response = RedirectResponse(redirect_url)
    response.set_cookie(
        key="token",
        value=access_token,
        httponly=True,
        secure=True,  # Ensure you're using HTTPS
        samesite="strict",  # Set the SameSite attribute to None
    )

    return response

def log_user(user_id, user_email, user_name, user_pic, first_logged_in, last_accessed):
    try:
        conn = get_connection()
        if conn.closed == 0:
            cur = conn.cursor()

            # Create table if not exists
            cur.execute(UserQueries.create_user_table)

            # Check if products exist
            cur.execute(UserQueries.select_all_user, (user_email,))
            row = cur.fetchone()
            row_count = row['count'] if row else 0

            if row_count == 0:
                cur.execute(UserQueries.insert_user, (user_id, user_email, user_name, user_pic, first_logged_in, last_accessed))
                
            conn.commit()
    except Error as e:
        raise HTTPException(status_code=500, detail="Server Internal Error")
    finally:
        if conn.closed == 0:
            cur.close()
            conn.close()

# def log_token(access_token, user_email, session_id):
#     try:
#         connection = mysql.connector.connect(host=host, database=database, user=user, password=password)

#         if connection.is_connected():
#             cursor = connection.cursor()

#             # SQL query to insert data
#             sql_query = """INSERT INTO issued_tokens (token, email_id, session_id) VALUES (%s,%s,%s)"""
#             # Execute the SQL query
#             cursor.execute(sql_query, (access_token, user_email, session_id))

#             # Commit changes
#             connection.commit()

#     except Error as e:
#         print("Error while connecting to MySQL", e)
#     finally:
#         if connection.is_connected():
#             cursor.close()
#             connection.close()
#             logger.info("MySQL connection is closed")

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
