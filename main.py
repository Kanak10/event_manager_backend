import os
from fastapi import FastAPI, Header, HTTPException, Depends, Request
from starlette.config import Config
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from apis import chatbot, authentication
import logging as logger
import time


from dotenv import load_dotenv
load_dotenv(override=True)

config = Config(".env")


expected_api_secret = os.getenv("FASTAPI_SECRET_KEY")

app = FastAPI()


app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # or specify allowed origins
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["*"]
)

app.add_middleware(
    SessionMiddleware,
    secret_key=config("SECRET_KEY"),
    same_site="lax",           # or "none" if frontend/backend are on different domains
    https_only=False
)

# Add Session middleware
# app.add_middleware(SessionMiddleware, secret_key=config("SECRET_KEY"))

# # Logging time taken for each api request
@app.middleware("http")
async def log_response_time(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    logger.info(f"Request: {request.url.path} completed in {process_time:.4f} seconds")
    return response 

app.include_router(chatbot.router, tags=["Chatbot"])
app.include_router(authentication.router, tags=["Authentication"])


















# from fastapi import FastAPI
# from starlette.middleware.sessions import SessionMiddleware
# from starlette.config import Config
# from authlib.integrations.starlette_client import OAuth
# from starlette.requests import Request
# import logging

# app = FastAPI()

# config = Config('.env')

# app.add_middleware(SessionMiddleware, secret_key=config('SECRET_KEY'))

# oauth = OAuth()

# google = oauth.register(
#     name='google',
#     client_id=config("GOOGLE_CLIENT_ID"),
#     client_secret=config("GOOGLE_CLIENT_SECRET"),
#     access_token_url=config("GOOGLE_ACCESS_TOKEN_URL"),
#     authorize_url=config("GOOGLE_AUTHORIZE_URL"),
#     api_base_url=config("GOOGLE_API_BASE_URL"),
#     userinfo_endpoint=config("GOOGLE_USERINFO_ENDPOINT"),
#     jwks_uri="https://www.googleapis.com/oauth2/v3/certs",
#     client_kwargs={'scope': 'openid email profile'}
# )

# @app.get("/login/{provider}")
# async def login(request: Request, provider: str):
#     if provider not in ['google', 'linkedin']:
#         return {"error": "Unsupport provider"}
    
#     oauth_provider = oauth.create_client(provider)

#     redirect_uri = config("REDIRECT_URI")
#     logging.debug(f"Redirect URI: {redirect_uri}")

#     print(f"redirect_uri:: {redirect_uri}")
#     print(f"request:: {request}")
#     return await oauth_provider.authorize_redirect(request, redirect_uri)

# @app.get("/auth/callback/{provider}")
# async def auth_callback(request: Request, provider: str):
#     # try:
#     print(f"provider:: {provider}")
#     print(f"request:: {request}")
#     if provider not in ['google', 'linkedin']:
#         return {"error": "Unsupport provider"}
    
#     oauth_provider = oauth.create_client(provider)
#     token = await oauth_provider.authorize_access_token(request)
#     user_info = (await oauth_provider.get("userinfo")).json()

#     # Store user in loacl store
#     print(f"token:: {token}")
#     print(f"oauth_provider:: {oauth_provider}")
#     print(f"user_info:: {user_info}")
#     return {"message": "User authentication successfully", "user_info": user_info}

#     # except Exception as e:
#     #     print(e)
