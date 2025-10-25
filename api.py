from fastapi import FastAPI, Request
from starlette.config import Config
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.sessions import SessionMiddleware
from apis import authentication, chatbot
import time
import logging as logger

from dotenv import load_dotenv

load_dotenv(override=True) # It loads environment variables from your .env file into Python, and override=True makes these values replace any existing system environment variables.

config = Config(".env") # This line creates a Starlette Config object that reads the .env file, allowing you to access environment variables in a structured way, e.g., config("VAR_NAME").

app = FastAPI()

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"], # Allow requests from any domain.
    allow_credentials=True, # Allow sending cookies, auth headers, etc.
    allow_methods=["*"], # Allow all HTTP methods (GET, POST, etc.).
    allow_headers=["*"], # Allow all request headers.
    expose_headers=["*"] # Allow all response headers to be visible to the client.
) # Enables cross-origin requests so your frontend can access the API safely.

# Add Session middleware
app.add_middleware(SessionMiddleware, secret_key=config("SECRET_KEY")) # Enables storing and securing per-user session data (like login info) in your app.

# # Logging time taken for each api request
@app.middleware("http")
async def log_response_time(request: Request, call_next):
    start_time = time.time()
    response = await call_next(request)
    process_time = time.time() - start_time
    print(f"response: {response}")
    print(f"process_time: {process_time}")
    logger.info(f"Request: {request.url.path} completed in {process_time:.4f} seconds")
    return response

app.include_router(chatbot.router)
app.include_router(authentication.router)

if __name__ == "__main__":
    import uvicorn
    import nest_asyncio
    nest_asyncio.apply()
    uvicorn.run(app, host="0.0.0.0", port=8000)