from pydantic import BaseModel
from datetime import datetime

class IssuedTokens(BaseModel):
    access_token: str
    user_email: str
    session_id: str
    created_at: datetime
    updated_at: datetime