from pydantic import BaseModel
from datetime import datetime
from typing import Optional

class UserModel(BaseModel):
    google_id: Optional[str] = None
    user_email: str
    user_name: Optional[str] = None
    user_pic: Optional[str] = None
    auth_provider: str
    hashed_password: Optional[str] = None
    created_at: datetime
    updated_at: datetime