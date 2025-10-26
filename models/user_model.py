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

    # def __init__(self, **kwargs):
    #     self.google_id = kwargs.get("google_id")
    #     self.user_email = kwargs.get("user_email")
    #     self.user_name = kwargs.get("user_name")
    #     self.user_pic = kwargs.get("user_pic")
    #     self.auth_provider = kwargs.get("auth_provider")
    #     self.hashed_password = kwargs.get("hashed_password")
    #     self.created_at = kwargs.get("created_at")
    #     self.updated_at = kwargs.get("updated_at")