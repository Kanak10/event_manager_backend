from pydantic import BaseModel
from typing import List
from datetime import datetime
from typing import Optional
# from adress_model import AddressModel
# from event import Event

class UserModel(BaseModel):
    user_id: Optional[int] = None
    google_id: Optional[str] = None
    user_email: Optional[str] = None
    user_name: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    user_pic: Optional[str] = None
    auth_provider: Optional[str] = None
    hashed_password: Optional[str] = None
    # address: AddressModel | None
    # events: List[Event] | None
    created_at: Optional[datetime] = None
    updated_at: Optional[datetime] = None


    class Config:
        from_attributes = True