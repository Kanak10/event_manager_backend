from pydantic import BaseModel
from typing import List
from datetime import datetime
from typing import Optional
# from adress_model import AddressModel
# from event import Event

class UserModel(BaseModel):
    # user_id: str | None
    google_id: Optional[str] = None
    user_email: str
    user_name: Optional[str] = None
    # first_name: str | None
    # last_name: str | None
    user_pic: Optional[str] = None
    auth_provider: str
    hashed_password: Optional[str] = None
    # address: AddressModel | None
    # events: List[Event] | None
    created_at: datetime
    updated_at: datetime