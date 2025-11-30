from pydantic import BaseModel, EmailStr
from datetime import datetime
from typing import Optional, List
from models.address_model import AddressRead
from models.event import EventRead

class UserBase(BaseModel):
    user_name: Optional[str] = None
    first_name: Optional[str] = None
    last_name: Optional[str] = None
    user_pic: Optional[str] = None

class UserCreate(UserBase):
    email: EmailStr
    password: str

class UserRegistration(UserBase):
    user_id: str
    email: EmailStr

class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserUpdate(UserBase):
    first_name: Optional[str]
    last_name: Optional[str]

class UserRead(UserBase):
    user_id: int
    user_email: EmailStr
    address: Optional[AddressRead] = None
    events: Optional[List[EventRead]] = None
    created_at: datetime
    updated_at: Optional[datetime]

    class Config:
        from_attributes = True # lets Pydantic read from object attributes (like SQLAlchemy models) instead of only from plain dicts.
