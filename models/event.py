from pydantic import BaseModel
from typing import Optional
from datetime import datetime

class EventBase(BaseModel):
    title: str
    genre: str
    latitude: float
    longitude: float
    start_date: Optional[datetime] = None
    end_date: Optional[datetime] = None
    price: Optional[int] = 0
    description: Optional[str] = None


class EventCreate(EventBase):
    founder_id: int


class EventRead(EventBase):
    event_id: int
    founder_id: int
    created_at: datetime
    updated_at: Optional[datetime] = None

    class Config:
        from_attributes = True
