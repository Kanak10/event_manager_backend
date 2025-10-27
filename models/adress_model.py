from pydantic import BaseModel

class AddressModel(BaseModel):
    user_id: str
    street: str
    city: str
    state: str
    country: str
    pincode: int