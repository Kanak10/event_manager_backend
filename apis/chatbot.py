from fastapi import Depends, APIRouter
from .authentication import get_current_user

router = APIRouter()

@router.get("/chat")
async def get_response(current_user: dict = Depends(get_current_user)):
    return {"message": "Welcome!", "user": current_user}
