from fastapi import HTTPException, Request, status, APIRouter, Depends
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy.orm import Session
from db_utils.database import get_db
from datetime import datetime
import db_utils.db_tabel_models as db_tabel_models
from models.user_model import UserRead, UserRegistration
from psycopg2 import Error

router = APIRouter()

@router.get('/users')
async def get_users(db: Session = Depends(get_db)):
    try:
        users = db.query(db_tabel_models.User).all()

        if not users:
            raise HTTPException(status_code=401, detail="User is not available")

        return [UserRead.model_validate(user, from_attributes=True) for user in users]
            
    except Error as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")

@router.post('/user/register')
async def register_user(request: Request, db: Session = Depends(get_db)):
    try:
        body = await request.json()
        print("RAW REQUEST BODY:", body)
        user_data = UserRegistration(**body)
        print("Parsed user_data:", user_data)
        
        user = db.query(db_tabel_models.User).filter(db_tabel_models.User.user_id == user_data.user_id).first()

        print(f"first name: {user_data.first_name}")
        print(f"last name: {user_data.last_name}")

        if user:
            print("user available")
            db.query(db_tabel_models.User).filter(db_tabel_models.User.user_id == user_data.user_id).update({
                db_tabel_models.User.first_name: user_data.first_name,
                db_tabel_models.User.last_name: user_data.last_name,
                db_tabel_models.User.updated_at: datetime.now()
            })
            db.commit()
            return "Updated Successfully"
        else:
            raise HTTPException(status_code=401, detail="User is not available")
        
    except Error as e:
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")