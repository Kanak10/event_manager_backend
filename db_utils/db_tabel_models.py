from sqlalchemy import (
    Column, Integer, String, Text, ForeignKey, Table, TIMESTAMP, func, Enum as SQLEnum
)
from sqlalchemy.orm import relationship, declarative_base
from enum import Enum

Base = declarative_base()

class UserRole(Enum):
    SPEAKER = "speaker"
    ORGANIZER = "organizer"
    SPONSOR = "sponsor"
    ATTENDEE = "attendee"

user_hobby_association = Table(
    "user_hobby_association",
    Base.metadata,
    Column("user_id", Integer, ForeignKey("users.user_id"), primary_key=True),
    Column("hobby_id", Integer, ForeignKey("hobby.hobby_id"), primary_key=True),
)

class User(Base):
    __tablename__ = "users"

    user_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    google_id = Column(String(255), unique=True, nullable=True)
    user_email = Column(String(255), unique=True, nullable=False)
    user_name = Column(String(255), nullable=True)
    first_name = Column(String(255), nullable=True)
    last_name = Column(String(255), nullable=True)
    user_pic = Column(Text, nullable=True)
    hashed_password = Column(Text, nullable=True)
    auth_provider = Column(String(50), nullable=False, default="email")
    role = Column(SQLEnum(UserRole), nullable=False, default=UserRole.ATTENDEE)
    created_at = Column(TIMESTAMP, server_default=func.now())
    updated_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())

    # Relationships
    address = relationship("Address", back_populates="user", uselist=False)
    events = relationship("Event", back_populates="user", cascade="all, delete-orphan")
    hobbies = relationship("Hobby", secondary=user_hobby_association, back_populates="users")


class IssuedToken(Base):
    __tablename__ = "issued_tokens"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    access_token = Column(String(512), nullable=False)
    user_email = Column(String(255), nullable=False)
    session_id = Column(String(255), nullable=False)
    created_at = Column(TIMESTAMP, server_default=func.now())
    updated_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())

class Address(Base):
    __tablename__ = "address"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    user_id = Column(Integer, ForeignKey("users.user_id"), nullable=False)
    street = Column(String(255), nullable=False)
    city = Column(String(100), nullable=False)
    state = Column(String(100), nullable=False)
    country = Column(String(100), nullable=False)
    pincode = Column(Integer, nullable=False)

    # Relationship back to User
    user = relationship("User", back_populates="address")


class Event(Base):
    __tablename__ = "events"

    id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(255), nullable=False)
    user_id = Column(Integer, ForeignKey("users.user_id"), nullable=False)

    # Relationship back to User
    user = relationship("User", back_populates="events")

class Hobby(Base):
    __tablename__ = "hobby"

    hobby_id = Column(Integer, primary_key=True, index=True, autoincrement=True)
    name = Column(String(100), nullable=False)
    created_at = Column(TIMESTAMP, server_default=func.now())
    updated_at = Column(TIMESTAMP, server_default=func.now(), onupdate=func.now())

    # Relationship back to User
    users = relationship("User", secondary=user_hobby_association, back_populates="hobbies")