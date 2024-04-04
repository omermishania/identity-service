# user_manager.py
from fastapi import HTTPException, status
from db.user_db import UserDB
from bson import ObjectId
import json
from passlib.context import CryptContext
from datetime import datetime, timedelta, timezone
from typing import Union, Any
from jose import jwt, JWTError
import uuid


# Set up the password hashing context
password_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ACCESS_TOKEN_EXPIRE_MINUTES = 30  # 30 minutes
ALGORITHM = "HS256"
JWT_SECRET_KEY = 'JWT_SECRET_KEY'   # should be kept secret


def verify_access_token(token: str) -> str:
    try:
        # Decode token. This will automatically verify the token's signature and expiration.
        decoded_token = jwt.decode(token, JWT_SECRET_KEY, algorithms=[ALGORITHM])

        user_id: str = decoded_token.get("sub")
        if not user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token missing subject.")

        return user_id
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token has expired.")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Could not validate credentials.")


def get_hashed_password(password: str) -> str:
    """Hash a password for storing."""
    return password_context.hash(password)


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verify a plain password against the hashed version."""
    return password_context.verify(plain_password, hashed_password)


def create_access_token(subject: Union[str, Any], expires_delta: int = None) -> str:
    if expires_delta is not None:
        expires_delta = datetime.utcnow() + expires_delta
    else:
        expires_delta = datetime.utcnow() + timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)

    to_encode = {"exp": expires_delta, "sub": str(subject)}
    encoded_jwt = jwt.encode(to_encode, JWT_SECRET_KEY, ALGORITHM)
    return encoded_jwt


class UserManager:
    def __init__(self):
        self.user_db = UserDB()

    def create_user(self, user_data):
        """Create a new user."""
        # querying database to check if user already exist
        user = self.user_db.find_user_by_email(user_data['email'])
        if user is not None:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="User with this email already exist"
            )
        user_data['_id'] = str(uuid.uuid4())
        user_data['password'] = get_hashed_password(user_data['password'])
        user_id = self.user_db.insert_user(user_data)
        return {"id": user_id}

    def authenticate_user(self, email, password):
        """Authenticate a user."""
        user = self.user_db.find_user_by_email(email)
        print(user)
        if user is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password"
            )
        hashed_pass = user['password']
        if not verify_password(password, hashed_pass):
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Incorrect email or password"
            )
        access_token = create_access_token(user['_id'])
        return {"access_token": access_token, "token_type": "bearer"}

    def list_users(self):
        """List all users."""
        users = self.user_db.list_users()
        # Directly convert ObjectId to string
        for user in users:
            user['_id'] = str(user['_id'])
        return users

    def get_user_profile(self, access_token):
        user_id = verify_access_token(access_token)
        user_profile = self.user_db.find_user_by_id(user_id)
        if not user_profile:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found.")

        return user_profile
