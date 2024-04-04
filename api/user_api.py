# user_api.py
from fastapi import FastAPI, HTTPException, Depends, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
from bl.user_manager import UserManager


app = FastAPI()

# Instance of OAuth2PasswordBearer
oauth2_scheme = OAuth2PasswordBearer(tokenUrl="/login")

user_manager = UserManager()


class User(BaseModel):
    email: str | None = None
    password: str | None = None


@app.get("/users")
async def list_users():
    users = user_manager.list_users()
    print(users)
    return users


@app.post("/register", status_code=status.HTTP_201_CREATED)
async def register_user(user: User):
    user_id = user_manager.create_user(user.dict())
    return user_id


@app.post("/login")
async def login_user(form_data: OAuth2PasswordRequestForm = Depends()):
    token_info = user_manager.authenticate_user(form_data.username, form_data.password)
    if not token_info:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED)
    return token_info


@app.get("/users/profile")
async def get_user_profile(token: str = Depends(oauth2_scheme)):
    user_profile = user_manager.get_user_profile(token)
    return user_profile

# @app.put("/users/{user_id}/update")
# async def update_user(user_id: int, user: UserUpdate):
#     # Your logic to update a user's information
#     return user_manager.update_user(user_id, user)


# @app.delete("/users/{user_id}/delete", status_code=status.HTTP_204_NO_CONTENT)
# async def delete_user(user_id: int):
#     # Your logic to delete a user
#     user_manager.delete_user(user_id)
#     return {"message": "User deleted successfully"}

# @app.post("/users/logout")
# async def logout_user():
#     # Your logic for user logout
#     return user_manager.logout_user()
#
# #
# @app.post("/users/reset-password/request")
# async def request_password_reset(email: str = Body(...)):
#     # Your logic to request password reset
#     return user_manager.request_password_reset(email)
#
#
# @app.post("/users/reset-password")
# async def reset_password(token: str, new_password: str = Body(...)):
#     # Your logic to reset password
#     return user_manager.reset_password(token, new_password)

# Examples
# @app.post("/users/")
# def create_user(user: User):
#     user_id = user_manager.create_user(user.dict())
#     return {"user_id": user_id}
#
#
# @app.post("/users/login/")
# def user_login(user: User):
#     if user_manager.authenticate_user(user.email, user.password):
#         return {"message": "User authenticated"}
#     return {"message": "Invalid credentials"}, 401
