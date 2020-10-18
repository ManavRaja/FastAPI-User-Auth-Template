from datetime import timedelta, datetime
from typing import Optional

from fastapi import HTTPException, Depends, Header, Form, Cookie, APIRouter
from fastapi.openapi.models import OAuthFlows as OAuthFlowsModel
from fastapi.security import OAuth2, OAuth2PasswordRequestForm
from fastapi.security.utils import get_authorization_scheme_param
from jose import jwt, JWSError
from passlib.context import CryptContext
from starlette import status
from starlette.requests import Request
from starlette.responses import Response
from starlette.status import HTTP_401_UNAUTHORIZED

import app.config as config
# import config
from app.models import UserInDB, TokenData, User
# from models import UserInDB, TokenData, User
from app.utils import get_settings, get_db

#from utilsy import get_settings, get_db

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")
router = APIRouter()


class OAuth2PasswordBearerWithCookie(OAuth2):
    def __init__(
        self,
        tokenUrl: str,
        scheme_name: str = None,
        scopes: dict = None,
        auto_error: bool = True,
    ):
        if not scopes:
            scopes = {}
        flows = OAuthFlowsModel(
            password={"tokenUrl": tokenUrl, "scopes": scopes})
        super().__init__(flows=flows, scheme_name=scheme_name, auto_error=auto_error)

    async def __call__(self, request: Request) -> Optional[str]:
        authorization: str = request.cookies.get("access_token")

        scheme, param = get_authorization_scheme_param(authorization)
        if not authorization or scheme.lower() != "bearer":
            if self.auto_error:
                raise HTTPException(
                    status_code=HTTP_401_UNAUTHORIZED,
                    detail="Not authenticated",
                    headers={"WWW-Authenticate": "Bearer"},
                )
            else:
                return None

        return param


oauth2_scheme = OAuth2PasswordBearerWithCookie(tokenUrl="login")


async def verify_password(plain_password, hashed_password):
    return pwd_context.verify(plain_password, hashed_password)


async def get_password_hash(password):
    return pwd_context.hash(password)


async def get_user(username: str, db):
    user_dict = await db.Users.find_one({"username": username})
    if user_dict:
        return UserInDB(**user_dict)


async def authenticate_user(username: str, password: str, db):
    user = await get_user(username, db)
    if not user:
        return False
    if not await verify_password(password, user.hashed_password):
        return False
    return user


async def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    settings = get_settings()
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    encoded_jwt = jwt.encode(to_encode, settings.SECRET_KEY, algorithm=settings.ALGORITHM)
    return encoded_jwt


async def get_current_user(token: str = Depends(oauth2_scheme), settings: config.Settings = Depends(get_settings), db=Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, settings.SECRET_KEY, algorithms=[settings.ALGORITHM])
        username: str = payload.get("sub")
        if username is None:
            raise credentials_exception
        token_data = TokenData(username=username)
    except JWSError:
        raise credentials_exception
    user = await get_user(username=token_data.username, db=db)
    if user is None:
        raise credentials_exception
    return user


@router.post("/login")
async def login_for_access_token(response: Response, form_data: OAuth2PasswordRequestForm = Depends(), settings: config.Settings = Depends(get_settings), csrf_token: str = Header(...), db=Depends(get_db)):
    user = await authenticate_user(form_data.username, form_data.password, db)
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
    access_token_expires = timedelta(minutes=settings.ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = await create_access_token(
        data={"sub": user.username}, expires_delta=access_token_expires
    )  # .decode("utf-8")
    response.set_cookie(
        key="access_token", value=f"Bearer {access_token}", secure=False, httponly=True, samesite="strict", max_age=604800)
    return {"msg": "Successfully logged in."}


@router.post("/register")
async def register(csrf_token: str = Header(...), full_name: str = Form(..., max_length=50), username: str = Form(..., max_length=25), password: str = Form(...), email: str = Form(..., regex="^[a-z0-9]+[\._]?[a-z0-9]+[@]\w+[.]\w{2,3}$"), db=Depends(get_db)):
    hashed_password = await get_password_hash(password)
    await db.Users.insert_one({"full_name": full_name, "email": email, "username": username, "hashed_password": hashed_password})
    return "Successfully registered!"


@router.post("/logout")
async def logout(response: Response, csrf_token: str = Header(...), access_token: str = Cookie(...)):
    response.delete_cookie(key="access_token")
    return "Successfully logged out!"


@router.get("/me", response_model=User)
async def current_user(current_user_info: User = Depends(get_current_user)):
    return current_user_info
