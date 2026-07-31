from datetime import datetime
from typing import Optional

try:
    from pydantic import BaseModel, EmailStr
    HAS_PYDANTIC = True
except ImportError:
    HAS_PYDANTIC = False
    class BaseModel:
        pass
    EmailStr = str

if HAS_PYDANTIC:
    class UserCreate(BaseModel):
        email: EmailStr
        password: str

    class UserLogin(BaseModel):
        email: EmailStr
        password: str

    class UserResponse(BaseModel):
        id: int
        email: str
        created_at: Optional[datetime] = None

        class Config:
            from_attributes = True

    class Token(BaseModel):
        access_token: str
        token_type: str = "bearer"

    class TokenData(BaseModel):
        email: Optional[str] = None
        user_id: Optional[int] = None

    class EntryCreate(BaseModel):
        site_name: str
        site_username: str
        password: str

    class EntryUpdate(BaseModel):
        site_name: Optional[str] = None
        site_username: Optional[str] = None
        password: Optional[str] = None

    class EntryResponse(BaseModel):
        id: int
        site_name: str
        site_username: str
        masked_password: str = "••••••••"
        created_at: Optional[str] = None
        updated_at: Optional[str] = None

    class EntryDetailResponse(BaseModel):
        id: int
        site_name: str
        site_username: str
        password: str
        created_at: Optional[str] = None
        updated_at: Optional[str] = None
