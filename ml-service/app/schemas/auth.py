from pydantic import BaseModel, EmailStr, field_validator

class RegisterRequest(BaseModel):
    email:    EmailStr
    password: str
    role:     str = "analyst"

    @field_validator('password')
    @classmethod
    def validate_complexity(cls, v: str) -> str:
        if len(v) < 8 or not any(c.isupper() for c in v) or not any(c.isdigit() for c in v):
            raise ValueError('Password debe tener min 8 chars, 1 mayuscula, 1 numero')
        return v


class LoginRequest(BaseModel):
    email:    EmailStr
    password: str


class TokenResponse(BaseModel):
    access_token:  str
    refresh_token: str
    token_type:    str = "bearer"


class RefreshRequest(BaseModel):
    refresh_token: str
