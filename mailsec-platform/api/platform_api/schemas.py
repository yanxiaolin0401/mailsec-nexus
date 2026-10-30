from __future__ import annotations

from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Login(StrictModel):
    username: str = Field(min_length=1, max_length=80)
    password: str = Field(min_length=1, max_length=256)
    mode: Literal["user", "admin"]
    tenant_slug: str | None = Field(default=None, max_length=80)


class TenantCreate(StrictModel):
    name: str = Field(min_length=1, max_length=160)
    slug: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,79}$")


class UserCreate(StrictModel):
    username: str = Field(pattern=r"^[a-zA-Z0-9._-]{3,80}$")
    display_name: str = Field(min_length=1, max_length=160)
    password: str = Field(min_length=12, max_length=256)
    role: Literal["user", "admin"]
    tenant_id: int | None = None

    @model_validator(mode="after")
    def check_tenant(self):
        if (self.role == "user") != (self.tenant_id is not None):
            raise ValueError("user requires tenant_id; admin must not have one")
        return self


class UserPatch(StrictModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=160)
    password: str | None = Field(default=None, min_length=12, max_length=256)
    is_active: bool | None = None


class PasswordChange(StrictModel):
    current_password: str = Field(min_length=1, max_length=256)
    new_password: str = Field(min_length=12, max_length=256)


class MailSearch(StrictModel):
    q: str | None = Field(default=None, min_length=1, max_length=200)
    sender: str | None = Field(default=None, min_length=1, max_length=320)
    risk_level: Literal["unknown", "low", "medium", "high"] | None = None
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0, le=10000)
    tenant_id: int | None = None
