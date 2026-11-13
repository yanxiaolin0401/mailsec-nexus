from __future__ import annotations

from typing import Literal

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator


class StrictModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class Login(StrictModel):
    username: str = Field(min_length=1, max_length=80)
    password: str
    mode: Literal["user", "admin"]
    tenant_slug: str | None = Field(default=None, max_length=80)


class Registration(StrictModel):
    username: str = Field(pattern=r"^[a-zA-Z0-9._-]{3,80}$")
    display_name: str = Field(min_length=1, max_length=160)
    password: str
    tenant_slug: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,79}$")


class TenantCreate(StrictModel):
    name: str = Field(min_length=1, max_length=160)
    slug: str = Field(pattern=r"^[a-z0-9][a-z0-9-]{1,79}$")


class UserCreate(StrictModel):
    username: str = Field(pattern=r"^[a-zA-Z0-9._-]{3,80}$")
    display_name: str = Field(min_length=1, max_length=160)
    password: str
    role: Literal["user", "admin"]
    tenant_id: int | None = None

    @model_validator(mode="after")
    def check_tenant(self):
        if (self.role == "user") != (self.tenant_id is not None):
            raise ValueError("user requires tenant_id; admin must not have one")
        return self


class UserPatch(StrictModel):
    display_name: str | None = Field(default=None, min_length=1, max_length=160)
    password: str | None = None
    is_active: bool | None = None


class PasswordChange(StrictModel):
    current_password: str
    new_password: str


class MailSearch(StrictModel):
    source: Literal["event", "legacy"] = "event"
    from_time: AwareDatetime | None = None
    to_time: AwareDatetime | None = None
    q: str | None = Field(default=None, min_length=1, max_length=200)
    sender: str | None = Field(default=None, min_length=1, max_length=320)
    sender_domain: str | None = Field(default=None, min_length=1, max_length=255)
    recipient: str | None = Field(default=None, min_length=1, max_length=320)
    subject: str | None = Field(default=None, min_length=1, max_length=200)
    has_attachment: bool | None = None
    attachment_suffix: str | None = Field(default=None, min_length=1, max_length=32)
    sender_ip: str | None = Field(default=None, max_length=45)
    attachment_md5: str | None = Field(default=None, pattern=r"^[0-9a-fA-F]{32}$")
    risk_verdict: Literal["unknown", "pass", "alert", "reject"] | None = None
    subject_or_attachment_contains: str | None = Field(default=None, min_length=1, max_length=200)
    attachment_name_contains: str | None = Field(default=None, min_length=1, max_length=200)
    source_system_id: str | None = Field(default=None, min_length=1, max_length=256)
    risk_level: Literal["unknown", "low", "medium", "high"] | None = None
    limit: int = Field(default=50, ge=1, le=200)
    offset: int = Field(default=0, ge=0, le=10000)
    tenant_id: int | None = None

    @model_validator(mode="after")
    def check_source_filters(self) -> MailSearch:
        if self.from_time and self.to_time and self.from_time > self.to_time:
            raise ValueError("invalid time range")
        if self.source == "legacy" and any(getattr(self, key) is not None for key in (
            "risk_level", "sender_ip", "attachment_md5", "risk_verdict", "subject_or_attachment_contains",
            "attachment_name_contains", "source_system_id")):
            raise ValueError("event-only filters are unavailable for legacy mail")
        return self


class NaturalPlan(StrictModel):
    source: Literal["event", "legacy"]
    text: str = Field(min_length=1, max_length=2000)
    tenant_id: int | None = None


class PlanExecute(StrictModel):
    plan_token: str = Field(min_length=40, max_length=8192)
    source: Literal["event", "legacy"]
    tenant_id: int | None = None
    limit: int | None = Field(default=None, ge=1, le=200)
    offset: int | None = Field(default=None, ge=0, le=10000)


class LlmConfigUpdate(StrictModel):
    provider: Literal["openai", "anthropic"]
    base_url: str = Field(min_length=1, max_length=500)
    model: str = Field(min_length=1, max_length=120)
    api_key: str | None = None
    external_authorized: bool = False
