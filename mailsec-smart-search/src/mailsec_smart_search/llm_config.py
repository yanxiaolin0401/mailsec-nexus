"""Persistent, server-only model configuration for the search API."""
from __future__ import annotations

import json
import os
from dataclasses import replace
from threading import Lock
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

from .config import Settings

_ALLOWED_BASES = {
    'openai': frozenset({
        'https://api.deepseek.com',
        'https://dashscope.aliyuncs.com/compatible-mode/v1',
        'https://api.openai.com/v1',
    }),
    'anthropic': frozenset({'https://api.anthropic.com/v1'}),
}


class ModelConfiguration(BaseModel):
    model_config = ConfigDict(extra='forbid')
    provider: Literal['openai', 'anthropic']
    base_url: str = Field(min_length=1, max_length=250)
    model: str = Field(min_length=1, max_length=120, pattern=r'^[A-Za-z0-9._:/-]+$')
    api_key: str | None = Field(default=None, max_length=4096)
    external_authorized: bool

    @model_validator(mode='after')
    def validate_base(self):
        if self.base_url not in _ALLOWED_BASES[self.provider]:
            raise ValueError('unsupported official HTTPS model base URL')
        return self


class RuntimeSettings:
    """Stable reference seen by route closures; only model fields change."""

    def __init__(self, settings: Settings):
        self.current = settings
        self._lock = Lock()
        self.path = settings.data_dir / 'llm-config.json'
        if self.path.exists():
            if self.path.is_symlink():
                raise ValueError('model configuration path is a symlink')
            values = json.loads(self.path.read_text())
            model = ModelConfiguration.model_validate(values)
            self.current = self._updated(model)

    def __getattr__(self, name):
        return getattr(self.current, name)

    def _updated(self, model: ModelConfiguration) -> Settings:
        same_destination = (model.provider == self.current.llm_provider
                            and model.base_url == self.current.llm_base_url)
        key = (self.current.llm_api_key if same_destination else '') if model.api_key is None else model.api_key
        return replace(self.current, llm_provider=model.provider, llm_base_url=model.base_url,
                       llm_model=model.model, llm_api_key=key,
                       llm_external_authorized=model.external_authorized)

    def public(self) -> dict:
        settings = self.current
        key_set = bool(settings.llm_api_key)
        return {'provider': settings.llm_provider, 'base_url': settings.llm_base_url,
                'model': settings.llm_model, 'api_key_set': key_set,
                'external_authorized': settings.llm_external_authorized,
                'configured': bool(key_set and settings.llm_provider and settings.llm_base_url
                                   and settings.llm_model and settings.llm_external_authorized)}

    def update(self, model: ModelConfiguration) -> dict:
        with self._lock:
            next_settings = self._updated(model)
            self.path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
            value = model.model_dump(exclude={'api_key'})
            value['api_key'] = next_settings.llm_api_key
            temp = self.path.with_name(self.path.name + f'.{os.getpid()}.tmp')
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            fd = os.open(temp, flags, 0o600)
            try:
                with os.fdopen(fd, 'w') as file:
                    json.dump(value, file, ensure_ascii=False)
                    file.flush()
                    os.fsync(file.fileno())
                os.replace(temp, self.path)
            finally:
                temp.unlink(missing_ok=True)
            self.current = next_settings
            return self.public()
