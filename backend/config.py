from functools import lru_cache

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    db_path: str = ".tracelens/tracelens.sqlite3"
    http_timeout: float = 20.0
    user_agent: str = "TraceLens/0.1"

    model_config = SettingsConfigDict(
        env_prefix="TRACELENS_",
        env_file=".env",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
