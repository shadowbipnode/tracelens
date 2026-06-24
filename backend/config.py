from functools import lru_cache

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    db_path: str = ".tracelens/tracelens.sqlite3"
    http_timeout: float = 20.0
    user_agent: str = "TraceLens/0.3"
    shodan_api_key: str = Field(default="", validation_alias="SHODAN_API_KEY")
    censys_api_id: str = Field(default="", validation_alias="CENSYS_API_ID")
    censys_api_secret: str = Field(
        default="", validation_alias="CENSYS_API_SECRET"
    )
    securitytrails_api_key: str = Field(
        default="", validation_alias="SECURITYTRAILS_API_KEY"
    )
    hibp_api_key: str = Field(default="", validation_alias="HIBP_API_KEY")

    model_config = SettingsConfigDict(
        env_prefix="TRACELENS_",
        env_file=".env",
        extra="ignore",
    )


@lru_cache
def get_settings() -> Settings:
    return Settings()
