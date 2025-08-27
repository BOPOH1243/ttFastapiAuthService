from pydantic_settings import BaseSettings, SettingsConfigDict
from pydantic import Field

class Settings(BaseSettings):
    DATABASE_URL: str = Field(..., description="PostgreSQL connection URL")
    SECRET_KEY: str = Field(..., description="JWT secret key")
    ACCESS_TOKEN_EXPIRE_MINUTES: int = Field(150, description="Access token lifetime in minutes")
    REFRESH_TOKEN_EXPIRE_MINUTES: int = Field(10080, description="Refresh token lifetime in minutes")
    TEST_DATABASE_URL: str = "sqlite:///:memory:"

    model_config = SettingsConfigDict(env_file=".env", env_file_encoding="utf-8")

settings = Settings()
