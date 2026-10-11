from typing import List
from pydantic_settings import BaseSettings, SettingsConfigDict

class Settings(BaseSettings):
    PROJECT_NAME: str = "CloudShield"
    VERSION: str = "0.1.0"
    API_V1_STR: str = "/api/v1"
    SERVER_NAME: str = "backend-node"
    ENVIRONMENT: str = "development"
    
    # Database
    DATABASE_URL: str = "sqlite:///./cloudshield.db"
    
    # CORS
    BACKEND_CORS_ORIGINS: List[str] = [
        "http://localhost",
        "http://localhost:3000",
        "http://localhost:8080",
        "http://127.0.0.1:3000",
        "http://127.0.0.1:8080",
    ]

    model_config = SettingsConfigDict(
        case_sensitive=True,
        env_file=".env",
        extra="allow"
    )

settings = Settings()
