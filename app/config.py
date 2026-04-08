"""
Configuration settings for User Service
"""

from pydantic_settings import BaseSettings
from typing import Optional


class Settings(BaseSettings):
    """Application settings"""
    
    # Database
    database_url: str = "postgresql://postgres:postgres@localhost:5432/user_db"
    
    # Redis
    redis_url: str = "redis://localhost:6379"
    
    # JWT
    jwt_secret: str = "your-secret-key-change-in-production"
    jwt_algorithm: str = "HS256"
    jwt_expiration_hours: int = 24
    
    # Logging
    log_level: str = "INFO"
    
    # Service URLs
    order_service_url: Optional[str] = None
    payment_service_url: Optional[str] = None

    class Config:
        env_file = ".env"


settings = Settings()
