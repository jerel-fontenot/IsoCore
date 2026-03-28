"""
IsoCore Configuration Manager (src/isocore/core/config.py)
----------------------------------------------------------
Loads variables from .env and ensures strict typing.
"""

from pydantic_settings import BaseSettings, SettingsConfigDict

class IsoConfig(BaseSettings):
    # If these are missing from the .env, Pydantic will use these defaults
    batch_size: int = 4
    max_wait_seconds: float = 1.0
    shutdown_timeout: float = 15.0

    # Storage with safe default
    db_path: str = "data/isocore.db"

    # Worker scaling
    # 0 means auto-detect based on CPU cores
    worker_count: int = 0

    # Tell Pydantic to look for variables starting with ISO_ in the .env file
    model_config = SettingsConfigDict(
        env_file=".env", 
        env_file_encoding="utf-8", 
        env_prefix="ISO_",
        extra="ignore"
    )

# Instantiate a global singleton we can import anywhere
settings = IsoConfig()