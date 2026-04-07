"""
API Key authentication for all SAPTARA services
"""

import os
import secrets
from fastapi import Security, HTTPException, status
from fastapi.security import APIKeyHeader

API_KEY_HEADER = APIKeyHeader(name="X-API-Key", auto_error=False)

# Load from env; fall back to a default dev key so services start without config
_RAW = os.getenv("API_KEYS", "saptara-dev-key-change-me")
VALID_API_KEYS: set[str] = {k.strip() for k in _RAW.split(",") if k.strip()}


def verify_api_key(api_key: str = Security(API_KEY_HEADER)) -> str:
    """
    Dependency that validates the X-API-Key header.
    Raises 401 if missing or invalid.
    """
    if not api_key or api_key not in VALID_API_KEYS:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key",
            headers={"WWW-Authenticate": "ApiKey"},
        )
    return api_key
