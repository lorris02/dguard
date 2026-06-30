from fastapi import Header, HTTPException

from app.config import SERVER_API_KEY


async def require_api_key(x_dguard_key: str | None = Header(default=None)) -> None:
    if not SERVER_API_KEY:
        return  # auth disabled when SERVER_API_KEY is not set
    if x_dguard_key != SERVER_API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing X-DGuard-Key header")
