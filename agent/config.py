import os
from dotenv import load_dotenv

load_dotenv(dotenv_path=os.path.join(os.path.dirname(__file__), ".env"))

DGUARD_SERVER: str = os.getenv("DGUARD_SERVER", "http://localhost:8000")
PROXY_PORT: int = int(os.getenv("PROXY_PORT", "8080"))
DEVICE_ID: str = os.getenv("DEVICE_ID", "unknown-device")
BLOCK_ENABLED: bool = os.getenv("BLOCK_ENABLED", "true").lower() == "true"
SERVER_API_KEY: str | None = os.getenv("SERVER_API_KEY")
