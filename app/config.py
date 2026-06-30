import os
from dotenv import load_dotenv

load_dotenv()

ANTHROPIC_API_KEY: str = os.environ["ANTHROPIC_API_KEY"]
DATABASE_PATH: str = os.getenv("DATABASE_PATH", "dguard.db")
LOG_FULL_CONTENT: bool = os.getenv("LOG_FULL_CONTENT", "true").lower() == "true"
SERVER_API_KEY: str | None = os.getenv("SERVER_API_KEY")
