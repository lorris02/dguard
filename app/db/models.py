import sqlite3
from app.config import DATABASE_PATH


def get_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(DATABASE_PATH)
    conn.row_factory = sqlite3.Row  # rows behave like dicts
    return conn


def init_db() -> None:
    with get_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS requests (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp    TEXT    NOT NULL,
                user_id      TEXT,
                model        TEXT,
                prompt_text  TEXT,
                response_text TEXT,
                flagged      INTEGER NOT NULL DEFAULT 0,
                flag_reasons TEXT,
                blocked      INTEGER NOT NULL DEFAULT 0,
                status       TEXT
            )
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS agent_events (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp    TEXT    NOT NULL,
                device_id    TEXT,
                destination  TEXT,
                content      TEXT,
                flagged      INTEGER NOT NULL DEFAULT 0,
                flag_reasons TEXT,
                blocked      INTEGER NOT NULL DEFAULT 0
            )
        """)
        conn.commit()
