from fastapi import APIRouter, HTTPException, Query

from app.db.models import get_connection

router = APIRouter()


def _row_to_dict(row) -> dict:
    return {
        "id": row["id"],
        "timestamp": row["timestamp"],
        "user_id": row["user_id"],
        "model": row["model"],
        "flagged": bool(row["flagged"]),
        "flag_reasons": row["flag_reasons"],
        "blocked": bool(row["blocked"]),
        "status": row["status"],
    }


@router.get("/logs")
def list_logs(
    limit: int = Query(default=50, le=500),
    flagged_only: bool = Query(default=False),
    blocked_only: bool = Query(default=False),
):
    query = "SELECT * FROM requests"
    conditions = []
    if flagged_only:
        conditions.append("flagged = 1")
    if blocked_only:
        conditions.append("blocked = 1")
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY id DESC LIMIT ?"

    with get_connection() as conn:
        rows = conn.execute(query, (limit,)).fetchall()

    return {"count": len(rows), "results": [_row_to_dict(r) for r in rows]}


@router.get("/logs/{log_id}")
def get_log(log_id: int):
    with get_connection() as conn:
        row = conn.execute(
            "SELECT * FROM requests WHERE id = ?", (log_id,)
        ).fetchone()

    if row is None:
        raise HTTPException(status_code=404, detail="Log entry not found")

    detail = dict(row)
    detail["flagged"] = bool(detail["flagged"])
    detail["blocked"] = bool(detail["blocked"])
    return detail
