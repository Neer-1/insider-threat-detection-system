# NEW — local on-disk queue for logs while offline, flushes via POST /logs on reconnect, mirrors the LogBuffer model

"""
The agent's own local offline queue — distinct from the server's LogBuffer
model (backend/models/buffer.py), which just records sync-event metadata
(a count and a timestamp), not log content. This is the actual holding
pen: real log payloads, stored on disk, until a confirmed successful
/logs/ingest call clears them. SQLite (stdlib, no extra dependency) rather
than a raw JSON file — crash-safe: a write either fully commits or
doesn't, so a process killed mid-write can't leave a corrupted queue
behind.
"""

import json
import sqlite3
from contextlib import contextmanager

from agent.config import BUFFER_DB_PATH


@contextmanager
def _connection():
    BUFFER_DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(BUFFER_DB_PATH)
    try:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS buffered_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                payload TEXT NOT NULL
            )
            """
        )
        yield conn
        conn.commit()
    finally:
        conn.close()


def enqueue(events: list) -> None:
    """Appends events to the local queue. Called both for freshly collected
    events and for events a failed send attempt falls back to — either
    way, nothing is dropped just because the server was unreachable at
    that moment."""
    if not events:
        return
    with _connection() as conn:
        conn.executemany(
            "INSERT INTO buffered_logs (payload) VALUES (?)",
            [(json.dumps(e),) for e in events],
        )


def peek_batch(limit: int = 200) -> list:
    """Returns up to `limit` queued (id, event) pairs without removing
    them — removal only happens after the server confirms receipt (see
    remove()), so a failed send leaves the queue untouched rather than
    losing events."""
    with _connection() as conn:
        rows = conn.execute(
            "SELECT id, payload FROM buffered_logs ORDER BY id ASC LIMIT ?", (limit,)
        ).fetchall()
    return [(row[0], json.loads(row[1])) for row in rows]


def remove(ids: list) -> None:
    if not ids:
        return
    with _connection() as conn:
        conn.executemany("DELETE FROM buffered_logs WHERE id = ?", [(i,) for i in ids])


def count() -> int:
    with _connection() as conn:
        return conn.execute("SELECT COUNT(*) FROM buffered_logs").fetchone()[0]
