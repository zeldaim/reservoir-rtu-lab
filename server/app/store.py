"""저장 — SQLite. 사건 · 장치별 마지막 일련번호 · 보고서."""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path

SCHEMA = """
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  site_id TEXT NOT NULL, device_id TEXT NOT NULL, seq INTEGER NOT NULL,
  received_at REAL NOT NULL, device_t INTEGER, type TEXT NOT NULL, detail TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS ix_events_site_time ON events(site_id, received_at);
CREATE TABLE IF NOT EXISTS device_seq (device_id TEXT PRIMARY KEY, last_seq INTEGER NOT NULL);
CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT, site_id TEXT NOT NULL, created_at REAL NOT NULL,
  engine TEXT NOT NULL, report_json TEXT NOT NULL
);
"""

MAX_TYPE, MAX_DETAIL = 16, 64        # 장치 펌웨어의 Event 구조와 같은 크기 (넘치면 잘라서 저장)


class Store:
    def __init__(self, path: str | Path):
        self.db = sqlite3.connect(str(path), check_same_thread=False)
        self.db.executescript(SCHEMA)

    def last_seq(self) -> dict[str, int]:
        return dict(self.db.execute("SELECT device_id, last_seq FROM device_seq"))

    def add_events(self, site_id: str, device_id: str, seq: int, events: list[dict]) -> int:
        now = time.time()
        rows = [(site_id, device_id, seq, now, e.get("t"), str(e.get("type", ""))[:MAX_TYPE],
                 str(e.get("detail", ""))[:MAX_DETAIL]) for e in events]
        with self.db:                                   # 사건과 일련번호를 한 번에 (반만 저장되지 않게)
            self.db.executemany("INSERT INTO events(site_id, device_id, seq, received_at, device_t, type, detail)"
                                " VALUES (?,?,?,?,?,?,?)", rows)
            self.db.execute("INSERT INTO device_seq(device_id, last_seq) VALUES (?,?) "
                            "ON CONFLICT(device_id) DO UPDATE SET last_seq=excluded.last_seq", (device_id, seq))
        return len(rows)

    def events(self, site_id: str, since: float, limit: int = 500) -> list[dict]:
        cur = self.db.execute("SELECT received_at, device_id, device_t, type, detail FROM events "
                              "WHERE site_id=? AND received_at>=? ORDER BY received_at, id LIMIT ?",
                              (site_id, since, limit))
        return [{"received_at": r[0], "device_id": r[1], "device_t": r[2], "type": r[3], "detail": r[4]}
                for r in cur]

    def save_report(self, site_id: str, engine: str, report: dict) -> int:
        with self.db:
            cur = self.db.execute("INSERT INTO reports(site_id, created_at, engine, report_json) VALUES (?,?,?,?)",
                                  (site_id, time.time(), engine, json.dumps(report, ensure_ascii=False)))
        return cur.lastrowid

    def latest_report(self, site_id: str) -> dict | None:
        r = self.db.execute("SELECT created_at, engine, report_json FROM reports WHERE site_id=? "
                            "ORDER BY id DESC LIMIT 1", (site_id,)).fetchone()
        return None if r is None else {"created_at": r[0], "engine": r[1], **json.loads(r[2])}
