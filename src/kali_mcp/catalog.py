"""Indexed metadata; artifacts and portable JSON sidecars remain on disk."""

from __future__ import annotations

import json
import sqlite3
from contextlib import contextmanager
from pathlib import Path


class Catalog:
    def __init__(self, root: Path, response_bytes: int = 131072):
        self.root = root
        self.response_bytes = response_bytes
        self.path = root / "catalog.sqlite3"
        with self.connect() as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.executescript("""
                CREATE TABLE IF NOT EXISTS records (
                    kind TEXT NOT NULL, id TEXT NOT NULL, engagement TEXT NOT NULL,
                    status TEXT NOT NULL, severity TEXT NOT NULL, created TEXT NOT NULL,
                    payload TEXT NOT NULL, PRIMARY KEY(kind, id)
                );
                CREATE INDEX IF NOT EXISTS records_engagement
                    ON records(kind, engagement, created, id);
                CREATE INDEX IF NOT EXISTS records_status ON records(kind, status);
                CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            """)
            initialized = db.execute("SELECT value FROM metadata WHERE key='imported'").fetchone()
            runtime = db.execute(
                "SELECT value FROM metadata WHERE key='runtime_migrated'"
            ).fetchone()
            reporting = db.execute(
                "SELECT value FROM metadata WHERE key='reporting_migrated'"
            ).fetchone()
            if initialized is None or runtime is None or reporting is None:
                for kind, pattern in (
                    ("engagement", "*/engagement.json"),
                    ("job", "*/jobs/*/job.json"),
                    ("finding", "*/findings/*.json"),
                    ("note", "*/notes/*.json"),
                    ("step", "*/steps/*.json"),
                    ("summary", "*/summary.json"),
                ):
                    for path in (root / "engagements").glob(pattern):
                        data = json.loads(path.read_text(encoding="utf-8"))
                        if kind == "finding":
                            status = "confirmed" if data.get("verified") else "open"
                            data.setdefault("status", status)
                        eid = path.relative_to(root / "engagements").parts[0]
                        self._put(db, kind, data, eid)
                db.execute("INSERT OR REPLACE INTO metadata VALUES ('imported', '1')")
                db.execute("INSERT OR REPLACE INTO metadata VALUES ('runtime_migrated', '1')")
                db.execute("INSERT OR REPLACE INTO metadata VALUES ('reporting_migrated', '1')")

    @contextmanager
    def connect(self):
        connection = sqlite3.connect(self.path, timeout=10)
        try:
            with connection:
                yield connection
        finally:
            connection.close()

    @staticmethod
    def _put(db, kind: str, data: dict, engagement: str):
        db.execute(
            "INSERT OR REPLACE INTO records VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                kind,
                data["id"],
                engagement,
                data.get("status", ""),
                data.get("severity", ""),
                data.get("created_at", ""),
                json.dumps(data, ensure_ascii=False, separators=(",", ":")),
            ),
        )

    def put(self, kind: str, data: dict, engagement: str) -> None:
        with self.connect() as db:
            self._put(db, kind, data, engagement)

    def get(self, kind: str, identifier: str, engagement: str | None = None) -> dict | None:
        query = "SELECT payload FROM records WHERE kind=? AND id=?"
        parameters = [kind, identifier]
        if engagement is not None:
            query += " AND engagement=?"
            parameters.append(engagement)
        with self.connect() as db:
            row = db.execute(query, parameters).fetchone()
        return json.loads(row[0]) if row else None

    def page(
        self,
        kind: str,
        engagement: str | None = None,
        offset: int = 0,
        limit: int = 100,
        status: str | None = None,
        severity: str | None = None,
        exclude: tuple[str, ...] = (),
    ) -> dict:
        if offset < 0 or not 1 <= limit <= 500:
            raise ValueError("offset >= 0; limit must be 1..500")
        clauses, parameters = ["kind=?"], [kind]
        for column, value in (
            ("engagement", engagement),
            ("status", status),
            ("severity", severity),
        ):
            if value is not None:
                clauses.append(f"{column}=?")
                parameters.append(value)
        where = " AND ".join(clauses)
        with self.connect() as db:
            total = db.execute(
                f"SELECT count(*) FROM records WHERE {where}", parameters
            ).fetchone()[0]
            rows = db.execute(
                f"SELECT payload FROM records WHERE {where} ORDER BY created,id LIMIT ? OFFSET ?",
                [*parameters, limit, offset],
            )
            entries, used = [], 0
            for row in rows:
                data = json.loads(row[0])
                for key in exclude:
                    data.pop(key, None)
                size = len(json.dumps(data, ensure_ascii=False).encode("utf-8")) + 2
                if size > self.response_bytes - 1024:
                    raise ValueError(
                        "Record exceeds response budget; use compact lists "
                        "or read its JSON artifact"
                    )
                if used + size > self.response_bytes - 1024:
                    break
                entries.append(data)
                used += size
        return {"items": entries, "total": total, "next_offset": min(offset + len(entries), total)}

    def all(self, kind: str, engagement: str | None = None) -> list[dict]:
        where = "kind=?" + (" AND engagement=?" if engagement is not None else "")
        parameters = [kind] + ([engagement] if engagement is not None else [])
        with self.connect() as db:
            rows = db.execute(
                f"SELECT payload FROM records WHERE {where} ORDER BY created,id", parameters
            ).fetchall()
        return [json.loads(row[0]) for row in rows]

    def unfinished_jobs(self) -> list[dict]:
        with self.connect() as db:
            rows = db.execute(
                "SELECT payload,engagement FROM records "
                "WHERE kind='job' AND status IN ('queued','running')"
            ).fetchall()
        return [{**json.loads(row[0]), "engagement_id": row[1]} for row in rows]

    def counts(self, kind: str, engagement: str, column: str = "status") -> dict:
        if column not in {"status", "severity"}:
            raise ValueError("Unsupported grouping")
        with self.connect() as db:
            rows = db.execute(
                f"SELECT {column},count(*) FROM records "
                "WHERE kind=? AND engagement=? GROUP BY " + column,
                (kind, engagement),
            ).fetchall()
        return dict(rows)
