# src/storage.py
import sqlite3
import json
import os
from datetime import datetime

class Storage:
    def __init__(self, db_path="iocs.db", out_dir="./out"):
        os.makedirs(out_dir, exist_ok=True)
        self.db_path = db_path
        self.out_dir = out_dir
        self._conn = sqlite3.connect(self.db_path, check_same_thread=False)
        self._ensure_tables()

    def _ensure_tables(self):
        cur = self._conn.cursor()
        cur.execute("""
        CREATE TABLE IF NOT EXISTS iocs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            raw TEXT,
            types TEXT,
            source TEXT,
            severity_score INTEGER,
            first_seen TEXT,
            added_at TEXT,
            meta_json TEXT,
            UNIQUE(raw, source)
        )
        """)
        self._conn.commit()

    def store_ioc(self, normalized):
        cur = self._conn.cursor()
        try:
            cur.execute("""
            INSERT INTO iocs (raw, types, source, severity_score, first_seen, added_at, meta_json)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (
                normalized["raw"],
                json.dumps(normalized["types"]),
                normalized.get("source"),
                normalized.get("severity_score", 0),
                normalized.get("first_seen"),
                datetime.utcnow().isoformat(),
                json.dumps(normalized.get("meta", {}))
            ))
            self._conn.commit()
            return True
        except sqlite3.IntegrityError:
            # already exists
            return False

    def export_json(self, filename=None):
        filename = filename or os.path.join(self.out_dir, f"iocs_{datetime.utcnow().strftime('%Y%m%dT%H%M%SZ')}.json")
        cur = self._conn.cursor()
        cur.execute("SELECT raw, types, source, severity_score, first_seen, added_at, meta_json FROM iocs")
        rows = cur.fetchall()
        out = []
        for r in rows:
            out.append({
                "raw": r[0],
                "types": json.loads(r[1]),
                "source": r[2],
                "severity_score": r[3],
                "first_seen": r[4],
                "added_at": r[5],
                "meta": json.loads(r[6] or "{}")
            })
        with open(filename, "w") as f:
            json.dump(out, f, indent=2)
        return filename
