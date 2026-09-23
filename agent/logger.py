"""Records every step an agent takes.

Events go to SQLite (for the API and dashboard) and to a JSON lines file,
which Wazuh can tail as a log source.
"""
import json
import sqlite3
import time
from pathlib import Path

from agent.tools import DB_PATH, BASE

JSONL_PATH = BASE / "data" / "agent_events.jsonl"


def init_log_tables():
    con = sqlite3.connect(DB_PATH)
    con.executescript(
        """
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY, started REAL, mode TEXT, user_input TEXT,
            final_output TEXT, attack_id TEXT, attack_category TEXT
        );
        CREATE TABLE IF NOT EXISTS events (
            id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, seq INTEGER, ts REAL,
            type TEXT, tool TEXT, trust TEXT, content TEXT, meta TEXT
        );
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, ts REAL, rule_id TEXT,
            title TEXT, severity TEXT, score INTEGER, atlas_id TEXT, atlas_name TEXT,
            evidence TEXT, layer TEXT
        );
        """
    )
    con.commit()
    con.close()


class SessionLogger:
    def __init__(self, session_id: str):
        self.session_id = session_id
        self.seq = 0
        self.events = []

    def log(self, type_: str, content: str, tool: str = "", trust: str = "trusted", meta: dict | None = None):
        self.seq += 1
        ev = {
            "session_id": self.session_id,
            "seq": self.seq,
            "ts": time.time(),
            "type": type_,
            "tool": tool,
            "trust": trust,
            "content": content,
            "meta": meta or {},
        }
        self.events.append(ev)
        con = sqlite3.connect(DB_PATH)
        con.execute(
            "INSERT INTO events (session_id, seq, ts, type, tool, trust, content, meta) VALUES (?,?,?,?,?,?,?,?)",
            (ev["session_id"], ev["seq"], ev["ts"], type_, tool, trust, content, json.dumps(ev["meta"])),
        )
        con.commit()
        con.close()
        JSONL_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(JSONL_PATH, "a") as f:
            f.write(json.dumps({"agentwatch": {k: v for k, v in ev.items() if k != "content"}, "content": content[:2000]}) + "\n")
        return ev
