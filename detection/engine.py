"""Runs both detection layers on a session and stores the alerts."""
import json
import os
import sqlite3
import time
import urllib.request

from agent.tools import DB_PATH
from detection.atlas import name_of
from detection.judge import run_judge
from detection.rules import run_rules


def load_events(session_id: str):
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    rows = con.execute("SELECT * FROM events WHERE session_id=? ORDER BY seq", (session_id,)).fetchall()
    con.close()
    return [dict(r) for r in rows]


def risk_score(alerts) -> int:
    if not alerts:
        return 0
    top = max(a["score"] for a in alerts)
    return min(100, top + 3 * (len(alerts) - 1))


def forward_to_threatwatch(session_id, alerts):
    """Optional: push alerts into the ThreatWatch backend if THREATWATCH_URL is set."""
    url = os.getenv("THREATWATCH_URL")
    if not url or not alerts:
        return
    payload = json.dumps({"source": "agentwatch", "session_id": session_id, "alerts": alerts}).encode()
    req = urllib.request.Request(url.rstrip("/") + "/ingest", data=payload, headers={"Content-Type": "application/json"})
    try:
        urllib.request.urlopen(req, timeout=5)
    except Exception as e:  # noqa: BLE001
        print(f"ThreatWatch forward failed: {e}")


def analyze(session_id: str, use_judge: bool = True):
    events = load_events(session_id)
    alerts = run_rules(events)
    if use_judge:
        alerts += run_judge(events)
    now = time.time()
    con = sqlite3.connect(DB_PATH)
    con.execute("DELETE FROM alerts WHERE session_id=?", (session_id,))
    for a in alerts:
        a["atlas_name"] = name_of(a["atlas_id"])
        con.execute(
            "INSERT INTO alerts (session_id, ts, rule_id, title, severity, score, atlas_id, atlas_name, evidence, layer) VALUES (?,?,?,?,?,?,?,?,?,?)",
            (session_id, now, a["rule_id"], a["title"], a["severity"], a["score"], a["atlas_id"], a["atlas_name"], a["evidence"], a["layer"]),
        )
    con.commit()
    con.close()
    forward_to_threatwatch(session_id, alerts)
    return {"session_id": session_id, "risk_score": risk_score(alerts), "alerts": alerts}
