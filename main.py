"""AgentWatch API. Serves sessions and alerts to the dashboard and lets you
run an ad hoc prompt through the agent and detection engine.
"""
import sqlite3
from pathlib import Path

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse
from pydantic import BaseModel

from agent.agent import Agent
from agent.logger import init_log_tables
from agent.tools import DB_PATH, init_db
from detection.engine import analyze, risk_score

app = FastAPI(title="AgentWatch")
app.add_middleware(CORSMiddleware, allow_origins=["*"], allow_methods=["*"], allow_headers=["*"])


@app.on_event("startup")
def startup():
    init_db()
    init_log_tables()


def q(sql, args=()):
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    rows = [dict(r) for r in con.execute(sql, args).fetchall()]
    con.close()
    return rows


FRONTEND = Path(__file__).resolve().parent / "frontend" / "index.html"


@app.get("/", response_class=HTMLResponse)
def dashboard():
    """Serve the dashboard from the backend so one command runs the whole thing.
    The page auto-detects it's being served here and pulls live data from this API."""
    return FRONTEND.read_text()


@app.get("/health")
def health():
    return {"status": "ok"}


@app.get("/sessions")
def sessions():
    rows = q("SELECT * FROM sessions ORDER BY started DESC")
    for r in rows:
        alerts = q("SELECT severity, score, atlas_id, atlas_name FROM alerts WHERE session_id=?", (r["id"],))
        r["alert_count"] = len(alerts)
        r["risk_score"] = risk_score(alerts)
        r["max_severity"] = max((a["severity"] for a in alerts), key=lambda s: ["low", "medium", "high", "critical"].index(s), default="none")
    return rows


@app.get("/sessions/{sid}")
def session_detail(sid: str):
    s = q("SELECT * FROM sessions WHERE id=?", (sid,))
    return {
        "session": s[0] if s else None,
        "events": q("SELECT * FROM events WHERE session_id=? ORDER BY seq", (sid,)),
        "alerts": q("SELECT * FROM alerts WHERE session_id=? ORDER BY score DESC", (sid,)),
    }


@app.get("/alerts")
def alerts():
    return q("SELECT a.*, s.attack_category FROM alerts a JOIN sessions s ON s.id=a.session_id ORDER BY a.score DESC, a.ts DESC")


@app.get("/stats")
def stats():
    alerts = q("SELECT * FROM alerts")
    by_atlas, by_sev = {}, {}
    for a in alerts:
        by_atlas[a["atlas_name"]] = by_atlas.get(a["atlas_name"], 0) + 1
        by_sev[a["severity"]] = by_sev.get(a["severity"], 0) + 1
    sessions = q("SELECT id FROM sessions")
    flagged = q("SELECT DISTINCT session_id FROM alerts")
    return {
        "total_sessions": len(sessions),
        "flagged_sessions": len(flagged),
        "total_alerts": len(alerts),
        "by_atlas": by_atlas,
        "by_severity": by_sev,
    }


class RunReq(BaseModel):
    prompt: str
    judge: bool = False


@app.post("/run")
def run(req: RunReq):
    result = Agent().run(req.prompt)
    det = analyze(result["session_id"], use_judge=req.judge)
    return {"session_id": result["session_id"], "output": result["output"], **det}
