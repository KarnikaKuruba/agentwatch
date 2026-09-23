"""Optional live forwarder.

Tails data/agent_events.jsonl and, whenever a session finishes (a model_output
event), runs the detection engine on it and prints the result. Use this if you
want detection to run continuously against an agent in production, rather than
in the batch run_attacks.py flow.

  python3 forwarder.py
"""
import json
import time
from pathlib import Path

from agent.logger import init_log_tables
from agent.tools import BASE, init_db
from detection.engine import analyze

JSONL = BASE / "data" / "agent_events.jsonl"


def tail(path: Path):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.touch(exist_ok=True)
    with open(path) as f:
        f.seek(0, 2)  # start at end
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.5)
                continue
            yield line


def main():
    init_db()
    init_log_tables()
    print(f"Watching {JSONL} for finished agent sessions. Ctrl-C to stop.")
    for line in tail(JSONL):
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        meta = ev.get("agentwatch", {})
        if meta.get("type") == "model_output":
            sid = meta.get("session_id")
            result = analyze(sid, use_judge=False)
            alerts = result["alerts"]
            tag = "CLEAN" if not alerts else f"{len(alerts)} ALERT(S)"
            print(f"[{sid}] risk={result['risk_score']:3d} {tag}")
            for a in alerts:
                print(f"    {a['severity']:8} {a['atlas_id']:14} {a['title']}")


if __name__ == "__main__":
    main()
