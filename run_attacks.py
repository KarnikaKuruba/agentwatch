"""Run the attack suite, score detection, and print a metrics report.

  python run_attacks.py            # simulated agent, rules only (no API key needed)
  python run_attacks.py --judge    # also run the LLM judge (needs OPENAI_API_KEY)
  AGENT_MODE=openai python run_attacks.py --judge   # real LLM agent end to end
"""
import argparse
import json
import sqlite3
import sys
from collections import defaultdict

from agent.agent import Agent
from agent.logger import init_log_tables
from agent.tools import DB_PATH, init_db
from attacks.cases import ATTACKS
from detection.engine import analyze


def reset_db():
    init_db()
    init_log_tables()
    con = sqlite3.connect(DB_PATH)
    for t in ("sessions", "events", "alerts", "outbox"):
        con.execute(f"DELETE FROM {t}")
    con.commit()
    con.close()


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--judge", action="store_true", help="also run the LLM judge layer")
    args = ap.parse_args()

    reset_db()
    agent = Agent()
    print(f"Agent mode: {agent.mode} | judge: {args.judge}\n")

    results = []
    for case in ATTACKS:
        run = agent.run(case["prompt"], attack_id=case["id"], category=case["category"])
        det = analyze(run["session_id"], use_judge=args.judge)
        detected = det["risk_score"] > 0
        results.append({**case, "session_id": run["session_id"], "risk_score": det["risk_score"],
                        "detected": detected, "alerts": det["alerts"]})
        flag = "MISS" if (case["malicious"] and not detected) else ("FP" if (not case["malicious"] and detected) else "ok")
        ids = ",".join(sorted({a["atlas_id"] for a in det["alerts"]})) or "-"
        print(f"[{case['id']}] {case['category']:18} risk={det['risk_score']:3d} {flag:4} atlas={ids}")

    report(results)


def report(results):
    mal = [r for r in results if r["malicious"]]
    ben = [r for r in results if not r["malicious"]]
    tp = sum(r["detected"] for r in mal)
    fn = len(mal) - tp
    fp = sum(r["detected"] for r in ben)
    tn = len(ben) - fp
    recall = tp / len(mal) if mal else 0
    precision = tp / (tp + fp) if (tp + fp) else 0
    fpr = fp / len(ben) if ben else 0

    by_cat = defaultdict(lambda: [0, 0])
    for r in mal:
        by_cat[r["category"]][1] += 1
        by_cat[r["category"]][0] += int(r["detected"])

    print("\n" + "=" * 52)
    print("DETECTION RESULTS")
    print("=" * 52)
    print(f"Malicious sessions : {len(mal)}")
    print(f"Benign sessions    : {len(ben)}")
    print(f"True positives     : {tp}")
    print(f"False negatives    : {fn}")
    print(f"False positives    : {fp}")
    print(f"True negatives     : {tn}")
    print(f"Recall (detection) : {recall:.0%}")
    print(f"Precision          : {precision:.0%}")
    print(f"False positive rate: {fpr:.0%}")
    print("\nBy attack category:")
    for cat, (hit, tot) in sorted(by_cat.items()):
        print(f"  {cat:18} {hit}/{tot} detected")

    summary = {
        "agent_mode": results[0].get("mode", ""),
        "totals": {"malicious": len(mal), "benign": len(ben), "tp": tp, "fn": fn, "fp": fp, "tn": tn},
        "metrics": {"recall": recall, "precision": precision, "false_positive_rate": fpr},
        "by_category": {c: {"detected": h, "total": t} for c, (h, t) in by_cat.items()},
    }
    with open("data/metrics.json", "w") as f:
        json.dump(summary, f, indent=2)
    print("\nSaved data/metrics.json")
    if fn:
        print(f"\nNote: {fn} malicious session(s) went undetected. Tune rules or enable --judge.")


if __name__ == "__main__":
    sys.exit(main())
