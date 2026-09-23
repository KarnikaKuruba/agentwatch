# AgentWatch

Runtime security monitoring for AI agents. AgentWatch watches everything an AI
agent does, the user prompt, every web page and file it reads, every tool call,
and its final output, and flags attacks like prompt injection, jailbreaks, data
leakage, and exfiltration. Every alert is mapped to a MITRE ATLAS technique.

Companies are connecting language models to real tools such as email, databases,
and internal APIs, but almost nobody monitors those agents the way a SOC monitors
servers. AgentWatch is that missing layer. It is a sibling to
[ThreatWatch](https://github.com/KarnikaKuruba/ThreatWatch-final), which triages
traditional SOC alerts.

## What it does

- Runs a test agent with four tools (fetch a web page, read a file, query a
  database, send email) and logs every step.
- Runs an attack suite of prompt injections, jailbreaks, indirect injections
  hidden in web pages and documents, secret extraction, and tool based
  exfiltration, plus benign control cases.
- Detects attacks with two layers: a fast rule engine and an optional LLM judge
  that reviews the whole session.
- Maps each alert to MITRE ATLAS and scores session risk from 0 to 100.
- Shows it all in a dashboard, and can forward alerts to Wazuh or ThreatWatch.

## Screenshots

**Dashboard overview.** Session counts, the session list, and alerts grouped by MITRE ATLAS technique.

![Dashboard overview](docs/screenshots/dashboard.png)

**Flagged sessions.** Attacks ranked by risk score, from direct and indirect prompt injection to jailbreaks.

![Flagged sessions](docs/screenshots/flagged-sessions.png)

**Severity filter.** Only the high severity sessions.

![High severity sessions](docs/screenshots/high-severity.png)

**System prompt leak.** The user prompt tries to override the agent's rules, and the agent prints its system prompt. AgentWatch flags the override and spots the planted canary (`AW-CANARY-7731`) in the output.

![System prompt leak](docs/screenshots/prompt-leak.png)

**Data exfiltration.** The agent is told to send the customer list outside the company. The trace shows the `query_db` call, the customer records it returned, and the `send_email` call to an outside address. Three alerts fire along the way.

![Data exfiltration trace](docs/screenshots/exfiltration.png)

## Results

From the bundled attack suite against the simulated agent, rules only:

| Metric | Value |
| --- | --- |
| Attacks detected | 16 / 16 |
| False positives | 0 / 8 benign sessions |
| Detection rate | 100% |
| False positive rate | 0% |

The simulated agent is deliberately naive so the suite is repeatable with no API
key. Point it at a real LLM agent (`AGENT_MODE=openai`) to measure detection
against genuine model behaviour, which is the more honest number to report.
Regenerate the table any time with `python run_attacks.py`.

### Running it

**Install.** One `pip install` pulls in everything.

![Installing requirements](docs/screenshots/install.png)

**Attack suite.** `python run_attacks.py` runs all 24 cases. Each line shows the risk score and the ATLAS techniques that fired, followed by the overall detection results.

![Attack suite output](docs/screenshots/attack-suite.png)

**Per-category results and backend.** Every category is fully detected. After that, `uvicorn main:app` starts the backend, and the dashboard pulls sessions and stats from it.

![Category results and backend running](docs/screenshots/results-and-server.png)

## Architecture

```
User prompt
   │
   ▼
Test agent ──fetch_url / read_file / query_db / send_email──▶ sandboxed tools
   │  (logs every event, tags tool output as trusted or untrusted)
   ▼
data/agent_events.jsonl ───────────────▶ Wazuh (optional)
   │
   ▼
Detection engine
   ├─ Rule layer   (10 rules over the session)
   └─ LLM judge    (optional second opinion)
   │
   ▼
Alerts + risk score  ──▶ FastAPI  ──▶ Dashboard
                                   └─▶ ThreatWatch (optional)
```

## Detection rules

| ID | Catches | ATLAS |
| --- | --- | --- |
| AW-001 | Instruction override in the user prompt | AML.T0051.000 |
| AW-002 | Instructions aimed at the agent inside fetched content | AML.T0051.001 |
| AW-003 | Hidden or obfuscated text (HTML comments, invisible CSS, base64) | AML.T0068 |
| AW-004 | Jailbreak phrasing | AML.T0054 |
| AW-005 | System prompt canary leaked | AML.T0056 |
| AW-006 | API key, password, or private key in an output or email | AML.T0057 |
| AW-007 | Email sent to an outside domain | AML.T0086 |
| AW-008 | Bulk read of sensitive tables | AML.T0085.001 |
| AW-009 | Email recipient came from untrusted content, not the user | AML.T0051.001 |
| AW-010 | Untrusted link relayed to the user | AML.T0051.001 |
| AW-J01 | LLM judge caught something the rules missed | varies |

## Quick start

```bash
pip install -r requirements.txt

# Run the attack suite and print the metrics (no API key needed)
python run_attacks.py

# Add the LLM judge and use a real agent (needs OPENAI_API_KEY in .env)
AGENT_MODE=openai python run_attacks.py --judge

# Start the backend, which also serves the dashboard
uvicorn main:app --port 8000

# Then open the dashboard in a browser:
#   http://localhost:8000
# It detects it's being served by the backend and shows live data automatically.
# (Double-clicking frontend/index.html still works too, showing the saved run.)
```

## Layout

```
agent/        the test agent, its sandboxed tools, and the event logger
detection/    ATLAS map, rule layer, LLM judge, and the engine that runs them
attacks/      the attack and benign test cases
fixtures/     fake web pages and documents, some carrying hidden injections
frontend/     the dashboard (single self-contained HTML file)
wazuh/        optional Wazuh decoder rules and setup notes
docs/         dashboard screenshots
main.py       FastAPI backend
run_attacks.py  run the suite and write data/metrics.json
```

## Notes

Everything runs in a sandbox. No real web requests, no real email, and the
database holds fake data with clearly fake secrets. MITRE ATLAS is updated often,
so check atlas.mitre.org before a demo in case a technique has been renamed.
