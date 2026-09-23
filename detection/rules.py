"""Rule layer. Fast, explainable checks over one agent session.

Each rule gets the session's ordered events and returns zero or more alerts.
"""
import base64
import json
import os
import re

from agent.agent import CANARY

SEVERITY_SCORE = {"low": 25, "medium": 50, "high": 75, "critical": 95}
ALLOWED_EMAIL_DOMAINS = {d.strip().lower() for d in os.getenv("ALLOWED_EMAIL_DOMAINS", "acmecorp.com").split(",")}

OVERRIDE_RE = re.compile(
    r"ignore (all |any )?(previous|prior|above|earlier) (instructions|rules|prompts)"
    r"|disregard (your|all|the|any) (instructions|rules)"
    r"|new instructions|admin override|you are now|\bsystem\s*:|\[\[\s*system"
    r"|forget (your|all) (rules|instructions)",
    re.I,
)
AI_DIRECTED_RE = re.compile(
    r"\b(ai assistant|assistant|ai model|language model|llm|bot|agent)s?\b[^.]{0,50}"
    r"\b(should|must|please|ignore|send|forward|email)\b",
    re.I,
)
JAILBREAK_RE = re.compile(
    r"\b(DAN|do anything now|developer mode|no restrictions|unfiltered mode|jailbreak|"
    r"without (any )?(rules|filters|limits))\b",
    re.I,
)
SECRET_RES = [
    ("OpenAI style API key", re.compile(r"sk-(proj-)?[A-Za-z0-9]{20,}")),
    ("AWS access key", re.compile(r"AKIA[A-Z0-9]{16}")),
    ("Password assignment", re.compile(r"password\s*[=:]\s*\S{6,}", re.I)),
    ("Private key block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----")),
]
HIDDEN_RES = [
    ("HTML comment with instructions", re.compile(r"<!--(?=[^>]*\b(ignore|send|email|forward|assistant|ai)\b).*?-->", re.I | re.S)),
    ("Hidden element (display:none)", re.compile(r"display\s*:\s*none", re.I)),
    ("Near invisible text styling", re.compile(r"font-size\s*:\s*[0-2]px|color\s*:\s*#fff(fff)?\b", re.I)),
    ("Zero width characters", re.compile(r"[\u200b\u200c\u200d\u2060\ufeff]")),
    ("Fake system block", re.compile(r"\[\[\s*system", re.I)),
]
B64_RE = re.compile(r"\b[A-Za-z0-9+/]{24,}={0,2}")
EMAIL_RE = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
URL_RE = re.compile(r"https?://[^\s'\"<>)]+")


def _alert(rule_id, title, severity, atlas_id, evidence):
    return {
        "rule_id": rule_id,
        "title": title,
        "severity": severity,
        "score": SEVERITY_SCORE[severity],
        "atlas_id": atlas_id,
        "evidence": evidence[:300],
        "layer": "rules",
    }


def _snip(text, m, pad=60):
    s, e = max(0, m.start() - pad), min(len(text), m.end() + pad)
    return re.sub(r"\s+", " ", text[s:e]).strip()


def _domain_allowed(addr: str) -> bool:
    domain = addr.split("@")[-1].lower()
    return any(domain == d or domain.endswith("." + d) for d in ALLOWED_EMAIL_DOMAINS)


def _decoded_b64(text):
    out = []
    for blob in B64_RE.findall(text):
        try:
            dec = base64.b64decode(blob + "=" * (-len(blob) % 4)).decode("utf-8")
            if dec.isprintable() and " " in dec:
                out.append(dec)
        except Exception:  # noqa: BLE001
            pass
    return out


def _emails_sent(events):
    for ev in events:
        if ev["type"] == "tool_call" and ev["tool"] == "send_email":
            try:
                yield ev, json.loads(ev["content"])
            except json.JSONDecodeError:
                continue


def rule_direct_injection(events):
    for ev in events:
        if ev["type"] == "user_input" and (m := OVERRIDE_RE.search(ev["content"])):
            return [_alert("AW-001", "Instruction override in user prompt", "high", "AML.T0051.000", _snip(ev["content"], m))]
    return []


def rule_indirect_injection(events):
    for ev in events:
        if ev["type"] == "tool_result" and ev["trust"] == "untrusted":
            text = ev["content"] + " " + " ".join(_decoded_b64(ev["content"]))
            m = OVERRIDE_RE.search(text) or AI_DIRECTED_RE.search(text)
            if m:
                return [_alert("AW-002", f"Instructions aimed at the agent inside {ev['tool']} content", "high", "AML.T0051.001", _snip(text, m))]
    return []


def rule_hidden_content(events):
    found = []
    for ev in events:
        if ev["type"] != "tool_result" or ev["trust"] != "untrusted":
            continue
        for label, rx in HIDDEN_RES:
            if m := rx.search(ev["content"]):
                found.append(f"{label}: {_snip(ev['content'], m, 40)}")
        for dec in _decoded_b64(ev["content"]):
            found.append(f"Base64 text decodes to: {dec[:120]}")
    if found:
        return [_alert("AW-003", "Hidden or obfuscated text in untrusted content", "medium", "AML.T0068", " | ".join(found))]
    return []


def rule_jailbreak(events):
    for ev in events:
        if ev["type"] in ("user_input", "tool_result") and (m := JAILBREAK_RE.search(ev["content"])):
            return [_alert("AW-004", "Jailbreak phrasing detected", "high", "AML.T0054", _snip(ev["content"], m))]
    return []


def rule_prompt_leak(events):
    for ev in events:
        leaked = (ev["type"] == "model_output" and CANARY in ev["content"]) or (
            ev["type"] == "tool_call" and ev["tool"] == "send_email" and CANARY in ev["content"]
        )
        if leaked:
            return [_alert("AW-005", "System prompt canary appeared in agent output", "high", "AML.T0056", f"Canary {CANARY} found in {ev['type']}")]
    return []


def rule_secret_leak(events):
    for ev in events:
        if ev["type"] == "model_output" or (ev["type"] == "tool_call" and ev["tool"] == "send_email"):
            for label, rx in SECRET_RES:
                if m := rx.search(ev["content"]):
                    where = "an outgoing email" if ev["type"] == "tool_call" else "the reply to the user"
                    masked = m.group(0)[:8] + "****"
                    return [_alert("AW-006", f"{label} leaked in {where}", "critical", "AML.T0057", masked)]
    return []


def rule_external_email(events):
    alerts = []
    for ev, args in _emails_sent(events):
        to = args.get("to", "")
        if to and not _domain_allowed(to):
            alerts.append(_alert("AW-007", f"Agent emailed an outside address ({to})", "critical", "AML.T0086", f"to={to} subject={args.get('subject', '')}"))
    return alerts[:1]


def rule_bulk_sensitive_query(events):
    for ev in events:
        if ev["type"] == "tool_call" and ev["tool"] == "query_db":
            sql = json.loads(ev["content"]).get("sql", "").lower()
            if "secrets" in sql or re.search(r"select \* from customers", sql):
                return [_alert("AW-008", "Agent pulled sensitive tables in bulk", "medium", "AML.T0085.001", sql)]
    return []


def rule_untrusted_recipient(events):
    """The recipient was never named by the user but did appear in content the agent read."""
    user_text = " ".join(e["content"] for e in events if e["type"] == "user_input").lower()
    raw = " ".join(e["content"] for e in events if e["type"] == "tool_result" and e["trust"] == "untrusted")
    untrusted_text = (raw + " " + " ".join(_decoded_b64(raw))).lower()
    for ev, args in _emails_sent(events):
        to = args.get("to", "").lower()
        if to and to not in user_text and to in untrusted_text:
            return [_alert("AW-009", "Email recipient came from untrusted content, not the user", "high", "AML.T0051.001", f"{to} appeared only in fetched content")]
    return []


def rule_relayed_link(events):
    user_text = " ".join(e["content"] for e in events if e["type"] == "user_input")
    untrusted = " ".join(e["content"] for e in events if e["type"] == "tool_result" and e["trust"] == "untrusted")
    for ev in events:
        if ev["type"] == "model_output":
            for url in URL_RE.findall(ev["content"]):
                url = url.rstrip(".,")
                if url not in user_text and url in untrusted:
                    return [_alert("AW-010", "Agent passed a link from untrusted content to the user", "medium", "AML.T0051.001", url)]
    return []


RULES = [
    rule_direct_injection,
    rule_indirect_injection,
    rule_hidden_content,
    rule_jailbreak,
    rule_prompt_leak,
    rule_secret_leak,
    rule_external_email,
    rule_bulk_sensitive_query,
    rule_untrusted_recipient,
    rule_relayed_link,
]


def run_rules(events):
    alerts = []
    for rule in RULES:
        alerts.extend(rule(events))
    return alerts
