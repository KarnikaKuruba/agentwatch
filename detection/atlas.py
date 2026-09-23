"""MITRE ATLAS techniques used by AgentWatch.

Names and IDs follow atlas.mitre.org. ATLAS is updated often, so check the
site before a demo and adjust anything that has been renamed.
"""

ATLAS = {
    "AML.T0051.000": {"name": "LLM Prompt Injection: Direct", "tactic": "Execution"},
    "AML.T0051.001": {"name": "LLM Prompt Injection: Indirect", "tactic": "Execution"},
    "AML.T0054": {"name": "LLM Jailbreak", "tactic": "Privilege Escalation"},
    "AML.T0056": {"name": "LLM Meta Prompt Extraction", "tactic": "Discovery"},
    "AML.T0057": {"name": "LLM Data Leakage", "tactic": "Exfiltration"},
    "AML.T0068": {"name": "LLM Prompt Obfuscation", "tactic": "Defense Evasion"},
    "AML.T0085.001": {"name": "Data from AI Services: AI Agent Tools", "tactic": "Collection"},
    "AML.T0086": {"name": "Exfiltration via AI Agent Tool Invocation", "tactic": "Exfiltration"},
}


def name_of(atlas_id: str) -> str:
    return ATLAS.get(atlas_id, {}).get("name", "Unmapped")
