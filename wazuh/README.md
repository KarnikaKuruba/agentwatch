# Wazuh integration (optional, advanced)

AgentWatch writes every agent event to `data/agent_events.jsonl`. Wazuh can tail
that file, decode the JSON, and raise its own alerts using the rules below. This
turns AI agent activity into a first class log source in a real SIEM, which is
the part that shows detection engineering skill.

## 1. Tell the Wazuh agent to read the log

Add to `/var/ossec/etc/ossec.conf` on the machine running the agent:

```xml
<localfile>
  <log_format>json</log_format>
  <location>/path/to/agentwatch/data/agent_events.jsonl</location>
</localfile>
```

## 2. Add the rules

Copy `local_rules.xml` into `/var/ossec/etc/rules/` and restart Wazuh:

```
sudo systemctl restart wazuh-manager
```

Because the log is JSON, Wazuh decodes the fields automatically. The rules key
off `agentwatch.type`, `agentwatch.trust`, and `agentwatch.tool`.
