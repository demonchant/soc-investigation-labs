# SaaS Account Takeover Detector

This project correlates SaaS audit events into account takeover stories. It detects external mailbox forwarding, hidden inbox rules, unexpected delegates, recovery method changes, mass deletion, and suspicious administrative activity after a risky sign in.

## Detection approach

Single audit events are useful, but account takeover becomes clearer when identity, mailbox, file, and administrative activity are joined by user and time. The engine assigns points to risky actions and raises a critical correlated finding when a user crosses the incident threshold.

## Run

```bash
python main.py
```

The command uses `data/saas_events.json` and writes findings to `reports/saas_findings.json`.

This is a production structured demonstration based on normalized synthetic events. A real deployment should ingest Microsoft 365, Google Workspace, Slack, Salesforce, or comparable SaaS audit feeds.
