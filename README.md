# Network Baseline Auditor

An offline Python checker for a small network inventory export. It compares router, firewall, NAS, and server settings to a readable security baseline and creates prioritized findings with remediation notes.

## What it demonstrates

- Translating common hardening guidance into repeatable configuration checks
- Reviewing network and endpoint settings using a structured JSON inventory
- Producing evidence-based findings suitable for a remediation plan
- Separating baseline policy from evaluation logic

## Quick start

Requires Python 3.10 or newer.

```bash
python audit.py lab_inventory.json
python audit.py lab_inventory.json --output findings.json
```

## Checks included

- Remote administration exposed to the WAN
- SSH root login and password-based authentication
- Firewall default inbound policy
- SMB encryption and guest access on NAS devices
- Firmware inventory older than a configurable age threshold

The sample inventory is fictional and uses documentation-only IP addresses. Edit `lab_inventory.json` to match a lab you own or are authorized to assess. Never submit real credentials or sensitive network details to a public repository.

## Output

Each finding includes an asset name, control ID, severity, evidence, and remediation. The report is a starting point for an authorized hardening review; it is not proof that a network is secure.

## Limitations and safe use

This tool reads a local inventory export only. It does not scan, log into, or change devices. Inventory accuracy and the selected baseline determine the quality of its results. Confirm findings on the authorized device before making changes.
