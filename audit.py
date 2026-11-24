#!/usr/bin/env python3
"""Audit a local JSON inventory against a compact security baseline."""
from __future__ import annotations
import argparse
import json
import sys
from datetime import date
from pathlib import Path

SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3}


def finding(asset: str, control: str, severity: str, evidence: str, recommendation: str) -> dict:
    return {"asset": asset, "control": control, "severity": severity,
            "evidence": evidence, "recommendation": recommendation}


def audit(inventory: dict, today: date | None = None) -> list[dict]:
    today = today or date.today()
    threshold_days = int(inventory.get("firmware_max_age_days", 365))
    results = []
    for device in inventory.get("devices", []):
        name = device.get("name", "unnamed-device")
        category = device.get("type", "unknown")
        if device.get("wan_admin_enabled") is True:
            results.append(finding(name, "NET-001", "critical", "WAN administration is enabled",
                                   "Disable WAN administration; use VPN or a dedicated management network."))
        if device.get("ssh_root_login") is True:
            results.append(finding(name, "SYS-001", "high", "SSH root login is enabled",
                                   "Disable direct root login and use named accounts with least privilege."))
        if device.get("ssh_password_auth") is True:
            results.append(finding(name, "SYS-002", "medium", "SSH password authentication is enabled",
                                   "Prefer key-based authentication and protect private keys appropriately."))
        if category == "firewall" and device.get("default_inbound_policy", "allow").lower() != "deny":
            results.append(finding(name, "NET-002", "high",
                                   f"Default inbound policy is {device.get('default_inbound_policy')}",
                                   "Set a default-deny inbound policy and add narrowly scoped allow rules."))
        if category == "nas" and device.get("smb_encryption") is not True:
            results.append(finding(name, "NAS-001", "medium", "SMB encryption is not enabled",
                                   "Enable SMB encryption where supported and verify client compatibility."))
        if category == "nas" and device.get("guest_access") is True:
            results.append(finding(name, "NAS-002", "high", "Guest file access is enabled",
                                   "Disable guest access and assign named users or groups with least privilege."))
        firmware_date = device.get("firmware_date")
        if firmware_date:
            try:
                age = (today - date.fromisoformat(firmware_date)).days
                if age > threshold_days:
                    results.append(finding(name, "PATCH-001", "medium",
                                           f"Firmware inventory date is {age} days old",
                                           "Check the vendor's security advisories and update through the approved change process."))
            except ValueError:
                results.append(finding(name, "DATA-001", "low", f"Invalid firmware_date: {firmware_date}",
                                       "Use an ISO date such as 2025-01-31 in the inventory."))
    return sorted(results, key=lambda item: (SEVERITY_ORDER[item["severity"]], item["asset"], item["control"]))


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("inventory", type=Path, help="local JSON inventory file")
    parser.add_argument("--output", type=Path, help="write report JSON to a file")
    args = parser.parse_args()
    try:
        inventory = json.loads(args.inventory.read_text(encoding="utf-8"))
        if not isinstance(inventory, dict) or not isinstance(inventory.get("devices", []), list):
            raise ValueError("expected a JSON object containing a devices array")
        findings = audit(inventory)
    except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
        print(f"Could not audit inventory: {exc}", file=sys.stderr)
        return 2
    report = {"asset_count": len(inventory.get("devices", [])), "finding_count": len(findings), "findings": findings}
    rendered = json.dumps(report, indent=2)
    if args.output:
        args.output.write_text(rendered + "\n", encoding="utf-8")
        print(f"Wrote {len(findings)} finding(s) to {args.output}")
    else:
        print(rendered)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
