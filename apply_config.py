#!/usr/bin/env python3
"""
apply_config_edits.py — one-shot config maintenance, run from ACF root.

Applies two edits to system_config.json:

  1. Copy capability_rules.pfirewall.decoder and
     capability_rules.pfirewall.rules into
     capability_rules.synthetic_firewall, if absent.

  2. Add {"event_id": 4624} to capability_rules.ssh.rules, if 4624
     is not already present.

Both edits are idempotent. Running the script a second time has no
additional effect.

Write is atomic: temp file, then os.replace. A timestamped backup
of the original is written before the change.

Usage:
    python apply_config_edits.py --dry-run
    python apply_config_edits.py
"""

import argparse
import json
import os
import shutil
import sys
import time

_HERE = os.path.dirname(os.path.abspath(__file__))
CONFIG_PATH = os.path.join(_HERE, "system_config.json")


def _load(path):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _atomic_write(path, data):
    tmp = f"{path}.tmp.{os.getpid()}.{int(time.time())}"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)
    os.replace(tmp, path)


def _backup(path):
    backup = f"{path}.bak.{int(time.time())}"
    shutil.copy2(path, backup)
    return backup


def _copy_pfirewall_to_synthetic_firewall(config):
    changes = []
    rules = config.get("capability_rules", {})
    if not isinstance(rules, dict):
        return ["capability_rules is not a dict; skipped"]

    pfirewall = rules.get("pfirewall")
    if not isinstance(pfirewall, dict):
        return ["capability_rules.pfirewall missing; skipped"]

    syn = rules.get("synthetic_firewall")
    if not isinstance(syn, dict):
        rules["synthetic_firewall"] = {}
        syn = rules["synthetic_firewall"]
        changes.append("created capability_rules.synthetic_firewall")

    if "decoder" not in syn:
        dec = pfirewall.get("decoder")
        if isinstance(dec, str) and dec:
            syn["decoder"] = dec
            changes.append(
                "copied decoder from pfirewall to synthetic_firewall")
    else:
        changes.append("decoder already present on synthetic_firewall")

    if "rules" not in syn:
        rl = pfirewall.get("rules")
        if isinstance(rl, list) and rl:
            syn["rules"] = list(rl)
            changes.append(
                "copied rules from pfirewall to synthetic_firewall")
    else:
        changes.append("rules already present on synthetic_firewall")

    if "type" not in syn and "type" in pfirewall:
        syn["type"] = pfirewall["type"]
        changes.append(
            "copied type from pfirewall to synthetic_firewall")

    return changes


def _add_ssh_4624(config):
    changes = []
    rules = config.get("capability_rules", {})
    if not isinstance(rules, dict):
        return ["capability_rules is not a dict; skipped"]

    ssh = rules.get("ssh")
    if not isinstance(ssh, dict):
        return ["capability_rules.ssh missing; skipped"]

    rule_list = ssh.get("rules")
    if not isinstance(rule_list, list):
        return ["capability_rules.ssh.rules missing or not a list; skipped"]

    existing_ids = set()
    for r in rule_list:
        if isinstance(r, dict) and "event_id" in r:
            try:
                existing_ids.add(int(r["event_id"]))
            except (TypeError, ValueError):
                pass

    if 4624 in existing_ids:
        changes.append("ssh already has event_id 4624")
    else:
        rule_list.append({"event_id": 4624})
        changes.append("added {\"event_id\": 4624} to ssh.rules")

    if 4625 not in existing_ids:
        changes.append(
            "WARNING: ssh.rules does not contain event_id 4625; "
            "login_success_after_failures needs both 4624 and 4625")

    return changes


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--dry-run", action="store_true",
                    help="print what would change, do not write")
    args = ap.parse_args()

    if not os.path.isfile(CONFIG_PATH):
        print(f"FAIL: config not found at {CONFIG_PATH}")
        sys.exit(1)

    try:
        config = _load(CONFIG_PATH)
    except Exception as e:
        print(f"FAIL: could not parse config: {e}")
        sys.exit(1)

    if not isinstance(config, dict):
        print("FAIL: config root is not a JSON object")
        sys.exit(1)

    changes = []
    changes.extend(_copy_pfirewall_to_synthetic_firewall(config))
    changes.extend(_add_ssh_4624(config))

    print("Proposed changes:")
    for c in changes:
        print(f"  - {c}")

    if args.dry_run:
        print("\n--dry-run: no write performed")
        return

    backup_path = _backup(CONFIG_PATH)
    print(f"\nBackup written: {backup_path}")

    try:
        _atomic_write(CONFIG_PATH, config)
    except Exception as e:
        print(f"FAIL: write failed: {e}")
        print(f"Config unchanged. Backup is at {backup_path}")
        sys.exit(1)

    print(f"Wrote {CONFIG_PATH}")
    print("\nNext steps:")
    print("  1. Restart orchestrator.")
    print("  2. Read layer_1_monitor_synthetic_firewall.behavior_coverage")
    print("     and layer_1_monitor_ssh.behavior_coverage.")


if __name__ == "__main__":
    main()