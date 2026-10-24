#!/usr/bin/env python3
"""Add MTD-specific fields to system_config.json without rewriting anything else."""
import json, sys, os
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from platform_utils import acquire_lock, release_lock

CFG = os.path.join(os.path.dirname(os.path.abspath(__file__)), "system_config.json")

with open(CFG, "r+", encoding="utf-8") as f:
    acquire_lock(f.fileno(), exclusive=True)
    try:
        data = json.load(f)

        cl = data.setdefault("capability_layers", {})
        ssh_layers = cl.get("ssh", [])
        if not isinstance(ssh_layers, list):
            ssh_layers = []
        if "layer4c" not in ssh_layers:
            ssh_layers.append("layer4c")
        cl["ssh"] = ssh_layers

        layers = data.setdefault("layers", {})
        layers["layer4c"] = True

        rules = data.setdefault("capability_rules", {})
        ssh_rules = rules.get("ssh", {})
        if not isinstance(ssh_rules, dict):
            ssh_rules = {}
        ssh_rules["service_ports"] = [22]
        ssh_rules["shuffle"] = {
            "enabled": True,
            "primary_port": 22,
            "alternate_port": 2222,
            "trigger_distinct_attackers": 3,
            "trigger_red_seconds": 60,
            "restore_after_seconds": 1800,
        }
        rules["ssh"] = ssh_rules
        data["capability_rules"] = rules

        f.seek(0); json.dump(data, f, indent=2); f.truncate()
    finally:
        release_lock(f.fileno())

print("MTD config added in place.")
print("ssh layers:   ", ssh_layers)
print("ssh rules keys:", list(ssh_rules.keys()))
