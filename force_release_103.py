#!/usr/bin/env python3
import json, sys, os, subprocess
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from platform_utils import acquire_lock, release_lock
from config import Config

TARGET = "192.168.56.103"
path = Config.BLACKBOARD_FILE

removed_rules = []
with open(path, "r+", encoding="utf-8") as f:
    acquire_lock(f.fileno(), exclusive=True)
    try:
        data = json.load(f)
        resp = data.get("layer_4a_response_ssh", {})
        blocked = resp.get("blocked_ips") or []
        kept = []
        for entry in blocked:
            if entry.get("ip") == TARGET:
                removed_rules.extend(entry.get("rule_names") or [])
            else:
                kept.append(entry)
        resp["blocked_ips"] = kept
        data["layer_4a_response_ssh"] = resp
        f.seek(0); json.dump(data, f, indent=2); f.truncate()
    finally:
        release_lock(f.fileno())

for rule in removed_rules:
    subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule}"], capture_output=True)

print(f"Removed {len(removed_rules)} firewall rules for {TARGET}")
print(f"Remaining blocked_ips: {len(kept)}")