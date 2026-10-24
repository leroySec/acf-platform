#!/usr/bin/env python3
"""
disable_ssh_layer2.py

Adds "layer2" to disabled_capabilities.ssh in the blackboard, using the
same platform file lock the engines use. The orchestrator's monitor_loop
reads disabled_capabilities every 5 s and will stop ssh@layer2 on its
next sync. The AIS engine for ssh is not respawned while the pair is
disabled, which is what the Gate 3 fallback test requires.

Idempotent: running it twice produces the same result.
"""

import json
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from platform_utils import acquire_lock, release_lock
from config import Config


def main():
    path = Config.BLACKBOARD_FILE

    with open(path, "r+", encoding="utf-8") as f:
        acquire_lock(f.fileno(), exclusive=True)
        try:
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                print("ERROR: blackboard is not valid JSON; aborting", file=sys.stderr)
                sys.exit(1)

            if not isinstance(data, dict):
                print("ERROR: blackboard root is not an object; aborting", file=sys.stderr)
                sys.exit(1)

            dis = data.get("disabled_capabilities")
            if not isinstance(dis, dict):
                dis = {}

            layers = dis.get("ssh")
            if not isinstance(layers, list):
                layers = []

            if "layer2" not in layers:
                layers.append("layer2")

            dis["ssh"] = layers
            data["disabled_capabilities"] = dis

            f.seek(0)
            json.dump(data, f, indent=2)
            f.truncate()
        finally:
            release_lock(f.fileno())

    print("disabled_capabilities.ssh =", layers)
    print("Write committed with lock held.")
    print("Orchestrator will stop ssh@layer2 within ~5 s and will not respawn it.")


if __name__ == "__main__":
    main()
