#!/usr/bin/env python3
"""
mtd/enabling.py — Time as an enabling factor for MTD actions.

The MTD ladder graduates on sustained state duration. An action is
not appropriate the instant the state changes. It becomes
appropriate once the state has been held long enough for the
lower-tier responses to demonstrate whether they are containing
the attack. Duration is the enabling condition.

This module is the single place that computes:
  - which state the capability is currently in
  - how long that state has been held
  - whether the state matches a requirement and has been held
    for at least a required duration

Actions call is_enabled(). They do not read the Blackboard
themselves for state and time.

Public API:
  read_state(capability) -> (state, entered_at)
  state_duration(capability, now=None) -> float
  is_enabled(capability, state_minimums, now=None) -> (bool, str)

Self-test:
  python mtd/enabling.py <capability>

Prints what the module currently reads from the Blackboard for the
capability, and what is_enabled would decide under a sample
threshold. Use it to answer "what does the enabling module see
right now" without starting the engine.
"""

import json
import os
import sys
import time
from typing import Dict, Optional, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)

try:
    from config import Config
    _CONFIG_AVAILABLE = True
except ImportError:
    Config = None
    _CONFIG_AVAILABLE = False

try:
    from platform_utils import acquire_lock, release_lock
    _LOCK_AVAILABLE = True
except ImportError:
    _LOCK_AVAILABLE = False

    def acquire_lock(fd, exclusive=True):
        pass

    def release_lock(fd):
        pass


BLACKBOARD_FILE = (
    getattr(Config, "BLACKBOARD_FILE", None)
    if _CONFIG_AVAILABLE else None
) or os.path.join(
    os.environ.get("TEMP", "/tmp"),
    "acf_state.json"
)

MAX_TIMESTAMP_AGE_SECONDS = 30 * 86400


def _read_blackboard() -> Dict:
    """One read of the Blackboard. Returns {} on any failure."""
    try:
        with open(BLACKBOARD_FILE, "r", encoding="utf-8") as f:
            if _LOCK_AVAILABLE:
                acquire_lock(f.fileno(), exclusive=False)
                try:
                    data = json.load(f)
                finally:
                    release_lock(f.fileno())
            else:
                data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


def read_state(capability: str) -> Tuple[str, float]:
    """
    Return (state, entered_at) for the capability.

    state is upper-cased and stripped. Empty string when the
    section does not exist or the value is malformed.

    entered_at is the epoch timestamp when the state was entered,
    from layer_3_state_<cap>.state_entered_at. 0.0 when unavailable
    or older than MAX_TIMESTAMP_AGE_SECONDS.
    """
    if not isinstance(capability, str) or not capability:
        return "", 0.0

    bb = _read_blackboard()
    sec = bb.get(f"layer_3_state_{capability}", {})
    if not isinstance(sec, dict):
        return "", 0.0

    s = sec.get("state", "")
    if not isinstance(s, str):
        s = ""
    s = s.strip().upper()

    try:
        entered = float(sec.get("state_entered_at", 0.0))
    except (TypeError, ValueError):
        entered = 0.0

    now = time.time()
    if entered <= 0 or entered > now:
        entered = 0.0
    elif (now - entered) > MAX_TIMESTAMP_AGE_SECONDS:
        entered = 0.0

    return s, entered


def state_duration(capability: str, now: Optional[float] = None
                   ) -> float:
    """
    Return the elapsed seconds since the state was entered.
    Returns 0.0 when entered_at is unavailable.
    """
    if now is None:
        now = time.time()
    _s, entered = read_state(capability)
    if entered <= 0:
        return 0.0
    return max(0.0, now - entered)


def is_enabled(capability: str,
               state_minimums: Dict[str, int],
               now: Optional[float] = None
               ) -> Tuple[bool, str]:
    """
    The enabling check.

    state_minimums maps state name to the minimum seconds the state
    must have been held before the action is enabled. Example:

        {"ORANGE": 60, "RED": 0}

    Only states listed in the map are considered. Any other state
    returns (False, reason).

    Returns (enabled, reason). The reason is a short string naming
    what the check observed, suitable for status()["gate_reason"].

    Never raises.
    """
    if not isinstance(capability, str) or not capability:
        return False, "invalid_capability"
    if not isinstance(state_minimums, dict) or not state_minimums:
        return False, "no_state_requirements"

    if now is None:
        now = time.time()

    try:
        state, entered = read_state(capability)
    except Exception as e:
        return False, f"read_failed:{type(e).__name__}"

    if state not in state_minimums:
        return False, f"state_below_required:{state or 'none'}"

    minimum = state_minimums[state]
    try:
        minimum = int(minimum)
    except (TypeError, ValueError):
        minimum = 0
    if minimum < 0:
        minimum = 0

    if entered <= 0:
        return False, "no_state_entered_at"

    elapsed = max(0.0, now - entered)
    if elapsed < minimum:
        return False, (
            f"{state.lower()}_seconds={int(elapsed)}<{minimum}")

    return True, f"{state.lower()}_sustained_seconds={int(elapsed)}"


# ======================================================================
# Self-test
# ======================================================================
def _selftest(capability: str) -> None:
    print("=" * 64)
    print("  mtd/enabling.py — self test")
    print("=" * 64)
    print()
    print(f"capability       : {capability}")
    print(f"blackboard       : {BLACKBOARD_FILE}")
    print(f"blackboard exists: {os.path.isfile(BLACKBOARD_FILE)}")
    print()

    bb = _read_blackboard()
    print(f"blackboard keys  : {len(bb)} top-level")
    section_name = f"layer_3_state_{capability}"
    present = section_name in bb if isinstance(bb, dict) else False
    print(f"state section    : {section_name}")
    print(f"section present  : {present}")

    if present:
        sec = bb.get(section_name)
        if isinstance(sec, dict):
            print(f"section keys     : {sorted(sec.keys())}")
    print()

    state, entered = read_state(capability)
    now = time.time()
    if entered > 0:
        elapsed = max(0.0, now - entered)
    else:
        elapsed = 0.0

    print(f"state            : {state!r}")
    print(f"state_entered_at : {entered}")
    if entered > 0:
        print(f"  ({elapsed:.1f} seconds ago)")
    else:
        print(f"  (not available)")
    print()

    # Sample A: ORANGE requires 20 s, RED fires immediately.
    sample_a = {"ORANGE": 20, "RED": 0}
    enabled_a, reason_a = is_enabled(capability, sample_a, now=now)
    print(f"sample A  {sample_a}")
    print(f"  enabled: {enabled_a}")
    print(f"  reason : {reason_a!r}")
    print()

    # Sample B: RED requires 90 s.
    sample_b = {"RED": 90}
    enabled_b, reason_b = is_enabled(capability, sample_b, now=now)
    print(f"sample B  {sample_b}")
    print(f"  enabled: {enabled_b}")
    print(f"  reason : {reason_b!r}")
    print()

    print("Interpretation")
    print("--------------")
    print("  state_below_required:GREEN  — the state section says GREEN")
    print("  no_state_entered_at          — the section exists but")
    print("                                 state_entered_at is missing")
    print("                                 or zero")
    print("  orange_seconds=15<20         — the state is ORANGE but")
    print("                                 has only been held 15 s")
    print("  red_sustained_seconds=45     — the state is RED and has")
    print("                                 been held 45 s")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("usage: python mtd/enabling.py <capability>")
        print("example: python mtd/enabling.py synthetic_firewall")
        sys.exit(1)
    _selftest(sys.argv[1])