#!/usr/bin/env python3
# ============================================================================
# OBSERVABILITY AGGREGATOR — read-only change detection over the Blackboard
# ============================================================================
# This module does not modify any ACF file. It reads the Blackboard,
# keeps the last-seen summary of a fixed set of sections, and reports
# field-level changes between two reads.
#
# Public API:
#     read_all()          -> {capability: {layer: {current, previous, changes}}}
#     read_observations() -> flat list of change observations
#     reset()             -> forget cached state (forces first-read mode)
#     is_first_read()     -> True until the first read_all() completes
#
# Design:
#   - Sections are matched by prefix. Unknown sections are ignored.
#   - Certain high-churn fields (timestamps, recent_lines, recent_events,
#     action_log, detector_stats, behavior_coverage, owner/pid fields)
#     are excluded from the summary so they do not generate change noise.
#   - Lists and dicts are summarised by length only ("<field>_count").
#   - Scalars (str, int, float, bool, None) are compared directly.
#   - The first read establishes baseline; no changes are reported.
# ============================================================================

import json
import time
import threading
from typing import Any, Dict, List, Optional, Tuple

from config import Config


# ----------------------------------------------------------------------
# Configuration
# ----------------------------------------------------------------------
BLACKBOARD_FILE = Config.BLACKBOARD_FILE

# Section prefix -> layer label
_SECTION_MAP: Tuple[Tuple[str, str], ...] = (
    ("reader_",             "reader"),
    ("layer_1_monitor_",    "layer1"),
    ("layer_2_ais_",        "layer2"),
    ("layer_2_groups_",     "layer2_groups"),
    ("layer_3_state_",      "layer3"),
    ("layer_4a_response_",  "layer4a"),
    ("layer_4c_mtd_",       "layer4c"),
)

# Sections with no capability suffix.
_GLOBAL_SECTIONS: Dict[str, str] = {
    "layer_1_sensor_ext":   "sensor",
    "layer_2_correlated":   "correlated",
    "layer_3_state":        "layer3_flat",
    "disabled_capabilities": "system",
    "enabled_capabilities":  "system",
    "capability_paths":      "system",
    "capability_layers":     "system",
    "preconditions":         "system",
}

# Fields that change every cycle and must not be treated as observations.
_IGNORED_FIELDS = frozenset({
    "reading_timestamp",
    "monitoring_timestamp",
    "ais_timestamp",
    "state_timestamp",
    "response_timestamp",
    "mtd_timestamp",
    "generated_at",
    "marker_timestamp",
    "reconciled_at",
    "reader_owner",
    "reader_pid",
    "reader_started",
    "state_entered_at",
    "block_timestamp",
    "installed_at",
    "expires_at",
    "last_heartbeat",
    "log_source",
    "recent_lines",
    "recent_events",
    "recent_ips",
    "action_log",
    "actions",
    "detector_stats",
    "behavior_coverage",
    "blocked_ips",
    "known_threats",
    "isolation_rule_names",
    "reader_pathological_drops",
})


# ----------------------------------------------------------------------
# Internal state
# ----------------------------------------------------------------------
_lock = threading.Lock()
_previous: Dict[str, Dict[str, Any]] = {}
_first_read: bool = True


# ----------------------------------------------------------------------
# Blackboard read
# ----------------------------------------------------------------------
def _read_blackboard() -> Dict[str, Any]:
    try:
        with open(BLACKBOARD_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


# ----------------------------------------------------------------------
# Section summarisation
# ----------------------------------------------------------------------
def _summarize_section(section: Any) -> Dict[str, Any]:
    """Return a stable, comparison-safe summary of one Blackboard section."""
    if not isinstance(section, dict):
        return {}
    summary: Dict[str, Any] = {}
    for key, value in section.items():
        if not isinstance(key, str):
            continue
        if key in _IGNORED_FIELDS:
            continue
        if isinstance(value, (str, int, float, bool)) or value is None:
            summary[key] = value
        elif isinstance(value, list):
            summary[key + "_count"] = len(value)
        elif isinstance(value, dict):
            summary[key + "_count"] = len(value)
    return summary


def _diff(prev: Dict[str, Any],
          curr: Dict[str, Any]) -> List[Dict[str, Any]]:
    """Return a list of field-level changes between two summaries."""
    changes: List[Dict[str, Any]] = []
    all_keys = set(prev.keys()) | set(curr.keys())
    for key in sorted(all_keys):
        in_prev = key in prev
        in_curr = key in curr
        if in_prev and not in_curr:
            changes.append({
                "field": key,
                "kind": "removed",
                "from": prev[key],
                "to": None,
            })
        elif not in_prev and in_curr:
            changes.append({
                "field": key,
                "kind": "added",
                "from": None,
                "to": curr[key],
            })
        elif prev[key] != curr[key]:
            changes.append({
                "field": key,
                "kind": "changed",
                "from": prev[key],
                "to": curr[key],
            })
    return changes


def _classify_section(section_name: str
                      ) -> Tuple[Optional[str], Optional[str]]:
    """Return (capability, layer_label) for a section, or (None, None)."""
    for prefix, label in _SECTION_MAP:
        if section_name.startswith(prefix):
            cap = section_name[len(prefix):]
            if not cap:
                return None, None
            return cap, label
    label = _GLOBAL_SECTIONS.get(section_name)
    if label is not None:
        return label, label
    return None, None


# ----------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------
def reset() -> None:
    """Forget cached summaries. The next read_all() will be a first read."""
    global _previous, _first_read
    with _lock:
        _previous = {}
        _first_read = True


def is_first_read() -> bool:
    with _lock:
        return _first_read


def read_all() -> Dict[str, Dict[str, Any]]:
    """
    Read the Blackboard and return per-capability, per-layer change data.

    {
      capability: {
        layer: {
          "current":  {field: value, ...},
          "previous": {field: value, ...},
          "changes":  [ {field, kind, from, to}, ... ],
          "ts":       float,
        }
      }
    }

    On the first call after import or reset(), "changes" is empty for
    every section and "previous" is empty; the first read establishes
    the baseline.
    """
    global _previous, _first_read

    bb = _read_blackboard()
    now = time.time()
    result: Dict[str, Dict[str, Any]] = {}

    with _lock:
        first = _first_read

        for section_name, raw_section in bb.items():
            if not isinstance(section_name, str):
                continue

            capability, layer_label = _classify_section(section_name)
            if capability is None or layer_label is None:
                continue

            summary = _summarize_section(raw_section)
            prev_summary = _previous.get(section_name, {})
            changes = [] if first else _diff(prev_summary, summary)

            result.setdefault(capability, {})[layer_label] = {
                "current":  summary,
                "previous": prev_summary,
                "changes":  changes,
                "ts":       now,
            }

            _previous[section_name] = summary

        _first_read = False

    return result


def read_observations() -> List[Dict[str, Any]]:
    """
    Flatten read_all() into a list of change observations:

    [
      {
        "ts":         float,
        "capability": str,
        "layer":      str,
        "field":      str,
        "kind":       "added" | "removed" | "changed",
        "from":       value | None,
        "to":         value | None,
      },
      ...
    ]
    """
    state = read_all()
    out: List[Dict[str, Any]] = []
    for capability in sorted(state.keys()):
        for layer_label in sorted(state[capability].keys()):
            entry = state[capability][layer_label]
            for change in entry["changes"]:
                out.append({
                    "ts":         entry["ts"],
                    "capability": capability,
                    "layer":      layer_label,
                    "field":      change["field"],
                    "kind":       change["kind"],
                    "from":       change["from"],
                    "to":         change["to"],
                })
    return out