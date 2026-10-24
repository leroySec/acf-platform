#!/usr/bin/env python3
"""
ais/behavior_classifier.py — SME behavior classifier extension.

The base classifier in ais_engine._classify_behavior handles
generic volume-based behaviors. This extension runs first. Each
detector returns (name, score) on match, or None to defer.

Documented industry references for the behavioral CHARACTERISTICS
each detector looks for:

  port_scan                     MITRE ATT&CK T1046
  remote_system_discovery_pattern  MITRE ATT&CK T1018
  focused_bruteforce            MITRE ATT&CK T1110.001 (base)
  multi_account_authentication_pattern
                                MITRE ATT&CK T1110.003 and
                                T1110.004 (ambiguous on
                                Windows Security telemetry)
  distributed_authentication_attack
                                MITRE ATT&CK T1110 (aggregate)
  slow_bruteforce               CrowdSec ssh-slow-bf scenario
                                family, fail2ban findtime
  login_success_after_failures  MITRE T1110 detection guidance:
                                failed-authentication correlation

Every THRESHOLD and every SCORE in this file is an ACF design
choice. The cited sources document what the behavior looks like
in principle; they do not prescribe the numeric values used here.

Technique labels ending in _pattern mean: the observed pattern is
consistent with the technique; the technique itself is not
confirmed.

Behaviors whose evidence is not reachable from a single host:

  ransomware_encryption    needs file-write burst rate
  outbound_exfiltration    needs outbound byte counters
  phishing                 evidence at mail layer, off-host
  scamming                 evidence at transaction layer, off-host
  e_commerce_fraud         evidence at application layer, off-host

The REQUIRED_EVIDENCE table is the contract between this
classifier and the pipeline above it. event_semantics declares the
abstract event type the behavior consumes; the coverage validator
in monitor_engine.py resolves the semantics to platform event IDs.
"""

import re
from typing import Any, Dict, List, Optional, Tuple


REQUIRED_EVIDENCE: Dict[str, Dict[str, Any]] = {

    # --- Base classifier outputs (declared for completeness) ------------
    "scan": {
        "implemented_by": "base_classifier",
        "event_types": ["network_connection"],
        "event_semantics": [],
        "required_properties": ["source_ip", "target_ip"],
        "raw_fields": ["src_ip", "dst_ip", "path", "ts"],
        "derived_features": ["distinct_target_ips", "window_seconds"],
        "group_kind": "source",
        "correlations": [],
        "time_context_seconds": 120,
        "config_prerequisites": ["firewall_logging"],
        "partial": True,
        "partial_kind": "benign_traffic_ambiguity",
        "partial_reason": (
            "Multi-target connection activity can also be produced "
            "by legitimate clients, monitoring, or software "
            "deployment. Confirmation requires endpoint evidence "
            "the host does not produce."
        ),
    },
    "multi_target_activity": {
        "implemented_by": "base_classifier",
        "event_types": ["network_connection"],
        "event_semantics": [],
        "required_properties": ["source_ip", "target_ip"],
        "raw_fields": ["src_ip", "dst_ip", "path", "ts"],
        "derived_features": ["distinct_target_ips", "window_seconds"],
        "group_kind": "source",
        "correlations": [],
        "time_context_seconds": 300,
        "config_prerequisites": ["firewall_logging"],
        "partial": True,
        "partial_kind": "benign_traffic_ambiguity",
        "partial_reason": (
            "Same limitation as scan: multi-target activity has "
            "benign explanations the host cannot rule out."
        ),
    },
    "high_volume_activity": {
        "implemented_by": "base_classifier",
        "event_types": ["authentication_event", "network_connection"],
        "event_semantics": [],
        "required_properties": ["timestamp"],
        "raw_fields": ["ts"],
        "derived_features": ["events_total"],
        "group_kind": "source",
        "correlations": [],
        "time_context_seconds": 300,
        "config_prerequisites": [],
        "partial": False,
        "partial_kind": "",
        "partial_reason": "",
    },
    "user_attacked_from_many_sources": {
        "implemented_by": "base_classifier",
        "event_types": ["authentication_event"],
        "event_semantics": ["authentication_failure"],
        "required_properties": ["user", "source_ip"],
        "raw_fields": ["user", "src_ip"],
        "derived_features": ["distinct_sources", "users"],
        "group_kind": "user",
        "correlations": [],
        "time_context_seconds": 1800,
        "config_prerequisites": ["audit_logon"],
        "partial": False,
        "partial_kind": "",
        "partial_reason": "",
    },
    "user_under_attack": {
        "implemented_by": "base_classifier",
        "event_types": ["authentication_event"],
        "event_semantics": ["authentication_failure"],
        "required_properties": ["user", "timestamp"],
        "raw_fields": ["user", "ts"],
        "derived_features": ["events_total", "users"],
        "group_kind": "user",
        "correlations": [],
        "time_context_seconds": 300,
        "config_prerequisites": ["audit_logon"],
        "partial": False,
        "partial_kind": "",
        "partial_reason": "",
    },
    "targeted_user_attack": {
        "implemented_by": "base_classifier",
        "event_types": ["authentication_event"],
        "event_semantics": ["authentication_failure"],
        "required_properties": ["user", "source_ip"],
        "raw_fields": ["user", "src_ip", "ts"],
        "derived_features": ["events_total", "users"],
        "group_kind": "source_user",
        "correlations": [],
        "time_context_seconds": 300,
        "config_prerequisites": ["audit_logon"],
        "partial": False,
        "partial_kind": "",
        "partial_reason": "",
    },
    "target_under_attack": {
        "implemented_by": "base_classifier",
        "event_types": ["network_connection"],
        "event_semantics": [],
        "required_properties": ["target_ip"],
        "raw_fields": ["dst_ip", "path", "ts"],
        "derived_features": ["events_total"],
        "group_kind": "target",
        "correlations": [],
        "time_context_seconds": 300,
        "config_prerequisites": [],
        "partial": True,
        "partial_kind": "benign_traffic_ambiguity",
        "partial_reason": (
            "High target activity can also come from legitimate "
            "clients, scanners with authorization, or health checks."
        ),
    },
    "focused_bruteforce": {
        "implemented_by": "base_classifier",
        "event_types": ["authentication_event"],
        "event_semantics": ["authentication_failure"],
        "required_properties": ["source_ip", "target_ip", "timestamp"],
        "raw_fields": ["src_ip", "dst_ip", "ts"],
        "derived_features": [
            "events_total",
            "distinct_target_ips",
            "window_seconds",
        ],
        "group_kind": "source",
        "correlations": [],
        "time_context_seconds": 300,
        "config_prerequisites": ["audit_logon"],
        "partial": True,
        "partial_kind": "benign_traffic_ambiguity",
        "partial_reason": (
            "Authentication failures against a single target can "
            "also come from misconfigured clients, expired "
            "credentials on scheduled tasks, or user error. "
            "Confirmation requires per-attempt credential "
            "evidence the host does not produce."
        ),
    },

    # --- Extension outputs ---------------------------------------------
    "port_scan": {
        "implemented_by": "extension",
        "event_types": ["network_connection"],
        "event_semantics": [],
        "required_properties": ["source_ip", "target_ip", "port"],
        "raw_fields": ["src_ip", "dst_ip", "dst_port", "path", "ts"],
        "derived_features": [
            "distinct_target_ports",
            "distinct_target_ips",
            "window_seconds",
        ],
        "group_kind": "source",
        "correlations": [],
        "time_context_seconds": 120,
        "config_prerequisites": ["firewall_logging"],
        "partial": False,
        "partial_kind": "",
        "partial_reason": "",
    },
    "remote_system_discovery_pattern": {
        "implemented_by": "extension",
        "event_types": ["network_connection"],
        "event_semantics": [],
        "required_properties": ["source_ip", "target_ip"],
        "raw_fields": ["src_ip", "dst_ip", "path", "ts"],
        "derived_features": [
            "distinct_target_ips",
            "window_seconds",
        ],
        "group_kind": "source",
        "correlations": [],
        "time_context_seconds": 120,
        "config_prerequisites": ["firewall_logging"],
        "partial": True,
        "partial_kind": "benign_traffic_ambiguity",
        "partial_reason": (
            "One source contacting many destinations can also be "
            "legitimate software distribution, backup, or "
            "monitoring. MITRE T1018 confirmation requires "
            "endpoint evidence of discovery utilities the host "
            "does not produce."
        ),
    },
    "multi_account_authentication_pattern": {
        "implemented_by": "extension",
        "event_types": ["authentication_event"],
        "event_semantics": ["authentication_failure"],
        "required_properties": ["source_ip", "user"],
        "raw_fields": ["src_ip", "user", "ts"],
        "derived_features": [
            "distinct_users",
            "window_seconds",
        ],
        "group_kind": "source",
        "correlations": [],
        "time_context_seconds": 300,
        "config_prerequisites": ["audit_logon"],
        "partial": True,
        "partial_kind": "technique_ambiguity",
        "partial_reason": (
            "The Windows Security channel carries usernames and "
            "outcomes, not password values. The observed pattern "
            "(one source, many usernames, short window) is "
            "consistent with both MITRE T1110.003 (Password "
            "Spraying) and T1110.004 (Credential Stuffing). The "
            "two cannot be distinguished without credential-pair "
            "evidence."
        ),
    },
    "slow_bruteforce": {
        "implemented_by": "extension",
        "event_types": ["authentication_event"],
        "event_semantics": ["authentication_failure"],
        "required_properties": ["source_ip", "timestamp"],
        "raw_fields": ["src_ip", "ts"],
        "derived_features": [
            "events_total",
            "window_seconds",
        ],
        "group_kind": "source",
        "correlations": [],
        "time_context_seconds": 900,
        "config_prerequisites": ["audit_logon"],
        "partial": True,
        "partial_kind": "window_too_short",
        "partial_reason": (
            "The AIS window is capped at 300 s by default. The "
            "behavior needs 900 s of history to observe sparse "
            "activity over a long window. Until the window is "
            "extended, this detector will not fire."
        ),
    },
    "distributed_authentication_attack": {
        "implemented_by": "extension",
        "event_types": ["authentication_event"],
        "event_semantics": ["authentication_failure"],
        "required_properties": ["source_ip", "target_ip"],
        "raw_fields": ["src_ip", "dst_ip", "ts"],
        "derived_features": [
            "distinct_sources",
            "events_total",
            "window_seconds",
        ],
        "group_kind": "target",
        "correlations": ["same_target_many_sources"],
        "time_context_seconds": 900,
        "config_prerequisites": ["audit_logon"],
        "partial": True,
        "partial_kind": "derived_feature_missing",
        "partial_reason": (
            "The grouper does not populate distinct_sources on "
            "target groups. Until the grouper is extended, this "
            "detector cannot fire."
        ),
    },
    "login_success_after_failures": {
        "implemented_by": "extension",
        "event_types": ["authentication_event"],
        "event_semantics": [
            "authentication_failure",
            "authentication_success",
        ],
        "required_properties": ["source_ip", "user", "event_id"],
        "raw_fields": ["src_ip", "user", "event_id", "ts"],
        "derived_features": ["classes", "window_seconds"],
        "group_kind": "source",
        "correlations": ["same_actor_group"],
        "time_context_seconds": 300,
        "config_prerequisites": ["audit_logon"],
        "partial": True,
        "partial_kind": "temporal_order_missing",
        "partial_reason": (
            "The group is keyed by (actor, direction), so "
            "same-actor is enforced by construction. Temporal "
            "ordering (failure-before-success) is not verified: "
            "the group carries per-class counts, not per-class "
            "timestamps. A group with both classes is reported "
            "regardless of order."
        ),
    },
    "privileged_account_targeted": {
        "implemented_by": "extension",
        "event_types": ["authentication_event"],
        "event_semantics": ["authentication_success"],
        "required_properties": ["user"],
        "raw_fields": ["user"],
        "derived_features": ["users"],
        "group_kind": "source",
        "correlations": [],
        "time_context_seconds": 300,
        "config_prerequisites": ["audit_logon"],
        "partial": False,
        "partial_kind": "",
        "partial_reason": "",
    },
}


# ======================================================================
# Safe coercion
# ======================================================================
def _safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _safe_float(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _classes_of(g: Dict) -> Dict:
    c = g.get("classes")
    return c if isinstance(c, dict) else {}


# ======================================================================
# Word-boundary matcher for privileged markers
# ======================================================================
_PRIVILEGED_MARKERS = (
    "administrator",
    "admin",
    "system",
    "root",
    "domain admin",
    "postgres",
    "mysql",
)
_PRIVILEGED_PATTERNS = [
    re.compile(r"\b" + re.escape(m) + r"\b", re.IGNORECASE)
    for m in _PRIVILEGED_MARKERS
]


# ======================================================================
# Compromise indicators — highest priority
# ======================================================================
def _detect_login_success_after_failures(
        g: Dict) -> Optional[Tuple[str, int]]:
    classes = _classes_of(g)
    if not classes:
        return None
    has_failure = "event:4625" in classes
    has_success = "event:4624" in classes
    if has_failure and has_success:
        return "login_success_after_failures", 75
    return None


def _detect_privileged_account_targeted(
        g: Dict) -> Optional[Tuple[str, int]]:
    users = g.get("users") or []
    if not isinstance(users, list):
        return None
    for u in users:
        if not isinstance(u, str):
            continue
        for pat in _PRIVILEGED_PATTERNS:
            if pat.search(u):
                return "privileged_account_targeted", 25
    return None


# ======================================================================
# Reconnaissance
# ======================================================================
def _detect_port_scan(g: Dict) -> Optional[Tuple[str, int]]:
    if g.get("actor_kind") != "ip":
        return None
    ports = _safe_int(g.get("distinct_target_ports"), 0)
    ips = _safe_int(g.get("distinct_target_ips"), 0)
    w = _safe_float(g.get("window_seconds"), 0.0)
    if ports >= 10 and ips <= 2 and 0 < w <= 120:
        return "port_scan", min(100, 50 + ports)
    return None


def _detect_remote_system_discovery_pattern(
        g: Dict) -> Optional[Tuple[str, int]]:
    if g.get("actor_kind") != "ip":
        return None
    ips = _safe_int(g.get("distinct_target_ips"), 0)
    w = _safe_float(g.get("window_seconds"), 0.0)
    if ips >= 10 and 0 < w <= 120:
        return "remote_system_discovery_pattern", min(100, 50 + ips)
    return None


# ======================================================================
# Credential attacks
# ======================================================================
def _detect_multi_account_authentication_pattern(
        g: Dict) -> Optional[Tuple[str, int]]:
    if g.get("actor_kind") != "ip":
        return None
    users = _safe_int(g.get("distinct_users"), 0)
    w = _safe_float(g.get("window_seconds"), 0.0)
    if users >= 5 and 0 < w <= 300:
        return "multi_account_authentication_pattern", min(100, 45 + users)
    return None


def _detect_slow_bruteforce(g: Dict) -> Optional[Tuple[str, int]]:
    if g.get("actor_kind") != "ip":
        return None
    n = _safe_int(g.get("events_total"), 0)
    w = _safe_float(g.get("window_seconds"), 0.0)
    if 3 <= n <= 10 and w > 900:
        return "slow_bruteforce", min(100, 40 + n * 2)
    return None


def _detect_distributed_authentication_attack(
        g: Dict) -> Optional[Tuple[str, int]]:
    if g.get("actor_kind") != "target":
        return None
    sources = _safe_int(g.get("distinct_sources"), 0)
    w = _safe_float(g.get("window_seconds"), 0.0)
    if sources >= 5 and 0 < w <= 900:
        return "distributed_authentication_attack", min(100, 40 + sources * 3)
    return None


_DETECTORS = (
    _detect_login_success_after_failures,
    _detect_privileged_account_targeted,
    _detect_port_scan,
    _detect_remote_system_discovery_pattern,
    _detect_multi_account_authentication_pattern,
    _detect_slow_bruteforce,
    _detect_distributed_authentication_attack,
)


def classify_sme_behaviors(
        group: Dict) -> Optional[Tuple[str, int]]:
    if not isinstance(group, dict):
        return None
    for fn in _DETECTORS:
        try:
            result = fn(group)
        except Exception:
            continue
        if result is not None:
            return result
    return None


if __name__ == "__main__":
    print("=" * 64)
    print("  SME behavior classifier — self test")
    print("=" * 64)
    print()

    ext_count = sum(1 for s in REQUIRED_EVIDENCE.values()
                    if s["implemented_by"] == "extension")
    base_count = sum(1 for s in REQUIRED_EVIDENCE.values()
                     if s["implemented_by"] == "base_classifier")
    partial_count = sum(1 for s in REQUIRED_EVIDENCE.values()
                        if s.get("partial"))
    print(f"REQUIRED_EVIDENCE entries: {len(REQUIRED_EVIDENCE)}")
    print(f"  extension outputs       : {ext_count}")
    print(f"  base classifier outputs : {base_count}")
    print(f"  partial coverage        : {partial_count}")
    print()

    print("Behaviors declaring event_semantics:")
    for name, spec in REQUIRED_EVIDENCE.items():
        sem = spec.get("event_semantics", [])
        if sem:
            print(f"  {name}: {sem}")
    print()

    samples = [
        ("port_scan", {
            "actor_kind": "ip", "actor": "1.2.3.4",
            "distinct_target_ports": 25, "distinct_target_ips": 1,
            "window_seconds": 45.0, "events_total": 30,
            "classes": {},
        }),
        ("login_success_after_failures", {
            "actor_kind": "ip", "actor": "9.9.9.9",
            "classes": {"event:4625": 5, "event:4624": 1},
            "window_seconds": 120.0, "events_total": 6,
        }),
        ("privileged_account_targeted (Administrator)", {
            "actor_kind": "ip", "actor": "10.0.0.5",
            "users": ["Administrator"],
            "events_total": 3, "window_seconds": 60.0,
        }),
        ("privileged_account_targeted (sam — should NOT match)", {
            "actor_kind": "ip", "actor": "10.0.0.6",
            "users": ["sam"],
            "events_total": 3, "window_seconds": 60.0,
        }),
        ("no match", {
            "actor_kind": "ip", "actor": "1.1.1.1",
            "events_total": 1, "window_seconds": 5.0,
        }),
    ]

    for label, g in samples:
        r = classify_sme_behaviors(g)
        print(f"--- {label} ---")
        print(f"  result: {r}")
        print()