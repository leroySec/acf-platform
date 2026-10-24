#!/usr/bin/env python3
"""
ais/grouper.py — Group detection records into analytical populations.

Reads detection records from layer_1_monitor_<cap>. Returns group
structures keyed by actor (source, user, target).

Stateless. Every call processes the detections passed in. State
(baselines, threat memory) stays in the AIS.

Grouping dimensions produced:
  source_groups       — one per (actor, direction)
  user_groups         — one per user (when the source provides a user)
  source_user_groups  — one per (source, user) pair
  target_groups       — one per destination host
  cross_source_by_user — users seen from multiple sources

FIX-3: target is stored as (host, port) separately. Groups now
carry distinct_target_ips and distinct_target_ports rather than
a mixed IP/IP:port string count.
"""

import time
from typing import Any, Dict, List, Optional, Tuple


SCHEMA_VERSION = "1.0"

# Placeholder values treated as missing.
_PLACEHOLDERS = frozenset({"-", "", "0.0.0.0", "::", "N/A"})


def _clean(value: Any) -> Optional[str]:
    """Return None for placeholder values, the string otherwise."""
    if value is None:
        return None
    if not isinstance(value, str):
        try:
            value = str(value)
        except Exception:
            return None
    value = value.strip()
    if value in _PLACEHOLDERS:
        return None
    return value


def _extract_source(event: Dict) -> Optional[str]:
    """Return the actor IP for the event, or None."""
    path = _clean(event.get("path"))
    if path in ("SEND", "RECEIVE"):
        return _clean(event.get("src_ip"))
    ips = event.get("ips")
    if isinstance(ips, list):
        for ip in ips:
            c = _clean(ip)
            if c:
                return c
    return _clean(event.get("src_ip"))


# FIX-3: return (host, port) separately, not a combined string.
def _extract_target(event: Dict) -> Tuple[Optional[str], Optional[str]]:
    """Return (target_host, target_port), each or both possibly None."""
    path = _clean(event.get("path"))
    if path == "SEND":
        # Firewall SEND: target is the remote host
        return _clean(event.get("dst_ip")), _clean(event.get("dst_port"))
    if path == "RECEIVE":
        # Firewall RECEIVE: target is the local host; port is local port
        return _clean(event.get("dst_ip")), _clean(event.get("dst_port"))
    return None, None


def _extract_user(event: Dict) -> Optional[str]:
    """Return the user identity for the event, or None."""
    return _clean(event.get("user"))


def _extract_class(event: Dict) -> str:
    """The class of the event, used for counting."""
    c = _clean(event.get("class"))
    if c:
        return c
    a = _clean(event.get("action"))
    if a:
        return a
    eid = event.get("event_id")
    if eid is not None:
        return f"event:{eid}"
    return "unknown"


def _extract_ts(event: Dict) -> Optional[float]:
    """Event time as a float epoch, if derivable."""
    ts = event.get("ts")
    if isinstance(ts, (int, float)):
        return float(ts)
    return None


def _bump(counter: Dict[str, int], key: str) -> None:
    counter[key] = counter.get(key, 0) + 1


def _finalize_group(actor: str,
                     actor_kind: str,
                     direction: Optional[str],
                     events: List[Dict],
                     classes: Dict[str, int],
                     target_ips: set,
                     target_ports: set,
                     users: set,
                     sources: set,
                     first_seen: Optional[float],
                     last_seen: Optional[float],
                     directions: Optional[List[str]] = None) -> Dict:
    window = None
    if first_seen is not None and last_seen is not None:
        window = round(last_seen - first_seen, 3)
    group = {
        "actor": actor,
        "actor_kind": actor_kind,
        "events_total": len(events),
        "classes": dict(classes),
        "first_seen": first_seen,
        "last_seen": last_seen,
        "window_seconds": window,
    }
    if direction:
        group["direction"] = direction
    if directions:
        group["directions"] = directions
    if target_ips:
        group["distinct_target_ips"] = len(target_ips)
        group["target_ips"] = sorted(target_ips)[:20]
        # Backward-compatible alias: distinct_destinations now equals
        # the number of distinct target IPs. It no longer counts
        # (IP, port) pairs.
        group["distinct_destinations"] = len(target_ips)
    if target_ports:
        group["distinct_target_ports"] = len(target_ports)
        group["target_ports"] = sorted(target_ports)[:20]
    if users:
        group["distinct_users"] = len(users)
        group["users"] = sorted(users)[:20]
    if sources:
        group["distinct_sources"] = len(sources)
        group["sources"] = sorted(sources)[:20]
    return group


def group_detections(capability: str,
                     detections: List[Dict],
                     now: Optional[float] = None) -> Dict:
    """
    Group detections into analytical populations.

    Parameters
    ----------
    capability : str
    detections : list of dicts, each a detection record
    now : float, current time (defaults to time.time())

    Returns
    -------
    dict with keys:
        capability, generated_at, input_count,
        source_groups, user_groups, source_user_groups,
        target_groups, cross_source_by_user,
        version
    """
    if now is None:
        now = time.time()

    if not isinstance(detections, list):
        detections = []

    # --- per-actor accumulators ---
    by_source: Dict[Tuple[str, Optional[str]], Dict] = {}
    by_user: Dict[str, Dict] = {}
    by_source_user: Dict[str, Dict] = {}
    by_target: Dict[str, Dict] = {}

    # Track sources per user for cross-source correlation.
    user_to_sources: Dict[str, set] = {}

    for event in detections:
        if not isinstance(event, dict):
            continue

        source = _extract_source(event)
        target_ip, target_port = _extract_target(event)
        user = _extract_user(event)
        cls = _extract_class(event)
        ts = _extract_ts(event)
        direction = _clean(event.get("path"))

        # --- source group (FIX-2: key by (source, direction)) ---
        if source:
            key = (source, direction)
            bucket = by_source.setdefault(key, {
                "events": [],
                "classes": {},
                "target_ips": set(),
                "target_ports": set(),
                "users": set(),
                "first": None,
                "last": None,
                "directions": set(),
            })
            if direction:
                bucket["directions"].add(direction)
            bucket["events"].append(event)
            _bump(bucket["classes"], cls)
            if target_ip:
                bucket["target_ips"].add(target_ip)
            if target_port:
                bucket["target_ports"].add(target_port)
            if user:
                bucket["users"].add(user)
            if ts is not None:
                if bucket["first"] is None or ts < bucket["first"]:
                    bucket["first"] = ts
                if bucket["last"] is None or ts > bucket["last"]:
                    bucket["last"] = ts

        # --- user group ---
        if user:
            bucket = by_user.setdefault(user, {
                "events": [],
                "classes": {},
                "sources": set(),
                "first": None,
                "last": None,
            })
            bucket["events"].append(event)
            _bump(bucket["classes"], cls)
            if source:
                bucket["sources"].add(source)
                user_to_sources.setdefault(user, set()).add(source)
            if ts is not None:
                if bucket["first"] is None or ts < bucket["first"]:
                    bucket["first"] = ts
                if bucket["last"] is None or ts > bucket["last"]:
                    bucket["last"] = ts

        # --- source+user group ---
        if source and user:
            key = f"{source}::{user}"
            bucket = by_source_user.setdefault(key, {
                "events": [],
                "classes": {},
                "first": None,
                "last": None,
            })
            bucket["events"].append(event)
            _bump(bucket["classes"], cls)
            if ts is not None:
                if bucket["first"] is None or ts < bucket["first"]:
                    bucket["first"] = ts
                if bucket["last"] is None or ts > bucket["last"]:
                    bucket["last"] = ts

        # --- target group (keyed by target IP host) ---
        if target_ip:
            bucket = by_target.setdefault(target_ip, {
                "events": [],
                "classes": {},
                "target_ports": set(),
                "first": None,
                "last": None,
            })
            bucket["events"].append(event)
            _bump(bucket["classes"], cls)
            if target_port:
                bucket["target_ports"].add(target_port)
            if ts is not None:
                if bucket["first"] is None or ts < bucket["first"]:
                    bucket["first"] = ts
                if bucket["last"] is None or ts > bucket["last"]:
                    bucket["last"] = ts

    # --- finalize ---
    source_groups = [
        _finalize_group(
            actor=key[0],
            actor_kind="ip",
            direction=(sorted(b["directions"])[0]
                       if len(b["directions"]) == 1 else None),
            events=b["events"],
            classes=b["classes"],
            target_ips=b["target_ips"],
            target_ports=b["target_ports"],
            users=b["users"],
            sources=set(),
            first_seen=b["first"],
            last_seen=b["last"],
            directions=list(sorted(b["directions"])),
        )
        for key, b in by_source.items()
    ]

    user_groups = [
        _finalize_group(
            actor=usr,
            actor_kind="user",
            direction=None,
            events=b["events"],
            classes=b["classes"],
            target_ips=set(),
            target_ports=set(),
            users=set(),
            sources=b["sources"],
            first_seen=b["first"],
            last_seen=b["last"],
        )
        for usr, b in by_user.items()
    ]

    source_user_groups = [
        _finalize_group(
            actor=key,
            actor_kind="source_user",
            direction=None,
            events=b["events"],
            classes=b["classes"],
            target_ips=set(),
            target_ports=set(),
            users=set(),
            sources=set(),
            first_seen=b["first"],
            last_seen=b["last"],
        )
        for key, b in by_source_user.items()
    ]

    target_groups = [
        _finalize_group(
            actor=tgt_ip,
            actor_kind="target",
            direction=None,
            events=b["events"],
            classes=b["classes"],
            target_ips={tgt_ip},
            target_ports=b["target_ports"],
            users=set(),
            sources=set(),
            first_seen=b["first"],
            last_seen=b["last"],
        )
        for tgt_ip, b in by_target.items()
    ]

    # --- cross-source correlation by user ---
    cross_source_by_user = []
    for usr, sources in user_to_sources.items():
        if len(sources) > 1:
            cross_source_by_user.append({
                "user": usr,
                "sources": sorted(sources),
                "source_count": len(sources),
            })

    return {
        "capability": capability,
        "generated_at": now,
        "input_count": len(detections),
        "source_groups": source_groups,
        "user_groups": user_groups,
        "source_user_groups": source_user_groups,
        "target_groups": target_groups,
        "cross_source_by_user": cross_source_by_user,
        "version": SCHEMA_VERSION,
    }