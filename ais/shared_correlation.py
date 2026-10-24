#!/usr/bin/env python3
"""
ais/shared_correlation.py — cross-capability correlation layer.

Sits above the AIS workers. Consumes normalized group records from
every capability and emits correlated behaviors when records from
different capabilities participate in a defined relationship within
a bounded time window.

Responsibilities:
  - Maintain a durable window of correlation-eligible records.
  - Apply the seven relationship rules to that window.
  - Emit correlated behaviors with evidence preserved.
  - Never produce a scalar risk. Risk is Layer 2's own responsibility.

Ownership: AISEngine, once per cycle, after all workers have run.
Persistence: durable file. Not the Blackboard.

Relationship vocabulary (prototype, documented in the refactor doc):
  same_actor, same_user, same_target, actor_user_match,
  user_multi_actor, actor_multi_target, capability_transition

Windows per relationship are prototype values, not industry constants.
"""
import os
import sys
import json
import time
from typing import Dict, List, Optional, Tuple, Any

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config
from platform_utils import get_temp_dir

try:
    from event_emit import emit
except ImportError:
    def emit(src, layer, level, msg):
        ts = time.strftime("%H:%M:%S")
        print(f"[{ts}][{src}][{layer}][{level.upper()}] {msg}")

SRC = "shared_correlation"
LAYER = "layer2"

# Per-relationship windows, in seconds. Prototype values.
CORRELATION_WINDOWS: Dict[str, int] = {
    "same_actor":            300,
    "actor_user_match":      300,
    "actor_multi_target":    900,
    "same_user":             900,
    "user_multi_actor":      1800,
    "same_target":           1800,
    "capability_transition": 3600,
}

_MAX_RECORDS = 20000
_MAX_CORRELATED = 500
_RETENTION_SECONDS = max(CORRELATION_WINDOWS.values()) + 60


def _safe_str(v: Any, default: str = "") -> str:
    if isinstance(v, str):
        return v
    if v is None:
        return default
    return str(v)


def _safe_float(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _file_path() -> str:
    return os.path.join(get_temp_dir(), "acf_shared_correlation.json")


def _load() -> Dict:
    path = _file_path()
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return {"records": [], "correlated": []}
    except Exception as e:
        emit(SRC, LAYER, "warn",
             f"correlation state read failed: {type(e).__name__}: {e}")
        return {"records": [], "correlated": []}
    if not isinstance(data, dict):
        return {"records": [], "correlated": []}
    recs = data.get("records")
    cors = data.get("correlated")
    return {
        "records": recs if isinstance(recs, list) else [],
        "correlated": cors if isinstance(cors, list) else [],
    }


def _save(state: Dict) -> bool:
    path = _file_path()
    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(state, f, separators=(",", ":"))
            try:
                f.flush()
                os.fsync(f.fileno())
            except Exception:
                pass
        os.replace(tmp, path)
        return True
    except Exception as e:
        emit(SRC, LAYER, "warn",
             f"correlation state write failed: {type(e).__name__}: {e}")
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass
        return False


def _extract_record(capability: str, group: Dict) -> Optional[Dict]:
    if not isinstance(group, dict):
        return None
    actor = _safe_str(group.get("actor"), "")
    if not actor:
        return None
    actor_kind = _safe_str(group.get("actor_kind"), "")
    ts = _safe_float(group.get("last_seen"), 0.0)
    if ts <= 0.0:
        ts = _safe_float(group.get("first_seen"), 0.0)
    if ts <= 0.0:
        ts = time.time()
    users = group.get("users") or []
    if not isinstance(users, list):
        users = []
    sources = group.get("sources") or []
    if not isinstance(sources, list):
        sources = []
    target_ips = group.get("target_ips") or []
    if not isinstance(target_ips, list):
        target_ips = []
    return {
        "capability": capability,
        "actor": actor,
        "actor_kind": actor_kind,
        "users": [u for u in users if isinstance(u, str) and u],
        "sources": [s for s in sources if isinstance(s, str) and s],
        "target_ips": [t for t in target_ips if isinstance(t, str) and t],
        "ts": ts,
        "events_total": _safe_int(group.get("events_total"), 0),
    }


def _prune(records: List[Dict], now: float) -> List[Dict]:
    cutoff = now - _RETENTION_SECONDS
    kept = [r for r in records
            if isinstance(r, dict)
            and isinstance(r.get("ts"), (int, float))
            and r.get("ts") >= cutoff]
    if len(kept) > _MAX_RECORDS:
        kept = kept[-_MAX_RECORDS:]
    return kept


# ----------------------------------------------------------------------
# Relationship rules. Each returns a list of correlated-behavior dicts.
# ----------------------------------------------------------------------
def _rule_same_actor(records: List[Dict], now: float) -> List[Dict]:
    window = CORRELATION_WINDOWS["same_actor"]
    by_actor: Dict[str, List[Dict]] = {}
    for r in records:
        if now - r["ts"] > window:
            continue
        by_actor.setdefault(r["actor"], []).append(r)
    out = []
    for actor, rs in by_actor.items():
        caps = sorted({r["capability"] for r in rs})
        if len(caps) < 2:
            continue
        out.append({
            "relationship_type": "same_actor",
            "actor": actor,
            "user": None,
            "capabilities": caps,
            "first_seen": min(r["ts"] for r in rs),
            "last_seen": max(r["ts"] for r in rs),
            "evidence_count": len(rs),
            "reason": f"same actor across {len(caps)} capabilities",
        })
    return out


def _rule_same_user(records: List[Dict], now: float) -> List[Dict]:
    window = CORRELATION_WINDOWS["same_user"]
    by_user: Dict[str, List[Dict]] = {}
    for r in records:
        if now - r["ts"] > window:
            continue
        for u in r["users"]:
            by_user.setdefault(u, []).append(r)
    out = []
    for user, rs in by_user.items():
        caps = sorted({r["capability"] for r in rs})
        if len(caps) < 2:
            continue
        out.append({
            "relationship_type": "same_user",
            "actor": None,
            "user": user,
            "capabilities": caps,
            "first_seen": min(r["ts"] for r in rs),
            "last_seen": max(r["ts"] for r in rs),
            "evidence_count": len(rs),
            "reason": f"same user across {len(caps)} capabilities",
        })
    return out


def _rule_same_target(records: List[Dict], now: float) -> List[Dict]:
    window = CORRELATION_WINDOWS["same_target"]
    by_target: Dict[str, List[Dict]] = {}
    for r in records:
        if now - r["ts"] > window:
            continue
        for t in r["target_ips"]:
            by_target.setdefault(t, []).append(r)
    out = []
    for target, rs in by_target.items():
        caps = sorted({r["capability"] for r in rs})
        if len(caps) < 2:
            continue
        out.append({
            "relationship_type": "same_target",
            "actor": None,
            "user": None,
            "target": target,
            "capabilities": caps,
            "first_seen": min(r["ts"] for r in rs),
            "last_seen": max(r["ts"] for r in rs),
            "evidence_count": len(rs),
            "reason": f"same target across {len(caps)} capabilities",
        })
    return out


def _rule_actor_user_match(records: List[Dict], now: float) -> List[Dict]:
    window = CORRELATION_WINDOWS["actor_user_match"]
    by_pair: Dict[Tuple[str, str], List[Dict]] = {}
    for r in records:
        if now - r["ts"] > window:
            continue
        for u in r["users"]:
            by_pair.setdefault((r["actor"], u), []).append(r)
    out = []
    for (actor, user), rs in by_pair.items():
        caps = sorted({r["capability"] for r in rs})
        if len(caps) < 2:
            continue
        out.append({
            "relationship_type": "actor_user_match",
            "actor": actor,
            "user": user,
            "capabilities": caps,
            "first_seen": min(r["ts"] for r in rs),
            "last_seen": max(r["ts"] for r in rs),
            "evidence_count": len(rs),
            "reason": f"same actor+user across {len(caps)} capabilities",
        })
    return out


def _rule_user_multi_actor(records: List[Dict], now: float) -> List[Dict]:
    window = CORRELATION_WINDOWS["user_multi_actor"]
    by_user: Dict[str, List[Dict]] = {}
    for r in records:
        if now - r["ts"] > window:
            continue
        for u in r["users"]:
            by_user.setdefault(u, []).append(r)
    out = []
    for user, rs in by_user.items():
        actors = sorted({r["actor"] for r in rs})
        if len(actors) < 2:
            continue
        out.append({
            "relationship_type": "user_multi_actor",
            "actor": None,
            "user": user,
            "actors": actors,
            "capabilities": sorted({r["capability"] for r in rs}),
            "first_seen": min(r["ts"] for r in rs),
            "last_seen": max(r["ts"] for r in rs),
            "evidence_count": len(rs),
            "reason": f"user targeted by {len(actors)} actors",
        })
    return out


def _rule_actor_multi_target(records: List[Dict], now: float) -> List[Dict]:
    window = CORRELATION_WINDOWS["actor_multi_target"]
    by_actor: Dict[str, List[Dict]] = {}
    for r in records:
        if now - r["ts"] > window:
            continue
        by_actor.setdefault(r["actor"], []).append(r)
    out = []
    for actor, rs in by_actor.items():
        targets = sorted({t for r in rs for t in r["target_ips"]})
        if len(targets) < 2:
            continue
        out.append({
            "relationship_type": "actor_multi_target",
            "actor": actor,
            "user": None,
            "targets": targets,
            "capabilities": sorted({r["capability"] for r in rs}),
            "first_seen": min(r["ts"] for r in rs),
            "last_seen": max(r["ts"] for r in rs),
            "evidence_count": len(rs),
            "reason": f"actor against {len(targets)} targets",
        })
    return out


def _rule_capability_transition(records: List[Dict], now: float) -> List[Dict]:
    window = CORRELATION_WINDOWS["capability_transition"]
    out = []
    for key_kind in ("actor", "user"):
        groups: Dict[str, List[Dict]] = {}
        if key_kind == "actor":
            for r in records:
                groups.setdefault(r["actor"], []).append(r)
        else:
            for r in records:
                for u in r["users"]:
                    groups.setdefault(u, []).append(r)
        for key, rs in groups.items():
            rs_sorted = sorted(rs, key=lambda r: r["ts"])
            for i in range(len(rs_sorted) - 1):
                a = rs_sorted[i]
                b = rs_sorted[i + 1]
                if a["capability"] == b["capability"]:
                    continue
                if b["ts"] - a["ts"] > window:
                    continue
                out.append({
                    "relationship_type": "capability_transition",
                    "actor": key if key_kind == "actor" else None,
                    "user": key if key_kind == "user" else None,
                    "from_capability": a["capability"],
                    "to_capability": b["capability"],
                    "capabilities": sorted({a["capability"],
                                             b["capability"]}),
                    "first_seen": a["ts"],
                    "last_seen": b["ts"],
                    "evidence_count": 2,
                    "reason": (f"{a['capability']} -> {b['capability']} "
                               f"within {window}s"),
                })
    return out


_RULES = (
    _rule_same_actor,
    _rule_same_user,
    _rule_same_target,
    _rule_actor_user_match,
    _rule_user_multi_actor,
    _rule_actor_multi_target,
    _rule_capability_transition,
)


class SharedCorrelation:
    """
    Owner of cross-capability correlation state. Instantiated once by
    AISEngine. Called once per engine cycle.
    """

    def __init__(self):
        self._state = _load()
        now = time.time()
        self._state["records"] = _prune(self._state["records"], now)
        self._state["correlated"] = [
            c for c in self._state["correlated"]
            if isinstance(c, dict)
            and isinstance(c.get("last_seen"), (int, float))
            and (now - c["last_seen"]) <= _RETENTION_SECONDS
        ][-_MAX_CORRELATED:]

    def update(self, per_capability_groups: Dict[str, Dict]) -> List[Dict]:
        now = time.time()

        new_records: List[Dict] = []
        for cap, groups in per_capability_groups.items():
            if not isinstance(groups, dict):
                continue
            for key in ("source_groups", "user_groups",
                        "source_user_groups", "target_groups"):
                for g in groups.get(key, []) or []:
                    rec = _extract_record(cap, g)
                    if rec is not None:
                        new_records.append(rec)

        self._state["records"].extend(new_records)
        self._state["records"] = _prune(self._state["records"], now)

        produced: List[Dict] = []
        for rule in _RULES:
            try:
                produced.extend(rule(self._state["records"], now))
            except Exception as e:
                emit(SRC, LAYER, "warn",
                     f"rule {rule.__name__} failed: "
                     f"{type(e).__name__}: {e}")

        for c in produced:
            c["generated_at"] = now

        self._state["correlated"].extend(produced)
        if len(self._state["correlated"]) > _MAX_CORRELATED:
            self._state["correlated"] = \
                self._state["correlated"][-_MAX_CORRELATED:]

        _save(self._state)

        if produced:
            types = sorted({c["relationship_type"] for c in produced})
            emit(SRC, LAYER, "info",
                 f"correlation cycle | records={len(self._state['records'])} "
                 f"produced={len(produced)} types={types}")

        return produced

    def snapshot(self) -> Dict:
        return {
            "records_count": len(self._state["records"]),
            "correlated_count": len(self._state["correlated"]),
            "correlated": self._state["correlated"][-_MAX_CORRELATED:],
            "windows": dict(CORRELATION_WINDOWS),
            "version": Config.SCHEMA_VERSION,
        }