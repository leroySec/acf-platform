#!/usr/bin/env python
"""
ais/ais_engine.py — Layer 2 threat-analysis engine (unified, capability-agnostic).
One process. Many capabilities. Uniform output.

REVISION: grouper + temporal memory + behavior scoring + actor filtering.

  Fix 4: SEND-direction source groups are not promoted to attacker_ip.
  Fix 5: loopback and link-local addresses are not promoted to attacker_ip.
  Fix 6: AIS keeps a rolling window of detections across cycles. The
         grouper is called on the window, not just the current batch.
  Fix 7: per-group behavior classification. Risk is computed from
         behavior scores, not from one generic confidence formula.

Item 2: the AIS window is durable across process restarts. It lives in
        a per-capability file outside the Blackboard, same pattern as
        the reader marker. Written once per cycle, pruned on load.

Item 3: cross-capability correlation. A single SharedCorrelation owner
        is instantiated by AISEngine and called once per engine cycle
        after all workers have run.

Item 4: threat memory is keyed by (actor, user). Network-only
        observations use (actor, None). The legacy "ip" field is kept
        as an alias so the response engine's fail2ban sweep is
        unaffected.

Item 5 support: cross_source_by_user entries are annotated with the
        Layer 2 behavior name, score, and evidence timestamps before
        they are written to the Blackboard.

Classifier extension:
  The SME behavior classifier lives in ais/behavior_classifier.py.
  It runs as a pre-classifier. On a match it returns (name, score)
  and the base classifier is skipped for that group. If the
  extension module is missing or the group does not match, the
  base classifier is called. The extension is additive.

Reliability fixes:
  R1: _last_groups is reset at the start of every run_cycle.
  R2: synthetic detections carry a unique synthetic_uid.
  R3: THREAT_MAX_AGE_SECONDS bounds threat memory by absolute age.

PRIMARY-INSTANCE GUARD:
  The orchestrator spawns this engine once per capability assigned to
  layer2. Only one instance is the "primary" and runs the engine loop.
  The primary is the instance whose sys.argv[1] matches the first
  capability (alphabetically) in the current layer2 assignment.
  All other instances sleep in a light loop. If the primary dies, the
  orchestrator respawns it and it re-takes the primary role. If the
  config changes and a different capability becomes alphabetically
  first, the matching running instance takes over on its next cycle.

Unchanged:
  - resource_factor, sensitivity_multiplier, criticality_factor
  - baseline persistence
  - detector_stats
  - section names (layer_2_ais_<cap>, layer_2_groups_<cap>)
"""
import os
import sys
import json
import time
import signal
from typing import Dict, List, Any, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config
from platform_utils import acquire_lock, release_lock, get_temp_dir
from ais.grouper import group_detections
from ais.shared_correlation import SharedCorrelation

try:
    from ais.behavior_classifier import classify_sme_behaviors
    _SME_EXTENSIONS_AVAILABLE = True
except ImportError:
    _SME_EXTENSIONS_AVAILABLE = False

    def classify_sme_behaviors(group):
        return None

try:
    from event_emit import emit
except ImportError:
    def emit(src, layer, level, msg, capability=None, cycle=None):
        ts = time.strftime("%H:%M:%S")
        print(f"[{ts}][{src}][{layer}][{level.upper()}] {msg}")

SRC = "ais_engine"
LAYER = "layer2"

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYSTEM_CONFIG_FILE = os.path.join(ROOT, "system_config.json")
BLACKBOARD_FILE = Config.BLACKBOARD_FILE
HEARTBEAT_FILE = os.path.join(get_temp_dir(), "acf_ais_engine.heartbeat")

BASE_CYCLE_SECONDS = 10
MIN_CYCLE_SECONDS = 3
MAX_CYCLE_SECONDS = 30

UPSTREAM_FRESH_SECONDS = 30
READER_FRESH_SECONDS = 30
RESOURCE_FRESH_SECONDS = 60

SEVERITY_WEIGHT = {"low": 5, "medium": 15, "high": 35, "critical": 60}
DEFAULT_SEVERITY_WEIGHT = 15

MAX_SYNTHETIC_DETECTIONS = 50
MAX_THREATS = 100
CONFIDENCE_THRESHOLD = 30
RETENTION_SECONDS = 600

THREAT_MAX_AGE_SECONDS = 3600

HITS_WEIGHT = 10
SEVERITY_BONUS = {"low": 0, "medium": 10, "high": 30, "critical": 50}
DEFAULT_SEVERITY_BONUS = 10

STATE_RANK = {"GREEN": 0, "YELLOW": 1, "ORANGE": 2, "RED": 3}

UPSTREAM_SECTIONS = {
    "sensor": ["layer_1_monitor_sensor", "layer_1_sensor_ext"],
}

WINDOW_MAX_SECONDS = 300.0
WINDOW_MAX_ITEMS = 5000

_LOOPBACK_PREFIXES = ("127.",)
_LINKLOCAL_PREFIXES = ("169.254.", "fe80:")
_UNSPECIFIED = ("0.0.0.0", "::")

_running = True
_last_cycle_time = time.time()


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
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


def _safe_str(v: Any, default: str = "") -> str:
    if isinstance(v, str):
        return v
    if v is None:
        return default
    return str(v)


def _bb_read() -> Dict:
    try:
        with open(BLACKBOARD_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return {}


def _bb_read_section(section: str) -> Dict:
    data = _bb_read()
    s = data.get(section, {})
    return s if isinstance(s, dict) else {}


def _bb_update(section: str, updates: Dict) -> bool:
    try:
        with open(BLACKBOARD_FILE, 'r+') as f:
            acquire_lock(f.fileno(), exclusive=True)
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = {}
            if section not in data or not isinstance(data[section], dict):
                data[section] = {}
            data[section].update(updates)
            f.seek(0)
            json.dump(data, f, indent=2)
            f.truncate()
            release_lock(f.fileno())
            return True
    except Exception as e:
        emit(SRC, LAYER, "error", f"Blackboard update for {section}: {e}")
        return False


def load_config() -> Dict:
    try:
        with open(SYSTEM_CONFIG_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        emit(SRC, LAYER, "error", f"config load failed: {e}")
        return {}


def _read_disabled_map() -> Dict[str, List[str]]:
    try:
        with open(BLACKBOARD_FILE, 'r') as f:
            disabled = json.load(f).get("disabled_capabilities", {})
    except Exception:
        return {}
    if isinstance(disabled, list):
        return {cap: ["*"] for cap in disabled}
    if isinstance(disabled, dict):
        out = {}
        for cap, layers in disabled.items():
            if isinstance(layers, list):
                out[cap] = layers
            elif layers is True:
                out[cap] = ["*"]
        return out
    return {}


def _pair_disabled(disabled_map: Dict, capability: str, layer: str) -> bool:
    entry = disabled_map.get(capability)
    if not entry:
        return False
    if "*" in entry:
        return True
    return layer in entry


def _capabilities_for_layer(config: Dict, layer: str) -> List[str]:
    capability_layers = config.get("capability_layers", {})
    if not isinstance(capability_layers, dict):
        return []
    return [
        name for name, layers in capability_layers.items()
        if isinstance(layers, list) and layer in layers
    ]


def _upstream_candidates(capability: str) -> List[str]:
    if capability in UPSTREAM_SECTIONS:
        return list(UPSTREAM_SECTIONS[capability])
    return [f"layer_1_monitor_{capability}"]


def _read_state(capability: str) -> str:
    section = _bb_read_section(f"layer_3_state_{capability}")
    if not section:
        return "GREEN"
    s = section.get("state")
    if not isinstance(s, str):
        return "GREEN"
    s = s.strip().upper()
    if s not in STATE_RANK:
        return "GREEN"
    return s


def _resolve_criticality(capability: str, config: Dict) -> float:
    def _coerce(value):
        try:
            f = float(value)
        except (TypeError, ValueError):
            return None
        if f < 0.0 or f > 1.0:
            return None
        return f

    override = config.get("capability_criticality", {})
    if isinstance(override, dict) and capability in override:
        v = _coerce(override[capability])
        if v is not None:
            return v

    builtin = getattr(Config, "CAPABILITY_CRITICALITY", {})
    if isinstance(builtin, dict) and capability in builtin:
        v = _coerce(builtin[capability])
        if v is not None:
            return v

    v = _coerce(getattr(Config, "DEFAULT_CAPABILITY_CRITICALITY", 0.5))
    return v if v is not None else 0.5


def _weighted_sum(detections: List[Dict]) -> int:
    total = 0
    for d in detections:
        if not isinstance(d, dict):
            continue
        sev = d.get("severity", "medium")
        weight = SEVERITY_WEIGHT.get(sev, DEFAULT_SEVERITY_WEIGHT)
        total += weight
    return total


# ----------------------------------------------------------------------
# FIX-4 / FIX-5: actor promotion filter
# ----------------------------------------------------------------------
def _is_promotable_actor(group: Dict) -> bool:
    ip = group.get("actor")
    if not isinstance(ip, str) or not ip:
        return False
    if ip in _UNSPECIFIED:
        return False
    for prefix in _LOOPBACK_PREFIXES:
        if ip.startswith(prefix):
            return False
    if ip == "::1":
        return False
    for prefix in _LINKLOCAL_PREFIXES:
        if ip.startswith(prefix):
            return False

    dirs = group.get("directions")
    if isinstance(dirs, list):
        if "SEND" in dirs and "RECEIVE" not in dirs:
            return False
    return True


# ----------------------------------------------------------------------
# FIX-7: behavior classification
# ----------------------------------------------------------------------
def _classify_behavior(group: Dict) -> Tuple[str, int]:
    kind = group.get("actor_kind", "")
    n = _safe_int(group.get("events_total"), 0)
    w = _safe_float(group.get("window_seconds"), 0.0)
    ips = _safe_int(group.get("distinct_target_ips"), 0)
    users = _safe_int(group.get("distinct_users"), 0)
    sources = _safe_int(group.get("distinct_sources"), 0)

    if n <= 0:
        return "empty", 0

    if kind == "ip":
        if ips >= 10 and 0 < w <= 120:
            return "scan", min(100, 50 + ips)
        if ips >= 5 and 0 < w <= 300:
            return "multi_target_activity", min(100, 30 + ips)
        if users >= 5 and 0 < w <= 300:
            return "password_spray", min(100, 40 + users)
        if n >= 10 and ips <= 2 and 0 < w <= 300:
            return "focused_bruteforce", min(100, 30 + n)
        if n >= 30:
            return "high_volume_activity", min(100, 25 + n // 4)
        return "low_source_activity", min(20, n)

    if kind == "user":
        if sources >= 3:
            return "user_attacked_from_many_sources", min(100, 40 + sources * 5)
        if n >= 5:
            return "user_under_attack", min(100, 25 + n)
        return "user_observed", min(15, n)

    if kind == "source_user":
        if n >= 5:
            return "targeted_user_attack", min(100, 30 + n)
        return "pair_observed", min(15, n)

    if kind == "target":
        if n >= 10:
            return "target_under_attack", min(100, 30 + n)
        return "target_observed", min(15, n)

    return "unknown", 0


def _classify_behavior_extended(group: Dict) -> Tuple[str, int]:
    """
    The classifier the engine actually calls.

    Runs the SME behavior detectors first (ais/behavior_classifier.py).
    On match, returns the extension's (name, score). Otherwise defers
    to the base classifier _classify_behavior. If the extension module
    is not importable, behaves exactly as the base.

    The extension is additive: it never overrides a group that it does
    not recognize, and a failure inside the extension falls through to
    the base rather than breaking the cycle.
    """
    if _SME_EXTENSIONS_AVAILABLE and isinstance(group, dict):
        try:
            r = classify_sme_behaviors(group)
        except Exception:
            r = None
        if r is not None:
            return r
    return _classify_behavior(group)


def _collect_groups(groups: Dict) -> List[Dict]:
    all_groups: List[Dict] = []
    for key in ("source_groups", "user_groups",
                "source_user_groups", "target_groups"):
        lst = groups.get(key, [])
        if isinstance(lst, list):
            all_groups.extend(lst)
    return all_groups


def _compute_risk_from_groups(groups: Dict,
                              baseline: float,
                              criticality_factor: float,
                              resource_factor: float,
                              sensitivity_multiplier: float
                              ) -> Tuple[int, float, Dict]:
    all_groups = _collect_groups(groups)

    if not all_groups:
        new_baseline = baseline * 0.8
        if new_baseline < 1.0:
            new_baseline = 0.0
        return 0, new_baseline, {
            "groups_total": 0,
            "groups_above_threshold": 0,
            "max_behavior_score": 0,
            "behaviors": {},
        }

    behaviors: Dict[str, int] = {}
    high_scores: List[int] = []
    max_below = 0

    for g in all_groups:
        b, s = _classify_behavior_extended(g)
        if s <= 0:
            continue
        if s >= CONFIDENCE_THRESHOLD:
            high_scores.append(s)
            behaviors[b] = max(behaviors.get(b, 0), s)
        else:
            if s > max_below:
                max_below = s

    if not high_scores:
        risk = int(min(CONFIDENCE_THRESHOLD - 1, max_below * 0.5))
        signal = float(max_below)
        if baseline <= 0:
            new_baseline = signal
        else:
            new_baseline = 0.8 * baseline + 0.2 * signal
        return risk, new_baseline, {
            "groups_total": len(all_groups),
            "groups_above_threshold": 0,
            "max_behavior_score": int(max_below),
            "behaviors": {},
        }

    base = float(len(high_scores)) * 15.0
    max_score = max(high_scores)
    final_risk = (base + float(max_score)) * criticality_factor \
        * resource_factor * sensitivity_multiplier
    risk = int(min(100.0, final_risk))

    signal = float(sum(high_scores))
    if baseline <= 0:
        new_baseline = signal
    else:
        new_baseline = 0.8 * baseline + 0.2 * signal

    summary = {
        "groups_total": len(all_groups),
        "groups_above_threshold": len(high_scores),
        "max_behavior_score": int(max_score),
        "behaviors": behaviors,
    }
    return risk, new_baseline, summary


# ----------------------------------------------------------------------
# FEEDBACK and helper detection synthesis
# ----------------------------------------------------------------------
def _detector_stats_from_detections(detections: List[Dict],
                                     previous: Dict[str, Dict]) -> Dict[str, Dict]:
    stats = {k: dict(v) for k, v in previous.items() if isinstance(v, dict)}
    now = time.time()
    for d in detections:
        if not isinstance(d, dict):
            continue
        cls = d.get("class", "unknown")
        if not isinstance(cls, str):
            cls = "unknown"
        entry = stats.setdefault(cls, {"hits": 0, "last_ts": 0.0})
        entry["hits"] = _safe_int(entry.get("hits"), 0) + 1
        entry["last_ts"] = now
    return stats


def _severity_bonus(severity: str) -> int:
    return SEVERITY_BONUS.get(severity, DEFAULT_SEVERITY_BONUS)


def _per_detection_gain(severity: str) -> int:
    return HITS_WEIGHT + _severity_bonus(severity)


# ----------------------------------------------------------------------
# ITEM 4 — threat memory keyed by (actor, user)
# ----------------------------------------------------------------------
def _update_threats_from_groups(known: List[Dict],
                                groups: Dict,
                                now: float) -> List[Dict]:
    index: Dict[Tuple[str, Optional[str]], Dict] = {}

    for entry in known:
        if not isinstance(entry, dict):
            continue
        actor = entry.get("actor") or entry.get("ip")
        if not isinstance(actor, str) or not actor:
            continue
        user = entry.get("user")
        if not isinstance(user, str) or not user:
            user = None
        key = (actor, user)
        index[key] = {
            "actor": actor,
            "user": user,
            "ip": actor,
            "first_seen": _safe_float(entry.get("first_seen"), now),
            "last_seen": _safe_float(entry.get("last_seen"), 0.0),
            "hits": _safe_int(entry.get("hits"), 0),
            "confidence": _safe_int(entry.get("confidence"), 0),
        }

    def _advance(actor: str, user: Optional[str],
                 hits: int, score: int) -> None:
        key = (actor, user)
        if key in index:
            e = index[key]
            e["hits"] += hits
            e["last_seen"] = now
            e["confidence"] = min(100, e["confidence"] + score)
        else:
            index[key] = {
                "actor": actor,
                "user": user,
                "ip": actor,
                "first_seen": now,
                "last_seen": now,
                "hits": hits,
                "confidence": min(100, score),
            }

    for g in groups.get("source_groups", []) or []:
        if not isinstance(g, dict):
            continue
        if not _is_promotable_actor(g):
            continue
        actor = g.get("actor")
        if not isinstance(actor, str) or not actor:
            continue
        _, score = _classify_behavior_extended(g)
        if score < CONFIDENCE_THRESHOLD:
            continue
        hits = _safe_int(g.get("events_total"), 0)
        users = g.get("users") or []
        users = [u for u in users if isinstance(u, str) and u]
        if users:
            per_user = max(1, hits // len(users))
            for u in users:
                _advance(actor, u, per_user, score)
        else:
            _advance(actor, None, hits, score)

    for g in groups.get("source_user_groups", []) or []:
        if not isinstance(g, dict):
            continue
        actor_str = g.get("actor")
        if not isinstance(actor_str, str) or "::" not in actor_str:
            continue
        actor, user = actor_str.split("::", 1)
        if not actor or not user:
            continue
        synthetic = {"actor": actor, "directions": []}
        if not _is_promotable_actor(synthetic):
            continue
        _, score = _classify_behavior_extended(g)
        if score < CONFIDENCE_THRESHOLD:
            continue
        hits = _safe_int(g.get("events_total"), 0)
        _advance(actor, user, hits, score)

    for g in groups.get("user_groups", []) or []:
        if not isinstance(g, dict):
            continue
        user = g.get("actor")
        if not isinstance(user, str) or not user:
            continue
        sources = g.get("sources") or []
        sources = [s for s in sources if isinstance(s, str) and s]
        if not sources:
            continue
        _, score = _classify_behavior_extended(g)
        if score < CONFIDENCE_THRESHOLD:
            continue
        hits = _safe_int(g.get("events_total"), 0)
        per_source = max(1, hits // len(sources))
        for src in sources:
            synthetic = {"actor": src, "directions": []}
            if not _is_promotable_actor(synthetic):
                continue
            _advance(src, user, per_source, score)

    survivors = []
    for entry in index.values():
        age = now - entry["last_seen"]
        if age > THREAT_MAX_AGE_SECONDS:
            continue
        if age > RETENTION_SECONDS \
                and entry["confidence"] < CONFIDENCE_THRESHOLD:
            continue
        survivors.append(entry)

    if len(survivors) > MAX_THREATS:
        survivors.sort(key=lambda e: e["last_seen"])
        survivors = survivors[-MAX_THREATS:]
    return survivors


def _make_detection(capability: str, ts: float, cls: str, severity: str,
                    detail_value: Any, src_ip: str = "0.0.0.0") -> Dict:
    return {
        "ts": ts,
        "source": capability,
        "class": cls,
        "severity": severity,
        "src_ip": src_ip,
        "detail": f"{cls}={detail_value}",
        "raw": f"{cls}={detail_value}",
    }


def _synthesize_detections(capability: str,
                           failures: int,
                           attacker_ip: str,
                           ts: float) -> List[Dict]:
    if failures <= 0:
        return []
    n = min(int(failures), MAX_SYNTHETIC_DETECTIONS)
    if failures <= 3:
        sev = "low"
    elif failures <= 10:
        sev = "medium"
    elif failures <= 30:
        sev = "high"
    else:
        sev = "critical"
    ip = attacker_ip if isinstance(attacker_ip, str) else "0.0.0.0"
    return [{
        "ts": ts,
        "source": capability,
        "class": "log_match",
        "severity": sev,
        "src_ip": ip,
        "detail": f"{failures} failures (from reader count)",
        "raw": "",
        "synthetic_uid": f"{capability}:{ts}:{i}",
    } for i in range(n)]


def _detections_from_sensor_section(capability: str,
                                    section: Dict,
                                    ts: float) -> List[Dict]:
    detections: List[Dict] = []
    detail = section.get("detail", {})
    if not isinstance(detail, dict):
        detail = {}

    if (detail.get("cpu_spike_detected") is True
            or section.get("cpu_spike_detected") is True):
        detections.append(_make_detection(
            capability, ts, "cpu_spike", "high",
            _safe_float(detail.get("cpu_percent",
                                   section.get("cpu_percent")), 0.0)))

    if (detail.get("memory_spike_detected") is True
            or section.get("memory_spike_detected") is True):
        detections.append(_make_detection(
            capability, ts, "memory_spike", "high",
            _safe_float(detail.get("memory_percent",
                                   section.get("memory_percent")), 0.0)))

    unknown = _safe_int(detail.get("unknown_connection_count",
                                    section.get("unknown_connection_count")), 0)
    if unknown > 0:
        detections.append(_make_detection(
            capability, ts, "unknown_connection", "high", unknown))

    changes = _safe_int(detail.get("file_change_count",
                                    section.get("file_change_count")), 0)
    if changes > 0:
        detections.append(_make_detection(
            capability, ts, "file_change", "high", changes))

    new_procs = _safe_int(detail.get("new_process_count",
                                      section.get("new_process_count")), 0)
    if new_procs > 0:
        detections.append(_make_detection(
            capability, ts, "process_new", "low", new_procs))

    return detections


# ----------------------------------------------------------------------
# ITEM 2 — durable AIS window helpers
# ----------------------------------------------------------------------
def _window_file_path(capability: str) -> str:
    return os.path.join(
        get_temp_dir(), f"acf_ais_window_{capability}.json")


def _window_read(capability: str) -> List[Dict]:
    path = _window_file_path(capability)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        return []
    except Exception as e:
        emit(SRC, LAYER, "warn",
             f"window read failed for {capability}: "
             f"{type(e).__name__}: {e}",
             capability=capability)
        return []
    if not isinstance(data, dict):
        return []
    win = data.get("window")
    if not isinstance(win, list):
        return []
    return [d for d in win if isinstance(d, dict)]


def _window_write(capability: str, window: List[Dict]) -> bool:
    path = _window_file_path(capability)
    tmp = path + ".tmp"
    payload = {
        "capability": capability,
        "window": window,
        "count": len(window),
        "written_at": time.time(),
        "version": Config.SCHEMA_VERSION,
    }
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(payload, f, separators=(",", ":"))
            try:
                f.flush()
                os.fsync(f.fileno())
            except Exception:
                pass
        os.replace(tmp, path)
        return True
    except Exception as e:
        emit(SRC, LAYER, "warn",
             f"window write failed for {capability}: "
             f"{type(e).__name__}: {e}",
             capability=capability)
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass
        return False


def _window_clear(capability: str) -> bool:
    path = _window_file_path(capability)
    try:
        if os.path.exists(path):
            os.remove(path)
        return True
    except Exception as e:
        emit(SRC, LAYER, "warn",
             f"window clear failed for {capability}: "
             f"{type(e).__name__}: {e}",
             capability=capability)
        return False


# ----------------------------------------------------------------------
# PRIMARY INSTANCE GUARD
# ----------------------------------------------------------------------
def _is_primary_instance(layer_name: str) -> bool:
    """
    Only one instance per layer runs the engine loop. The orchestrator
    spawns this engine once per capability in SERVICE_MAP assigned to
    the layer. The primary is the instance whose sys.argv[1] matches
    the first such capability (alphabetically). If started without an
    argument, act as primary.

    The election is restricted to SERVICE_MAP capabilities because
    those are the only ones the orchestrator ever spawns. Custom
    capabilities (defender, pfirewall) are processed by those
    instances as part of their layer's assignment; they do not get
    their own process.

    Recomputed every cycle so a change in the layer's capability set
    is picked up automatically.
    """
    if len(sys.argv) < 2:
        return True
    my_cap = sys.argv[1]
    try:
        config = load_config()
    except Exception:
        return True
    caps = _capabilities_for_layer(config, layer_name)
    if not caps:
        return True
    spawnable = [c for c in caps if c in Config.SERVICE_MAP]
    if not spawnable:
        return True
    return my_cap == sorted(spawnable)[0]


# ----------------------------------------------------------------------
# Worker
# ----------------------------------------------------------------------
class AISWorker:
    def __init__(self, name: str, disabled_map: Dict):
        self.name = name
        self.upstream_candidates = _upstream_candidates(name)
        self.reader_section = f"reader_{name}"
        self.ais_section = f"layer_2_ais_{name}"
        self.groups_section = f"layer_2_groups_{name}"
        self.disabled_map = disabled_map
        self.baseline = 0.0
        self.known_threats: List[Dict] = []
        self.risk = 0
        self.last_attacker_ip = "0.0.0.0"
        self.cycle_count = 0
        self.last_processed_source_id: Optional[float] = None
        self._reader_cumulative_seen: Optional[int] = None
        self.detector_stats: Dict[str, Dict] = {}

        self._window: List[Dict] = []
        self._window_max_seconds = WINDOW_MAX_SECONDS
        self._window_max_items = WINDOW_MAX_ITEMS

        self._last_groups: Dict = {}

        config = load_config()
        criticality = _resolve_criticality(name, config)
        self.criticality_factor = 0.5 + criticality
        self.resource_factor = 1.0
        self.sensitivity_multiplier = 1.0

        self._load_persisted_state()

    def _load_persisted_state(self) -> None:
        section = _bb_read_section(self.ais_section)
        self.baseline = _safe_float(section.get("baseline"), 0.0)

        threats = section.get("known_threats")
        if isinstance(threats, list):
            self.known_threats = [t for t in threats if isinstance(t, dict)]

        self.risk = _safe_int(section.get("risk"), 0)
        self.last_attacker_ip = (
            _safe_str(section.get("attacker_ip"), "0.0.0.0") or "0.0.0.0"
        )

        persisted_source = section.get("last_processed_source_id")
        if persisted_source is not None:
            self.last_processed_source_id = (
                _safe_float(persisted_source, 0.0) or None
            )

        v = section.get("_reader_cumulative_seen")
        if isinstance(v, (int, float)):
            self._reader_cumulative_seen = int(v)
        else:
            self._reader_cumulative_seen = None

        ds = section.get("detector_stats")
        if isinstance(ds, dict):
            self.detector_stats = {
                k: dict(v) for k, v in ds.items()
                if isinstance(k, str) and isinstance(v, dict)
            }
        else:
            self.detector_stats = {}

        self._window = _window_read(self.name)
        self._prune_window(time.time())

    def _add_to_window(self, detections: List[Dict]) -> None:
        for d in detections:
            if isinstance(d, dict):
                self._window.append(d)

    def _prune_window(self, now: float) -> None:
        cutoff = now - self._window_max_seconds
        kept: List[Dict] = []
        seen: set = set()
        for d in self._window:
            if not isinstance(d, dict):
                continue
            ts = d.get("ts")
            if not isinstance(ts, (int, float)) or ts < cutoff:
                continue
            key = (
                ts,
                d.get("class"),
                d.get("src_ip"),
                (d.get("raw") or "")[:200],
                d.get("event_id"),
                d.get("record_id"),
                d.get("synthetic_uid"),
            )
            if key in seen:
                continue
            seen.add(key)
            kept.append(d)
        if len(kept) > self._window_max_items:
            kept = kept[-self._window_max_items:]
        self._window = kept

    def _resource_factor_refresh(self) -> float:
        section = _bb_read_section("layer_1_monitor_sensor")
        if not section:
            return 1.0

        ts = _safe_float(section.get("monitoring_timestamp"), 0.0)
        if ts <= 0.0 or (time.time() - ts) > RESOURCE_FRESH_SECONDS:
            return 1.0
        if section.get("monitor_healthy") is not True:
            return 1.0

        detail = section.get("detail", {})
        if not isinstance(detail, dict):
            return 1.0

        cpu = _safe_float(detail.get("cpu_percent"), 0.0)
        mem = _safe_float(detail.get("memory_percent"), 0.0)
        stress = max(cpu, mem) / 100.0
        if stress < 0.0:
            stress = 0.0
        if stress > 1.0:
            stress = 1.0

        amp = getattr(Config, "RESOURCE_STRESS_AMPLIFIER", 0.5)
        try:
            amp = float(amp)
        except (TypeError, ValueError):
            amp = 0.5
        if amp < 0.0:
            amp = 0.0

        return 1.0 + amp * stress

    def _sensitivity_refresh(self, current_state: str) -> float:
        if current_state in ("YELLOW", "ORANGE", "RED"):
            try:
                m = float(getattr(
                    Config, "YELLOW_SENSITIVITY_MULTIPLIER", 1.5))
            except (TypeError, ValueError):
                m = 1.5
            if m < 1.0:
                m = 1.0
            return m
        return 1.0

    def _read_upstream(self) -> Optional[Tuple[List[Dict], str, float]]:
        for section_name in self.upstream_candidates:
            section = _bb_read_section(section_name)
            if not section:
                continue

            ts = _safe_float(section.get("monitoring_timestamp"), 0.0)
            if ts <= 0.0:
                ts = _safe_float(section.get("sensor_timestamp"), 0.0)
            if ts <= 0.0:
                continue
            if (time.time() - ts) > UPSTREAM_FRESH_SECONDS:
                continue

            healthy = section.get("monitor_healthy")
            if healthy is None:
                healthy = section.get("sensor_healthy")
            if healthy is not True:
                continue

            detections = section.get("detections")
            if isinstance(detections, list):
                if not detections:
                    last_failures = _safe_int(
                        section.get("last_failures"), 0)
                    if last_failures > 0:
                        emit(SRC, LAYER, "warn",
                             f"upstream {section_name} inconsistent "
                             f"(detections=[] but last_failures="
                             f"{last_failures}); falling through",
                             capability=self.name)
                        continue
                return detections, section_name, ts

            if section_name in ("layer_1_monitor_sensor",
                                 "layer_1_sensor_ext"):
                synth = _detections_from_sensor_section(
                    self.name, section, ts)
                return synth, section_name, ts

            return [], section_name, ts
        return None

    def _read_reader(self) -> Optional[Tuple[List[Dict], str, float]]:
        section = _bb_read_section(self.reader_section)
        if not section:
            return None

        ts = section.get("reading_timestamp")
        if ts is None:
            ts = section.get("monitoring_timestamp", 0.0)
        ts = _safe_float(ts, 0.0)
        if ts <= 0.0:
            return None
        if (time.time() - ts) > READER_FRESH_SECONDS:
            return None
        if section.get("reader_ready") is not True:
            return None

        cumulative = _safe_int(section.get("last_failures_cumulative"), 0)
        ip = _safe_str(section.get("last_attacker_ip"), "0.0.0.0") or "0.0.0.0"

        seen = self._reader_cumulative_seen
        if seen is None:
            failures = cumulative
        elif cumulative < seen:
            failures = 0
        else:
            failures = cumulative - seen
        self._reader_cumulative_seen = cumulative

        detections = _synthesize_detections(self.name, failures, ip, ts)
        return detections, "reader", ts

    def run_cycle(self) -> None:
        if _pair_disabled(self.disabled_map, self.name, "layer2"):
            return

        self._last_groups = {}

        detections: List[Dict] = []
        source = "none"
        source_id: Optional[float] = None

        upstream = self._read_upstream()
        if upstream is not None:
            detections, source, source_id = upstream
        else:
            reader = self._read_reader()
            if reader is not None:
                detections, source, source_id = reader

        now = time.time()
        self.resource_factor = self._resource_factor_refresh()
        current_state = _read_state(self.name)
        self.sensitivity_multiplier = self._sensitivity_refresh(current_state)

        self.detector_stats = _detector_stats_from_detections(
            detections, self.detector_stats
        )

        same_cycle = (source != "none"
                      and source_id is not None
                      and source_id == self.last_processed_source_id)
        if source != "none" and source_id is not None:
            self.last_processed_source_id = source_id
        self._add_to_window(detections)
        self._prune_window(now)
        _window_write(self.name, self._window)

        groups = group_detections(self.name, self._window, now=now)

        # Item 5: annotate cross-source entries with the Layer 2
        # behavior so the distributed response acts only when the
        # distributed behavior exists.
        try:
            user_groups_by_actor = {
                g.get("actor"): g
                for g in (groups.get("user_groups") or [])
                if isinstance(g, dict)
            }
            for entry in groups.get("cross_source_by_user") or []:
                if not isinstance(entry, dict):
                    continue
                user = entry.get("user")
                ug = user_groups_by_actor.get(user)
                if ug is None:
                    continue
                b, s = _classify_behavior_extended(ug)
                entry["behavior"] = b
                entry["behavior_score"] = int(s)
                entry["first_seen"] = ug.get("first_seen")
                entry["last_seen"] = ug.get("last_seen")
        except Exception as e:
            emit(SRC, LAYER, "warn",
                 f"behavior annotation failed: "
                 f"{type(e).__name__}: {e}",
                 capability=self.name)

        self._last_groups = groups

        _bb_update(self.groups_section, {
            "source": self.name,
            "generated_at": now,
            "input_count": len(self._window),
            "cycle_input_count": len(detections),
            "window_seconds": self._window_max_seconds,
            "source_groups": groups.get("source_groups", []),
            "user_groups": groups.get("user_groups", []),
            "source_user_groups": groups.get("source_user_groups", []),
            "target_groups": groups.get("target_groups", []),
            "cross_source_by_user": groups.get("cross_source_by_user", []),
            "version": Config.SCHEMA_VERSION,
        })

        if same_cycle and source != "none":
            _bb_update(self.ais_section, {
                "ais_timestamp": now,
                "ais_healthy": True,
                "_reader_cumulative_seen": self._reader_cumulative_seen,
                "criticality_factor": round(self.criticality_factor, 3),
                "resource_factor": round(self.resource_factor, 3),
                "sensitivity_multiplier": round(
                    self.sensitivity_multiplier, 3),
                "observed_state": current_state,
                "detector_stats": self.detector_stats,
            })
            return

        if source == "none" and not self._window:
            self.known_threats = _update_threats_from_groups(
                self.known_threats, groups, now)
            _bb_update(self.ais_section, {
                "source": self.name,
                "ais_timestamp": now,
                "ais_healthy": False,
                "risk": self.risk,
                "attacker_ip": self.last_attacker_ip,
                "baseline": self.baseline,
                "known_threats": self.known_threats,
                "last_processed_source_id": self.last_processed_source_id,
                "detail": {
                    "input_source": "none",
                    "detections_count": 0,
                    "known_threat_count": len(self.known_threats),
                },
                "version": Config.SCHEMA_VERSION,
                "_reader_cumulative_seen": self._reader_cumulative_seen,
                "criticality_factor": round(self.criticality_factor, 3),
                "resource_factor": round(self.resource_factor, 3),
                "sensitivity_multiplier": round(
                    self.sensitivity_multiplier, 3),
                "observed_state": current_state,
                "detector_stats": self.detector_stats,
            })
            emit(SRC, LAYER, "warn",
                 f"Cycle {self.cycle_count} | "
                 f"no input from upstream or reader",
                 capability=self.name)
            return

        risk, new_baseline, group_summary = _compute_risk_from_groups(
            groups,
            self.baseline,
            criticality_factor=self.criticality_factor,
            resource_factor=self.resource_factor,
            sensitivity_multiplier=self.sensitivity_multiplier,
        )
        self.baseline = new_baseline
        self.risk = risk

        attacker_ip = self.last_attacker_ip
        best_score = -1
        for g in groups.get("source_groups", []) or []:
            if not isinstance(g, dict):
                continue
            if not _is_promotable_actor(g):
                continue
            _, score = _classify_behavior_extended(g)
            if score > best_score:
                best_score = score
                attacker_ip = g.get("actor")
        if best_score >= CONFIDENCE_THRESHOLD \
                and attacker_ip != self.last_attacker_ip:
            self.last_attacker_ip = attacker_ip

        self.known_threats = _update_threats_from_groups(
            self.known_threats, groups, now)

        detail = {
            "input_source": source,
            "detections_count": len(detections),
            "window_size": len(self._window),
            "known_threat_count": len(self.known_threats),
            "weighted_sum": _weighted_sum(detections),
            "criticality_factor": round(self.criticality_factor, 3),
            "resource_factor": round(self.resource_factor, 3),
            "sensitivity_multiplier": round(
                self.sensitivity_multiplier, 3),
            "observed_state": current_state,
            "groups_total": group_summary["groups_total"],
            "groups_above_threshold":
                group_summary["groups_above_threshold"],
            "max_behavior_score": group_summary["max_behavior_score"],
            "behaviors": group_summary.get("behaviors", {}),
        }

        _bb_update(self.ais_section, {
            "source": self.name,
            "ais_timestamp": now,
            "ais_healthy": True,
            "risk": risk,
            "attacker_ip": self.last_attacker_ip,
            "baseline": self.baseline,
            "known_threats": self.known_threats,
            "last_processed_source_id": self.last_processed_source_id,
            "detail": detail,
            "version": Config.SCHEMA_VERSION,
            "_reader_cumulative_seen": self._reader_cumulative_seen,
            "criticality_factor": round(self.criticality_factor, 3),
            "resource_factor": round(self.resource_factor, 3),
            "sensitivity_multiplier": round(
                self.sensitivity_multiplier, 3),
            "observed_state": current_state,
            "detector_stats": self.detector_stats,
        })

        try:
            with open(Config.LOG_FILE, "a") as f:
                f.write(f"[{self.name}-AIS] {time.ctime()} | "
                        f"Risk: {risk} | Attacker: {self.last_attacker_ip} | "
                        f"Source: {source}\n")
        except Exception:
            pass

        self.cycle_count += 1
        behaviors_str = ",".join(
            f"{k}={v}" for k, v in
            sorted((group_summary.get("behaviors") or {}).items()))
        emit(SRC, LAYER, "info",
             f"Cycle {self.cycle_count} | source={source} "
             f"detections={len(detections)} "
             f"window={len(self._window)} risk={risk} "
             f"groups={group_summary['groups_total']} "
             f"above={group_summary['groups_above_threshold']} "
             f"max={group_summary['max_behavior_score']} "
             f"behaviors=[{behaviors_str}] "
             f"attacker={self.last_attacker_ip} "
             f"baseline={self.baseline:.1f} "
             f"threats={len(self.known_threats)}",
             capability=self.name)


# ----------------------------------------------------------------------
# Engine
# ----------------------------------------------------------------------
class AISEngine:
    def __init__(self):
        self.workers: Dict[str, AISWorker] = {}
        self.cycle_count = 0
        self._no_workers_warned_at = 0.0
        self.shared_correlation = SharedCorrelation()

    def _rebuild_workers(self, disabled_map: Dict):
        config = load_config()
        if not config:
            emit(SRC, LAYER, "error", "config empty; no workers")
            return
        names = _capabilities_for_layer(config, "layer2")
        if not names:
            return

        for name in list(self.workers.keys()):
            if name not in names:
                emit(SRC, LAYER, "info",
                     f"{name} no longer assigned to layer2; dropping",
                     capability=name)
                _window_clear(name)
                del self.workers[name]

        for name in names:
            existing = self.workers.get(name)
            if existing is not None:
                existing.disabled_map = disabled_map
                continue
            self.workers[name] = AISWorker(name, disabled_map)
            emit(SRC, LAYER, "info", "worker attached", capability=name)

    def _run_all(self):
        for name, worker in self.workers.items():
            try:
                worker.run_cycle()
            except Exception as e:
                emit(SRC, LAYER, "error", f"worker error: {e}",
                     capability=name)

    def _warn_no_workers(self):
        now = time.time()
        if now - self._no_workers_warned_at < 60.0:
            return
        self._no_workers_warned_at = now
        emit(SRC, LAYER, "warn", "no capabilities assigned to layer2")

    def run(self):
        global _running, _last_cycle_time
        signal.signal(signal.SIGINT, _shutdown)
        signal.signal(signal.SIGTERM, _shutdown)
        emit(SRC, LAYER, "info", "AIS engine starting")
        try:
            while _running:
                if not _is_primary_instance(LAYER):
                    time.sleep(BASE_CYCLE_SECONDS)
                    continue
                _last_cycle_time = time.time()
                self.cycle_count += 1
                disabled_map = _read_disabled_map()
                try:
                    self._rebuild_workers(disabled_map)
                    self._run_all()
                    per_cap_groups = {
                        name: w._last_groups
                        for name, w in self.workers.items()
                        if isinstance(w._last_groups, dict)
                        and w._last_groups
                    }
                    if per_cap_groups:
                        self.shared_correlation.update(per_cap_groups)
                    _bb_update("layer_2_correlated",
                               self.shared_correlation.snapshot())
                except Exception as e:
                    emit(SRC, LAYER, "error",
                         f"engine cycle error: {e}")
                if not self.workers:
                    self._warn_no_workers()
                self._write_heartbeat()
                sleep_total = self._cycle_sleep()
                slept = 0.0
                while _running and slept < sleep_total:
                    time.sleep(0.5)
                    slept += 0.5
        finally:
            self._remove_heartbeat()
            emit(SRC, LAYER, "info", "AIS engine stopped")

    def _write_heartbeat(self):
        try:
            os.makedirs(os.path.dirname(HEARTBEAT_FILE), exist_ok=True)
            with open(HEARTBEAT_FILE, "w") as f:
                f.write(str(time.time()))
        except Exception:
            pass

    def _remove_heartbeat(self):
        try:
            if os.path.exists(HEARTBEAT_FILE):
                os.remove(HEARTBEAT_FILE)
        except Exception:
            pass

    def _cycle_sleep(self) -> float:
        data = _bb_read()
        states: List[str] = []
        for cap in self.workers.keys():
            sec = data.get(f"layer_3_state_{cap}")
            if isinstance(sec, dict):
                s = sec.get("state")
                if isinstance(s, str):
                    s_norm = s.strip().upper()
                    if s_norm in STATE_RANK:
                        states.append(s_norm)
        if not states:
            flat = data.get("layer_3_state", {})
            if isinstance(flat, dict):
                s = flat.get("state")
                if isinstance(s, str):
                    s_norm = s.strip().upper()
                    if s_norm in STATE_RANK:
                        states.append(s_norm)
        state = (max(states, key=lambda s: STATE_RANK[s])
                 if states else "GREEN")
        if state == "RED":
            return MIN_CYCLE_SECONDS
        if state == "ORANGE":
            return max(MIN_CYCLE_SECONDS, BASE_CYCLE_SECONDS // 2)
        if state == "YELLOW":
            return max(MIN_CYCLE_SECONDS,
                       int(BASE_CYCLE_SECONDS * 0.75))
        return min(MAX_CYCLE_SECONDS, BASE_CYCLE_SECONDS)


def _shutdown(sig, frame):
    global _running
    emit(SRC, LAYER, "info", f"shutdown signal {sig}")
    _running = False


def main():
    if not os.path.exists(SYSTEM_CONFIG_FILE):
        emit(SRC, LAYER, "error",
             f"config not found at {SYSTEM_CONFIG_FILE}")
        sys.exit(1)
    if not os.path.exists(BLACKBOARD_FILE):
        emit(SRC, LAYER, "error",
             f"blackboard not found at {BLACKBOARD_FILE}")
        sys.exit(1)
    emit(SRC, LAYER, "info", f"config loaded from {SYSTEM_CONFIG_FILE}")
    engine = AISEngine()
    engine.run()


if __name__ == "__main__":
    main()