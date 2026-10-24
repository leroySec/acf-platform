#!/usr/bin/env python3
"""
state/state_engine.py — Layer 3 decision engine (unified, capability-agnostic).
One process. Many capabilities. Uniform output.

For each capability assigned to layer3:
  - Read risk from layer_2_ais_<cap> when fresh (linear).
  - Fall back to layer_1_monitor_<cap> or layer_1_sensor_ext.
  - Fall back to reader_<cap>.
  - Map risk to state via hysteresis thresholds.
  - Hold state on de-escalation for N cycles per rank.
  - Write layer_3_state_<cap>.

--- FEEDBACK ---
  - Persisted state_entered_at so feedback can measure time-in-state.

PRIMARY-INSTANCE GUARD:
  The orchestrator spawns this engine once per capability assigned to
  layer3. Only one instance is the "primary" and runs the engine loop.
  The primary is the instance whose sys.argv[1] matches the first
  capability (alphabetically) in the current layer3 assignment.
  All other instances sleep in a light loop. If the primary dies, the
  orchestrator respawns it and it re-takes the primary role. If the
  config changes and a different capability becomes alphabetically
  first, the matching running instance takes over on its next cycle.
"""
import os
import sys
import json
import time
import signal
import threading
from typing import Dict, List, Any, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config
from platform_utils import acquire_lock, release_lock, get_temp_dir

try:
    from event_emit import emit
except ImportError:
    def emit(src, layer, level, msg, capability=None, cycle=None):
        ts = time.strftime("%H:%M:%S")
        print(f"[{ts}][{src}][{layer}][{level.upper()}] {msg}")

SRC = "state_engine"
LAYER = "layer3"

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYSTEM_CONFIG_FILE = os.path.join(ROOT, "system_config.json")
BLACKBOARD_FILE = Config.BLACKBOARD_FILE
HEARTBEAT_FILE = os.path.join(get_temp_dir(), "acf_state_engine.heartbeat")

BASE_CYCLE_SECONDS = 10
MIN_CYCLE_SECONDS = 3
MAX_CYCLE_SECONDS = 30
WATCHDOG_MULTIPLIER = 5

UPSTREAM_FRESH_SECONDS = 30
READER_FRESH_SECONDS = 30

SEVERITY_WEIGHT = {"low": 5, "medium": 15, "high": 35, "critical": 60}
DEFAULT_SEVERITY_WEIGHT = 15

MAX_SYNTHETIC_DETECTIONS = 50
ANOMALY_RATIO_CAP = 3.0
BASELINE_ALPHA = 0.8

STATE_RANK = {"GREEN": 0, "YELLOW": 1, "ORANGE": 2, "RED": 3}

GREEN_TO_YELLOW = Config.GREEN_TO_YELLOW
YELLOW_TO_ORANGE = Config.YELLOW_TO_ORANGE
ORANGE_TO_RED = Config.ORANGE_TO_RED
RED_TO_ORANGE = Config.RED_TO_ORANGE
ORANGE_TO_YELLOW = Config.ORANGE_TO_YELLOW
YELLOW_TO_GREEN = Config.YELLOW_TO_GREEN

UPSTREAM_SECTIONS = {
    "sensor": ["layer_1_sensor_ext", "layer_1_monitor_sensor"],
}

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


def _clamp_risk(v: Any) -> int:
    return min(100, max(0, _safe_int(v, 0)))


def _validate_thresholds() -> List[str]:
    errors = []
    if not (GREEN_TO_YELLOW > YELLOW_TO_GREEN):
        errors.append("GREEN_TO_YELLOW must be > YELLOW_TO_GREEN")
    if not (YELLOW_TO_ORANGE > ORANGE_TO_YELLOW):
        errors.append("YELLOW_TO_ORANGE must be > ORANGE_TO_YELLOW")
    if not (ORANGE_TO_RED > RED_TO_ORANGE):
        errors.append("ORANGE_TO_RED must be > RED_TO_ORANGE")
    return errors


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


def _layer1_candidates(capability: str) -> List[str]:
    if capability in UPSTREAM_SECTIONS:
        return list(UPSTREAM_SECTIONS[capability])
    return [f"layer_1_monitor_{capability}"]


def _weighted_sum(detections: List[Dict]) -> int:
    total = 0
    for d in detections:
        if not isinstance(d, dict):
            continue
        sev = d.get("severity", "medium")
        total += SEVERITY_WEIGHT.get(sev, DEFAULT_SEVERITY_WEIGHT)
    return total


def _compute_risk(detections: List[Dict],
                  baseline: float) -> Tuple[int, float]:
    total = _weighted_sum(detections)

    if total <= 0:
        new_baseline = baseline * BASELINE_ALPHA
        if new_baseline < 1.0:
            new_baseline = 0.0
        return 0, new_baseline

    if baseline <= 0:
        amplification = 1.0
        new_baseline = float(total)
    else:
        ratio = total / baseline
        amplification = min(max(ratio, 1.0), ANOMALY_RATIO_CAP)
        new_baseline = (BASELINE_ALPHA * baseline
                        + (1.0 - BASELINE_ALPHA) * total)

    risk = int(min(100.0, total * amplification))
    return risk, new_baseline


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


def _synthesize_detections(capability: str, failures: int,
                            attacker_ip: str, ts: float) -> List[Dict]:
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
        "ts": ts, "source": capability, "class": "log_match",
        "severity": sev, "src_ip": ip,
        "detail": f"{failures} failures (from reader count)", "raw": "",
    } for _ in range(n)]


def _detections_from_sensor_section(capability: str, section: Dict,
                                     ts: float) -> List[Dict]:
    detections: List[Dict] = []
    if section.get("cpu_spike_detected") is True:
        detections.append(_make_detection(
            capability, ts, "cpu_spike", "high",
            _safe_float(section.get("cpu_percent"), 0.0)))
    if section.get("memory_spike_detected") is True:
        detections.append(_make_detection(
            capability, ts, "memory_spike", "high",
            _safe_float(section.get("memory_percent"), 0.0)))
    unknown = _safe_int(section.get("unknown_connection_count"), 0)
    if unknown > 0:
        detections.append(_make_detection(
            capability, ts, "unknown_connection", "high", unknown))
    changes = _safe_int(section.get("file_change_count"), 0)
    if changes > 0:
        detections.append(_make_detection(
            capability, ts, "file_change", "high", changes))
    new_procs = _safe_int(section.get("new_process_count"), 0)
    if new_procs > 0:
        detections.append(_make_detection(
            capability, ts, "process_new", "low", new_procs))
    return detections


def _transition(current: str, risk: int) -> Tuple[str, str]:
    current = current if current in STATE_RANK else "GREEN"

    if current == "GREEN":
        if risk > GREEN_TO_YELLOW:
            return "YELLOW", "GREEN_TO_YELLOW"
    elif current == "YELLOW":
        if risk > YELLOW_TO_ORANGE:
            return "ORANGE", "YELLOW_TO_ORANGE"
        if risk < YELLOW_TO_GREEN:
            return "GREEN", "YELLOW_TO_GREEN"
    elif current == "ORANGE":
        if risk > ORANGE_TO_RED:
            return "RED", "ORANGE_TO_RED"
        if risk < ORANGE_TO_YELLOW:
            return "YELLOW", "ORANGE_TO_YELLOW"
    elif current == "RED":
        if risk < RED_TO_ORANGE:
            return "ORANGE", "RED_TO_ORANGE"

    return current, "none"


def _de_escalation_delay(old_state: str) -> int:
    if old_state == "YELLOW":
        default = 2
        try:
            return max(0, int(getattr(
                Config, "YELLOW_DE_ESCALATION_CYCLES", default)))
        except (TypeError, ValueError):
            return default
    if old_state == "ORANGE":
        default = 2
        try:
            return max(0, int(getattr(
                Config, "ORANGE_DE_ESCALATION_CYCLES", default)))
        except (TypeError, ValueError):
            return default
    if old_state == "RED":
        default = 3
        try:
            return max(0, int(getattr(
                Config, "RED_DE_ESCALATION_CYCLES", default)))
        except (TypeError, ValueError):
            return default
    return 0


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
class StateWorker:
    def __init__(self, name: str, disabled_map: Dict):
        self.name = name
        self.ais_section = f"layer_2_ais_{name}"
        self.reader_section = f"reader_{name}"
        self.state_section = f"layer_3_state_{name}"
        self.layer1_candidates = _layer1_candidates(name)
        self.disabled_map = disabled_map
        self.state = "GREEN"
        self.previous_state = "GREEN"
        self.risk_input = 0
        self.cycle_count = 0
        self.branch_baseline = 0.0
        self.last_processed_key: Optional[Tuple[str, float]] = None
        self._reader_cumulative_seen: Optional[int] = None
        self._de_escalation_counter = 0
        self.state_entered_at = 0.0  # --- FEEDBACK ---
        self._load_persisted_state()

    def _load_persisted_state(self) -> None:
        section = _bb_read_section(self.state_section)

        s = section.get("state")
        if isinstance(s, str) and s in STATE_RANK:
            self.state = s

        p = section.get("previous_state")
        if isinstance(p, str) and p in STATE_RANK:
            self.previous_state = p

        if (abs(STATE_RANK[self.state]
                - STATE_RANK[self.previous_state]) > 1):
            emit(SRC, LAYER, "warn",
                 f"previous_state {self.previous_state} not adjacent to "
                 f"state {self.state}; resetting",
                 capability=self.name)
            self.previous_state = self.state

        self.risk_input = _clamp_risk(section.get("risk_input"))

        detail = section.get("detail")
        if isinstance(detail, dict):
            self.branch_baseline = _safe_float(
                detail.get("branch_baseline"), 0.0)

        persisted = section.get("last_processed_key")
        if (isinstance(persisted, list) and len(persisted) == 2
                and isinstance(persisted[0], str)):
            self.last_processed_key = (
                persisted[0],
                _safe_float(persisted[1], 0.0),
            )

        v = section.get("_reader_cumulative_seen")
        if isinstance(v, (int, float)):
            self._reader_cumulative_seen = int(v)
        else:
            self._reader_cumulative_seen = None

        v = section.get("_de_escalation_counter")
        if isinstance(v, (int, float)):
            self._de_escalation_counter = int(v)
        else:
            self._de_escalation_counter = 0

        v = section.get("state_entered_at")
        if isinstance(v, (int, float)) and v > 0:
            self.state_entered_at = float(v)
        else:
            self.state_entered_at = 0.0

    def _read_ais_risk(self) -> Optional[Tuple[int, str, float, Optional[float]]]:
        section = _bb_read_section(self.ais_section)
        if not section:
            return None
        ts = _safe_float(section.get("ais_timestamp"), 0.0)
        if ts <= 0.0:
            return None
        if (time.time() - ts) > UPSTREAM_FRESH_SECONDS:
            return None
        if section.get("ais_healthy") is not True:
            return None
        risk = _clamp_risk(section.get("risk"))
        baseline = _safe_float(section.get("baseline"), 0.0)
        return risk, "layer_2_ais", ts, baseline

    def _read_layer1_risk(self) -> Optional[Tuple[int, str, float, None]]:
        for section_name in self.layer1_candidates:
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
            if isinstance(detections, list) and detections:
                risk, new_baseline = _compute_risk(
                    detections, self.branch_baseline)
                self.branch_baseline = new_baseline
                return risk, section_name, ts, None

            if section_name == "layer_1_sensor_ext":
                synth = _detections_from_sensor_section(
                    self.name, section, ts)
                risk, new_baseline = _compute_risk(
                    synth, self.branch_baseline)
                self.branch_baseline = new_baseline
                return risk, section_name, ts, None

            if isinstance(detections, list):
                last_failures = _safe_int(section.get("last_failures"), 0)
                if last_failures > 0:
                    emit(SRC, LAYER, "warn",
                         f"upstream {section_name} inconsistent "
                         f"(detections=[] but last_failures="
                         f"{last_failures}); falling through",
                         capability=self.name)
                    continue
                risk, new_baseline = _compute_risk(
                    [], self.branch_baseline)
                self.branch_baseline = new_baseline
                return risk, section_name, ts, None

        return None

    def _read_reader_risk(self) -> Optional[Tuple[int, str, float, None]]:
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
        risk, new_baseline = _compute_risk(
            detections, self.branch_baseline)
        self.branch_baseline = new_baseline
        return risk, "reader", ts, None

    def _read_risk(self) -> Optional[Tuple[int, str, float, Optional[float]]]:
        r = self._read_ais_risk()
        if r is not None:
            return r
        r = self._read_layer1_risk()
        if r is not None:
            return r
        r = self._read_reader_risk()
        if r is not None:
            return r
        return None

    def run_cycle(self) -> None:
        self.cycle_count += 1
        if _pair_disabled(self.disabled_map, self.name, "layer3"):
            return

        now = time.time()
        read = self._read_risk()

        if read is None:
            _bb_update(self.state_section, {
                "source": self.name,
                "state_timestamp": now,
                "state_healthy": False,
                "state": self.state,
                "previous_state": self.previous_state,
                "risk_input": self.risk_input,
                "last_processed_key": (
                    list(self.last_processed_key)
                    if self.last_processed_key else None
                ),
                "detail": {
                    "input_source": "none",
                    "transition": "hold",
                    "branch_baseline": self.branch_baseline,
                },
                "version": Config.SCHEMA_VERSION,
                "_reader_cumulative_seen": self._reader_cumulative_seen,
                "_de_escalation_counter": self._de_escalation_counter,
                "state_entered_at": self.state_entered_at,
            })
            emit(SRC, LAYER, "warn",
                 f"Cycle {self.cycle_count} | no input; "
                 f"holding {self.state}",
                 capability=self.name)
            return

        risk, source, source_id, baseline_hint = read

        if baseline_hint is not None:
            self.branch_baseline = baseline_hint

        new_key = (source, source_id)
        if new_key == self.last_processed_key:
            if self.state_entered_at <= 0.0:
                self.state_entered_at = now
            _bb_update(self.state_section, {
                "state_timestamp": now,
                "state_healthy": True,
                "_reader_cumulative_seen": self._reader_cumulative_seen,
                "_de_escalation_counter": self._de_escalation_counter,
                "state_entered_at": self.state_entered_at,
            })
            return

        self.last_processed_key = new_key
        old_state = self.state
        proposed_state, transition_label = _transition(old_state, risk)

        # Per-state de-escalation hold
        going_down = (
            STATE_RANK.get(proposed_state, 0)
            < STATE_RANK.get(old_state, 0)
        )
        delay = _de_escalation_delay(old_state) if going_down else 0

        if going_down and delay > 0:
            self._de_escalation_counter += 1
            if self._de_escalation_counter < delay:
                new_state = old_state
                transition_label = f"hold_{old_state.lower()}"
            else:
                new_state = proposed_state
                self._de_escalation_counter = 0
        else:
            new_state = proposed_state
            self._de_escalation_counter = 0

        if new_state != old_state:
            self.previous_state = old_state
            self.state = new_state
            self.state_entered_at = now
            self.risk_input = risk
        else:
            if self.state_entered_at <= 0.0:
                self.state_entered_at = now

        _bb_update(self.state_section, {
            "source": self.name,
            "state_timestamp": now,
            "state_healthy": True,
            "state": self.state,
            "previous_state": self.previous_state,
            "risk_input": risk,
            "last_processed_key": list(self.last_processed_key),
            "detail": {
                "input_source": source,
                "transition": transition_label,
                "branch_baseline": self.branch_baseline,
            },
            "version": Config.SCHEMA_VERSION,
            "_reader_cumulative_seen": self._reader_cumulative_seen,
            "_de_escalation_counter": self._de_escalation_counter,
            "state_entered_at": self.state_entered_at,
        })

        try:
            with open(Config.LOG_FILE, "a") as f:
                f.write(f"[{self.name}-STATE] {time.ctime()} | "
                        f"State: {self.state} | Risk: {risk} | "
                        f"Source: {source}\n")
        except Exception:
            pass

        emit(SRC, LAYER, "info",
             f"Cycle {self.cycle_count} | source={source} risk={risk} "
             f"state={self.state} transition={transition_label}",
             capability=self.name)


# ----------------------------------------------------------------------
# Engine
# ----------------------------------------------------------------------
class StateEngine:
    def __init__(self):
        self.workers: Dict[str, StateWorker] = {}
        self.cycle_count = 0
        self._no_workers_warned_at = 0.0

    def _rebuild_workers(self, disabled_map: Dict):
        config = load_config()
        if not config:
            emit(SRC, LAYER, "error", "config empty; no workers")
            return
        names = _capabilities_for_layer(config, "layer3")
        if not names:
            return

        for name in list(self.workers.keys()):
            if name not in names:
                emit(SRC, LAYER, "info",
                     f"{name} no longer assigned to layer3; dropping",
                     capability=name)
                del self.workers[name]

        for name in names:
            existing = self.workers.get(name)
            if existing is not None:
                existing.disabled_map = disabled_map
                continue
            self.workers[name] = StateWorker(name, disabled_map)
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
        emit(SRC, LAYER, "warn", "no capabilities assigned to layer3")

    def run(self):
        global _running, _last_cycle_time
        signal.signal(signal.SIGINT, _shutdown)
        signal.signal(signal.SIGTERM, _shutdown)
        emit(SRC, LAYER, "info", "State engine starting")
        threading.Thread(target=watchdog, daemon=True,
                         name="state_watchdog").start()
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
                except Exception as e:
                    emit(SRC, LAYER, "error", f"engine cycle error: {e}")
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
            emit(SRC, LAYER, "info", "State engine stopped")

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


def watchdog():
    threshold = BASE_CYCLE_SECONDS * WATCHDOG_MULTIPLIER
    global _running
    while _running:
        time.sleep(threshold / 2)
        if not _running:
            return
        if time.time() - _last_cycle_time > threshold:
            emit(SRC, LAYER, "error",
                 f"watchdog: no cycle in {threshold}s, "
                 f"requesting shutdown")
            _running = False
            return


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

    threshold_errors = _validate_thresholds()
    if threshold_errors:
        emit(SRC, LAYER, "error", "invalid hysteresis thresholds:")
        for e in threshold_errors:
            emit(SRC, LAYER, "error", f"  - {e}")
        sys.exit(1)

    emit(SRC, LAYER, "info", f"config loaded from {SYSTEM_CONFIG_FILE}")
    engine = StateEngine()
    engine.run()


if __name__ == "__main__":
    main()