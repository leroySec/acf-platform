#!/usr/bin/env python3
"""
feedback/feedback_engine.py — Layer 5 Feedback, engine.

Owns the loop, the Blackboard I/O, scheduling, and persistence.
Delegates every computation to feedback_analysis.

Twelve engine responsibilities
------------------------------
  E1  Lifecycle         main(), signals, atexit, single instance
  E2  Cycle             per-cycle loop and adaptive sleep
  E3  Reader            single Blackboard snapshot per cycle
  E4  Composer          W1..W9 in order, per capability
  E5  Per-Cap Writer    atomic replacement of layer_5_feedback_<cap>
  E6  Global Aggregator W10 over all capabilities
  E7  Persistence       per-cycle summary record
  E8  Heartbeat         dual-signal heartbeat file
  E9  Watchdog          productive-progress monitor
  E10 Rebuild           reconcile capability set to config
  E11 Isolation         wrap calls so one failure cannot stop the loop
  E12 Shutdown          idempotent teardown, safe from any path

Contract with the analysis module
---------------------------------
The analysis module is pure. It does not read the Blackboard, does
not write, does not schedule, does not persist. The engine supplies
every argument to every analysis function and stores every return
value. The analysis module's own contract is not modified here.

In-process mutable state
------------------------
  _running                     process-wide stop flag
  _last_progress_mono          monotonic timestamp of the last cycle
                               whose writes succeeded, or whose
                               capability set was empty by design.
                               Read by the watchdog. NOT updated on
                               the blackboard-unreadable skip path
                               or on cycles where every write
                               failed.
  _skip_started_mono           monotonic timestamp of the first
                               consecutive skip; None when not
                               skipping.
  _skip_warned_at              set of warning fractions already
                               emitted during the current skip run.
  _pid_fd                      the held file object whose open
                               descriptor holds the PID lock;
                               None when released.
  _config_cache                {mtime, data}
  _whitelist_cache             {mtime, data}
  _config_missing_logged       True after the config-missing line
                               has been emitted once.
  _whitelist_missing_logged    True after the whitelist-missing
                               line has been emitted once.

Module-level path constants are immutable after import. External
shared state — Blackboard, aggregates file, heartbeat file — is not
held in the process; every access is atomic and goes through the
file system.

Import contract
---------------
Three imports are performed at module load: config,
platform_utils, feedback_analysis. Each is wrapped in try/except
and, on failure, prints a diagnostic to stderr and calls
sys.exit(2). The exit code 2 signals "boot failure" to a
supervisor. This is intentional — the module is a supervised
daemon entry point, not a library. A supervisor that wants to
handle the failure differently should wrap the import and check
for it. The module is not designed to be imported by a test runner
without a working Config.

Clock contract
--------------
Scheduling uses time.monotonic(). All arguments passed to the
analysis module (now, ts) use time.time() — epoch seconds. The
heartbeat file carries both.

Platform signal notes
---------------------
On POSIX: SIGINT (Ctrl+C) and SIGTERM (kill) are registered.
On Windows: SIGINT is delivered by Ctrl+C. SIGTERM is not
delivered by TerminateProcess. SIGBREAK (Ctrl+Break) is registered
when the platform provides it. The deployment must stop the engine
with Ctrl+C or Ctrl+Break on Windows.

Heartbeat contract
------------------
The heartbeat file is JSON:

    {"ts": <wall-clock epoch seconds>,
     "progress_ts": <monotonic seconds>}

  ts           is updated on every loop iteration, including the
               skip path. It is the "process is alive" signal.

  progress_ts  is updated only on cycles that produced output
               (writes succeeded or capability set was empty).
               It is the "loop is producing" signal.

A monitor watching for liveness checks ts. A monitor checking that
Layer 5 is healthy compares progress_ts against the current
monotonic clock on the same host. Cross-host monitoring must use ts
and accept the wall-clock caveats.

progress_ts is meaningful only to a same-host monitor reading the
same monotonic clock. Python's time.monotonic() has an undefined
reference point; only differences within a host are portable.

Watchdog scope
--------------
E9 detects "the loop is no longer producing output." The progress
timestamp is updated only on cycles where at least one write
succeeded or the capability set was empty by design. A sustained
inability to write — from any cause — trips the watchdog after
WATCHDOG_MULTIPLIER * BASE_CYCLE_SECONDS.

W3 history timing
-----------------
W3 (resource cost) reads the feedback history as it stood at the
start of the cycle. The current cycle's history entry is appended
by W8 after W3 has run. This is intentional.

W3 output
---------
W3's output is written to layer_5_feedback_<cap> under
"resource_cost".

Detector weights
----------------
W6 (clonal selection) is not called by this engine yet. The data
path it needs — per-detector outcomes — is not produced by any
other engine today. When W6 is disabled, the section records
`detector_weights: null` and `detector_weights_disabled: true`.

PID file contract
-----------------
The file descriptor is held open for the process lifetime. The
exclusive lock is acquired before the file is truncated. The file
is never unlinked — a stale PID file with a stale PID is harmless;
the lock is the source of truth.

Sequence in _acquire_pid_file:
    open(O_RDWR | O_CREAT)   — no truncation
    acquire_lock()            — fail-fast if another instance holds
    seek(0); write(pid); truncate()

A failed starter never destroys the running instance's PID file.

Config and whitelist reload policy
----------------------------------
Both system_config.json and Config.WHITELIST_FILE are cached by
mtime. Edits are observed on the next cycle after the mtime
changes. The host's mtime resolution bounds edit-observation
latency — on FAT32 up to 2 seconds; on NTFS 100 ns.

A malformed whitelist or config edit is treated as "unreadable":
the prior cached value is retained and a log line is emitted. The
cache is never silently emptied by a parse failure.

A deleted file serves the prior cached value and logs once until
the file reappears.

Read-failure contract
---------------------
When the Blackboard cannot be read for a cycle, the per-capability
loop, the global write, and the persistence step are skipped. No
history entry is appended, no aggregate is recomputed, no section
is overwritten. The progress timestamp is NOT updated. The next
cycle attempts to read again.

Persistence contract
--------------------
FEEDBACK_AGGREGATES_FILE records one JSON line per productive
cycle:

    {
        "ts":                     wall-clock epoch seconds,
        "global":                 W10 result,
        "per_cap":                {cap: W9 aggregates},
        "per_cap_detail":         {cap: {resource_cost,
                                         recommendations,
                                         history_len,
                                         learned_memory_len}},
        "capabilities_attempted": int,
        "capabilities_written":   int,
    }

per_cap_detail is a size-annotated summary, not a full duplicate
of the per-cap section. The blackboard remains the source of truth
for history, memory, and full per-cap detail. Each record is a
few hundred bytes per capability; the file is bounded by
AGGREGATES_MAX_BYTES with one-generation rotation.

A cycle with zero capabilities produces no record. A cycle that
attempted capabilities but wrote none produces a record with empty
per_cap and per_cap_detail — the mismatch is the signal.

Monitor section schema
----------------------
  layer_1_monitor_<cap>       per-cap monitor section
  layer_1_monitor_sensor      sensor fallback section

  Freshness fields:
    monitoring_timestamp   float  epoch seconds
    sensor_timestamp       float  epoch seconds (fallback)

  detail sub-fields consulted by W3:
    detail.cpu_percent     float  0–100
    detail.memory_percent  float  0–100

Schema version
--------------
The version field written to each section is the value of
Config.SCHEMA_VERSION if it is a non-empty string, otherwise JSON
null.

Refusal contract
----------------
Argument-level invalidity in the analysis returns the empty form.
Config-level invalidity raises FeedbackError at analysis import.
I/O failure in the engine logs and continues the cycle. Shutdown
is idempotent and never raises.
"""

import os
import sys
import json
import time
import signal
import atexit
import threading
import getpass

from typing import Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# ----------------------------------------------------------------------
# Imports — all three defended uniformly
# ----------------------------------------------------------------------

try:
    from config import Config
except ImportError as _e:
    print(f"[FEEDBACK][BOOT] cannot import config: {_e}",
          file=sys.stderr, flush=True)
    sys.exit(2)

try:
    from platform_utils import get_temp_dir, acquire_lock, release_lock
except ImportError as _e:
    print(f"[FEEDBACK][BOOT] cannot import platform_utils: {_e}",
          file=sys.stderr, flush=True)
    sys.exit(2)

try:
    from feedback import feedback_analysis as fa
except ImportError as _e:
    print(f"[FEEDBACK][BOOT] cannot import feedback_analysis: {_e}",
          file=sys.stderr, flush=True)
    sys.exit(2)


# ----------------------------------------------------------------------
# Module constants
# ----------------------------------------------------------------------

SRC = "feedback_engine"
LAYER = "layer5"

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYSTEM_CONFIG_FILE = os.path.join(ROOT, "system_config.json")
BLACKBOARD_FILE = Config.BLACKBOARD_FILE
HEARTBEAT_FILE = os.path.join(get_temp_dir(), "acf_feedback_engine.heartbeat")
PID_FILE = os.path.join(get_temp_dir(), "acf_feedback_engine.pid")

BASE_CYCLE_SECONDS = 10
MIN_CYCLE_SECONDS = 3
MAX_CYCLE_SECONDS = 30

WATCHDOG_MULTIPLIER = 20
WATCHDOG_SOFT_MULTIPLIER = 3

AGGREGATES_MAX_BYTES = 50 * 1024 * 1024

MONITOR_FRESHNESS_SECONDS = 60

SKIP_WARN_FRACTIONS = (0.25, 0.5, 0.75)

STATE_RANK = {"GREEN": 0, "YELLOW": 1, "ORANGE": 2, "RED": 3}

_RELEASE_ACTIONS = frozenset({"release_isolation", "release_ip"})


# ----------------------------------------------------------------------
# In-process mutable state
# ----------------------------------------------------------------------

_running = True
_last_progress_mono = 0.0
_skip_started_mono = None
_skip_warned_at = set()
_pid_fd = None
_config_cache = {"mtime": 0.0, "data": {}}
_whitelist_cache = {"mtime": 0.0, "data": []}
_config_missing_logged = False
_whitelist_missing_logged = False


# ----------------------------------------------------------------------
# Logging
# ----------------------------------------------------------------------

def _log(msg: str) -> None:
    ts = time.strftime("%H:%M:%S")
    print(f"[{ts}][{SRC}][{LAYER}] {msg}", flush=True)


def _log_audit(msg: str) -> None:
    try:
        with open(Config.LOG_FILE, "a") as f:
            user = getpass.getuser()
            f.write(f"[FEEDBACK] {time.ctime()} | User: {user} | {msg}\n")
    except Exception:
        pass


def _schema_version():
    v = getattr(Config, "SCHEMA_VERSION", None)
    if isinstance(v, str) and v:
        return v
    return None


# ----------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------

def _is_release(action_type) -> bool:
    if not isinstance(action_type, str):
        return False
    return action_type.strip().lower() in _RELEASE_ACTIONS


def _read_config_uncached() -> Optional[Dict]:
    try:
        with open(SYSTEM_CONFIG_FILE, "r") as f:
            return json.load(f)
    except Exception as e:
        _log(f"config read failed: {e}")
        return None


def _read_config() -> Dict:
    global _config_cache, _config_missing_logged
    if not os.path.exists(SYSTEM_CONFIG_FILE):
        if not _config_missing_logged:
            _log(f"config file missing at {SYSTEM_CONFIG_FILE}; "
                 f"serving cached data")
            _config_missing_logged = True
        return _config_cache["data"]
    _config_missing_logged = False
    try:
        mtime = os.path.getmtime(SYSTEM_CONFIG_FILE)
    except OSError:
        return _config_cache["data"]
    if mtime == _config_cache["mtime"]:
        return _config_cache["data"]
    data = _read_config_uncached()
    if isinstance(data, dict):
        _config_cache = {"mtime": mtime, "data": data}
    else:
        _config_cache = {"mtime": mtime, "data": _config_cache["data"]}
    return _config_cache["data"]


def _read_whitelist_uncached() -> Optional[List[str]]:
    try:
        with open(Config.WHITELIST_FILE, "r") as f:
            data = json.load(f)
    except Exception as e:
        _log(f"whitelist read failed: {e}")
        return None
    if isinstance(data, list):
        return [x for x in data if isinstance(x, str)]
    if isinstance(data, dict):
        ips = data.get("whitelisted_ips")
        if isinstance(ips, list):
            return [x for x in ips if isinstance(x, str)]
        return None
    return None


def _read_whitelist() -> List[str]:
    global _whitelist_cache, _whitelist_missing_logged
    path = Config.WHITELIST_FILE
    if not os.path.exists(path):
        if not _whitelist_missing_logged:
            _log(f"whitelist file missing at {path}; "
                 f"serving cached data")
            _whitelist_missing_logged = True
        return _whitelist_cache["data"]
    _whitelist_missing_logged = False
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return _whitelist_cache["data"]
    if mtime == _whitelist_cache["mtime"]:
        return _whitelist_cache["data"]
    data = _read_whitelist_uncached()
    if data is None:
        _whitelist_cache = {"mtime": mtime,
                            "data": _whitelist_cache["data"]}
    else:
        _whitelist_cache = {"mtime": mtime, "data": data}
    return _whitelist_cache["data"]


def _validate_whitelist_at_startup() -> None:
    path = Config.WHITELIST_FILE
    if not os.path.exists(path):
        _log(f"whitelist not found at {path}; FP detection "
             f"will run without a whitelist")
        return
    try:
        with open(path, "r") as f:
            data = json.load(f)
    except Exception as e:
        _log(f"whitelist unreadable at startup: {e}; FP detection "
             f"will run without a whitelist")
        return
    if not isinstance(data, (list, dict)):
        _log(f"whitelist has unexpected root type "
             f"{type(data).__name__}; treating as empty")


def _capabilities_for_layer5(config: Dict) -> List[str]:
    capability_layers = config.get("capability_layers", {})
    if not isinstance(capability_layers, dict):
        return []
    return [
        name for name, layers in capability_layers.items()
        if isinstance(layers, list) and "layer5" in layers
    ]


def _normalize_disabled_value(layers) -> Optional[List[str]]:
    if isinstance(layers, list):
        clean = [str(x) for x in layers if isinstance(x, str)]
        return clean if clean else None
    if layers is True:
        return ["*"]
    if isinstance(layers, bool):
        return None
    if isinstance(layers, int):
        return ["*"] if layers != 0 else None
    if isinstance(layers, str):
        low = layers.strip().lower()
        if low in ("yes", "true", "1"):
            return ["*"]
        if low in ("no", "false", "0", ""):
            return None
        return ["*"]
    _log(f"disabled_capabilities entry has unexpected type "
         f"{type(layers).__name__}; ignored")
    return None


def _extract_disabled_map(bb: Dict) -> Dict[str, List[str]]:
    if not isinstance(bb, dict):
        return {}
    disabled = bb.get("disabled_capabilities", {})
    if isinstance(disabled, list):
        out = {}
        for cap in disabled:
            if isinstance(cap, str) and cap:
                out[cap] = ["*"]
            else:
                _log(f"disabled_capabilities list entry is "
                     f"{type(cap).__name__}; ignored")
        return out
    if isinstance(disabled, dict):
        out = {}
        for cap, layers in disabled.items():
            if not isinstance(cap, str) or not cap:
                continue
            normalized = _normalize_disabled_value(layers)
            if normalized is not None:
                out[cap] = normalized
        return out
    return {}


def _pair_disabled(disabled_map: Dict, capability: str, layer: str) -> bool:
    entry = disabled_map.get(capability)
    if not entry:
        return False
    if "*" in entry:
        return True
    return layer in entry


def _coerce_risk(value) -> Optional[int]:
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value if 0 <= value <= 100 else None
    try:
        f = float(value)
    except (TypeError, ValueError):
        return None
    if f != int(f):
        return None
    i = int(f)
    return i if 0 <= i <= 100 else None


# ----------------------------------------------------------------------
# E3 — Reader Worker
# ----------------------------------------------------------------------

def _read_bb_snapshot() -> Optional[Dict]:
    try:
        with open(BLACKBOARD_FILE, "r") as f:
            acquire_lock(f.fileno(), exclusive=False)
            try:
                bb = json.load(f)
            finally:
                release_lock(f.fileno())
    except Exception as e:
        _log(f"blackboard unreadable: {e}")
        return None
    if not isinstance(bb, dict):
        _log(f"blackboard root is {type(bb).__name__}, not dict")
        return None
    return bb


def _monitor_freshness(section, now: float) -> str:
    if not isinstance(section, dict) or not section:
        return "unknown"
    ts = section.get("monitoring_timestamp")
    if ts is None:
        ts = section.get("sensor_timestamp")
    if ts is None:
        return "unknown"
    try:
        ts = float(ts)
    except (TypeError, ValueError):
        return "unknown"
    if ts <= 0:
        return "unknown"
    if (now - ts) <= MONITOR_FRESHNESS_SECONDS:
        return "fresh"
    return "stale"


def _read_all(capability: str, whitelist: List[str],
              bb: Dict, now: float) -> Dict:
    sections = {
        "ais": {},
        "state": {},
        "response": {},
        "monitor": {},
        "feedback_prior": {},
        "whitelist": whitelist,
    }

    key_map = {
        "ais": f"layer_2_ais_{capability}",
        "state": f"layer_3_state_{capability}",
        "response": f"layer_4a_response_{capability}",
        "monitor": f"layer_1_monitor_{capability}",
        "feedback_prior": f"layer_5_feedback_{capability}",
    }

    for field, section_name in key_map.items():
        value = bb.get(section_name)
        if value is None:
            continue
        if not isinstance(value, dict):
            _log(f"{capability}: section {section_name} is "
                 f"{type(value).__name__}, expected dict; coerced")
            continue
        sections[field] = value

    per_cap = sections["monitor"]
    sensor = bb.get("layer_1_monitor_sensor")
    if not isinstance(sensor, dict):
        sensor = None

    if per_cap and sensor:
        per_fr = _monitor_freshness(per_cap, now)
        sen_fr = _monitor_freshness(sensor, now)
        if per_fr == "fresh":
            pass
        elif sen_fr == "fresh":
            sections["monitor"] = sensor
    elif not per_cap and sensor:
        sections["monitor"] = sensor

    return sections


# ----------------------------------------------------------------------
# E4 — Composer Worker
# ----------------------------------------------------------------------

def _memory_unchanged(existing_memory: Dict) -> Dict:
    succ = existing_memory.get("successful_actions")
    ineff = existing_memory.get("ineffective_actions")
    return {
        "successful_actions": list(succ) if isinstance(succ, list) else [],
        "ineffective_actions": list(ineff) if isinstance(ineff, list) else [],
    }


def _compose(capability: str, sections: Dict, now: float) -> Dict:
    ais = sections["ais"]
    state = sections["state"]
    response = sections["response"]
    monitor = sections["monitor"]
    feedback_prior = sections["feedback_prior"]
    whitelist = sections["whitelist"]

    actions = response.get("actions") if isinstance(response, dict) else None
    if not isinstance(actions, list):
        actions = []

    w1 = fa.compute_risk_reduction(ais, response, now)
    w2 = fa.compute_false_positive(response, whitelist, state)

    non_release = [
        a for a in actions
        if isinstance(a, dict) and not _is_release(a.get("action"))
    ]
    if non_release:
        fp_rate = len(w2.get("false_positives", [])) / len(non_release)
    else:
        fp_rate = None

    history_prior = feedback_prior.get("history")
    if not isinstance(history_prior, list):
        history_prior = []
    w3 = fa.compute_resource_cost(history_prior, response, monitor, now)

    w4 = fa.compute_response_time(state, response)

    w5 = fa.build_recommendation(
        fp_rate,
        w1.get("avg_reduction_points"),
        w1.get("actions_judged", 0),
    )

    existing_memory = feedback_prior.get("learned_memory")
    if not isinstance(existing_memory, dict):
        existing_memory = {}
    current_risk = _coerce_risk(ais.get("risk"))

    try:
        w7 = fa.update_memory(existing_memory, actions, w1, current_risk)
    except fa.FeedbackError:
        w7 = _memory_unchanged(existing_memory)

    detail = monitor.get("detail") if isinstance(monitor, dict) else None
    cpu = detail.get("cpu_percent") if isinstance(detail, dict) else None
    mem = detail.get("memory_percent") if isinstance(detail, dict) else None
    entry = {
        "ts": now,
        "cpu": cpu,
        "mem": mem,
        "risk_reduction": w1.get("avg_reduction_points"),
        "fp": bool(len(w2.get("false_positives", [])) > 0),
        "response_time": w4.get("avg_seconds"),
    }

    w8 = fa.append_history(history_prior, entry)
    new_history = w8.get("history", [])
    w9 = fa.rollup_aggregates(new_history)

    return {
        "history": new_history,
        "aggregates": w9,
        "resource_cost": w3,
        "detector_weights": None,
        "detector_weights_disabled": True,
        "recommendations": w5.get("recommendations", {}),
        "learned_memory": w7,
        "ts": now,
    }


# ----------------------------------------------------------------------
# E5 — Per-Capability Writer Worker
# ----------------------------------------------------------------------

def _write_capability(capability: str, composed: Dict) -> bool:
    section = f"layer_5_feedback_{capability}"
    payload = {
        "source": capability,
        "history": composed.get("history", []),
        "aggregates": composed.get("aggregates", {}),
        "resource_cost": composed.get("resource_cost", {}),
        "detector_weights": composed.get("detector_weights"),
        "detector_weights_disabled": bool(
            composed.get("detector_weights_disabled", False)),
        "recommendations": composed.get("recommendations", {}),
        "learned_memory": composed.get("learned_memory", {}),
        "ts": composed.get("ts", 0.0),
        "version": _schema_version(),
    }
    try:
        with open(BLACKBOARD_FILE, "r+") as f:
            acquire_lock(f.fileno(), exclusive=True)
            try:
                try:
                    bb = json.load(f)
                except json.JSONDecodeError:
                    bb = {}
                if not isinstance(bb, dict):
                    bb = {}
                bb[section] = payload
                f.seek(0)
                json.dump(bb, f, indent=2)
                f.truncate()
            finally:
                release_lock(f.fileno())
        return True
    except Exception as e:
        _log(f"write {capability}: {e}")
        return False


# ----------------------------------------------------------------------
# E6 — Global Aggregator Worker
# ----------------------------------------------------------------------

def _write_global(per_cap_results: Dict[str, Dict],
                  now: float,
                  capabilities_attempted: int) -> Tuple[Dict, bool]:
    if not isinstance(per_cap_results, dict):
        per_cap_results = {}
    global_result = fa.aggregate_global(per_cap_results)

    payload = {
        "aggregates": global_result,
        "capabilities_attempted": capabilities_attempted,
        "capabilities_written": len(per_cap_results),
        "ts": now,
        "version": _schema_version(),
    }
    ok = False
    try:
        with open(BLACKBOARD_FILE, "r+") as f:
            acquire_lock(f.fileno(), exclusive=True)
            try:
                try:
                    bb = json.load(f)
                except json.JSONDecodeError:
                    bb = {}
                if not isinstance(bb, dict):
                    bb = {}
                bb["layer_5_feedback"] = payload
                f.seek(0)
                json.dump(bb, f, indent=2)
                f.truncate()
                ok = True
            finally:
                release_lock(f.fileno())
    except Exception as e:
        _log(f"write global: {e}")
    return global_result, ok


# ----------------------------------------------------------------------
# E7 — Persistence Worker
# ----------------------------------------------------------------------

def _rotate_aggregates_if_needed() -> None:
    try:
        size = os.path.getsize(Config.FEEDBACK_AGGREGATES_FILE)
    except OSError:
        return
    if size < AGGREGATES_MAX_BYTES:
        return
    rotated = Config.FEEDBACK_AGGREGATES_FILE + ".1"
    try:
        if os.path.exists(rotated):
            os.remove(rotated)
        os.replace(Config.FEEDBACK_AGGREGATES_FILE, rotated)
        _log(f"aggregates file rotated at {size} bytes")
    except OSError as e:
        _log(f"aggregates rotation failed: {e}")


def _persist(per_cap_aggregates: Dict[str, Dict],
             per_cap_detail: Dict[str, Dict],
             global_result: Dict,
             now: float,
             capabilities_attempted: int) -> None:
    _rotate_aggregates_if_needed()
    record = {
        "ts": now,
        "global": global_result,
        "per_cap": per_cap_aggregates,
        "per_cap_detail": per_cap_detail,
        "capabilities_attempted": capabilities_attempted,
        "capabilities_written": len(per_cap_aggregates),
    }
    try:
        os.makedirs(os.path.dirname(Config.FEEDBACK_AGGREGATES_FILE),
                    exist_ok=True)
        with open(Config.FEEDBACK_AGGREGATES_FILE, "a",
                  encoding="utf-8") as f:
            f.write(json.dumps(record) + "\n")
    except Exception as e:
        _log(f"persist failed: {e}")


# ----------------------------------------------------------------------
# E8 — Heartbeat Worker
# ----------------------------------------------------------------------

def _write_heartbeat() -> None:
    """
    Write the dual-signal heartbeat. The caller is responsible for
    updating _last_progress_mono before calling this on productive
    paths. On skip paths the caller does NOT update it, so
    progress_ts reflects the last successful cycle.
    """
    payload = {
        "ts": time.time(),
        "progress_ts": _last_progress_mono,
    }
    try:
        os.makedirs(os.path.dirname(HEARTBEAT_FILE), exist_ok=True)
        with open(HEARTBEAT_FILE, "w") as f:
            json.dump(payload, f)
    except Exception as e:
        _log(f"heartbeat write failed: {e}")


def _remove_heartbeat() -> None:
    try:
        if os.path.exists(HEARTBEAT_FILE):
            os.remove(HEARTBEAT_FILE)
    except Exception:
        pass


# ----------------------------------------------------------------------
# E9 — Watchdog Worker
# ----------------------------------------------------------------------

def _watchdog() -> None:
    global _running
    hard = BASE_CYCLE_SECONDS * WATCHDOG_MULTIPLIER
    soft = BASE_CYCLE_SECONDS * WATCHDOG_SOFT_MULTIPLIER
    warned_soft = False
    while _running:
        time.sleep(hard / 4)
        if not _running:
            return
        elapsed = time.monotonic() - _last_progress_mono
        if elapsed > hard:
            _log(f"watchdog: no progress in {elapsed:.1f}s, "
                 f"requesting shutdown")
            _running = False
            return
        if elapsed > soft and not warned_soft:
            _log(f"watchdog: slow progress ({elapsed:.1f}s)")
            warned_soft = True
        elif elapsed <= soft:
            warned_soft = False


# ----------------------------------------------------------------------
# E10 — Rebuild Worker
# ----------------------------------------------------------------------

def _rebuild_capabilities(current: List[str], config: Dict,
                          disabled_map: Dict) -> List[str]:
    wanted = _capabilities_for_layer5(config)
    wanted = [
        c for c in wanted
        if not _pair_disabled(disabled_map, c, "layer5")
    ]
    wanted_set = set(wanted)
    for c in current:
        if c not in wanted_set:
            _log(f"{c} no longer assigned to layer5; dropping")
    for c in wanted:
        if c not in current:
            _log(f"{c} assigned to layer5; attached")
    return wanted


# ----------------------------------------------------------------------
# E11 — Isolation Worker
# ----------------------------------------------------------------------

def _isolated(capability: str, fn, *args, **kwargs):
    try:
        return fn(*args, **kwargs)
    except Exception as e:
        _log(f"{capability}: isolated failure: "
             f"{type(e).__name__}: {e}")
        return None


# ----------------------------------------------------------------------
# E12 — Shutdown Worker
# ----------------------------------------------------------------------

def _shutdown() -> None:
    _remove_heartbeat()
    _release_pid_file()


# ----------------------------------------------------------------------
# PID file — held for the process lifetime, never unlinked
# ----------------------------------------------------------------------

def _acquire_pid_file() -> bool:
    """
    Open without truncation, acquire the lock, then truncate and
    write. A failed starter never destroys the running instance's
    PID file.
    """
    global _pid_fd
    try:
        fd = os.open(PID_FILE, os.O_RDWR | os.O_CREAT, 0o644)
    except OSError as e:
        _log(f"pid file open failed: {e}")
        return False
    try:
        f = os.fdopen(fd, "r+")
    except Exception as e:
        _log(f"pid file fdopen failed: {e}")
        try:
            os.close(fd)
        except Exception:
            pass
        return False
    try:
        acquire_lock(f.fileno(), exclusive=True)
    except Exception as e:
        _log(f"pid file lock acquisition failed: {e}")
        try:
            f.close()
        except Exception:
            pass
        return False
    try:
        f.seek(0)
        f.write(str(os.getpid()))
        f.truncate()
        f.flush()
        _pid_fd = f
        return True
    except Exception as e:
        _log(f"pid file write failed: {e}")
        try:
            f.close()
        except Exception:
            pass
        return False


def _release_pid_file() -> None:
    global _pid_fd
    if _pid_fd is not None:
        try:
            release_lock(_pid_fd.fileno())
        except Exception:
            pass
        try:
            _pid_fd.close()
        except Exception:
            pass
        _pid_fd = None


# ----------------------------------------------------------------------
# E2 — Cycle Worker
# ----------------------------------------------------------------------

def _cycle_sleep(capabilities: List[str], bb: Dict) -> float:
    worst = "GREEN"
    for cap in capabilities:
        sec = bb.get(f"layer_3_state_{cap}") if isinstance(bb, dict) else None
        if not isinstance(sec, dict):
            continue
        s = sec.get("state")
        if not isinstance(s, str):
            continue
        s_norm = s.strip().upper()
        if s_norm in STATE_RANK and STATE_RANK[s_norm] > STATE_RANK[worst]:
            worst = s_norm
    if worst == "RED":
        return MIN_CYCLE_SECONDS
    if worst == "ORANGE":
        return max(MIN_CYCLE_SECONDS, BASE_CYCLE_SECONDS // 2)
    if worst == "YELLOW":
        return max(MIN_CYCLE_SECONDS,
                   int(BASE_CYCLE_SECONDS * 0.75))
    return min(MAX_CYCLE_SECONDS, BASE_CYCLE_SECONDS)


def _run_cycle(capabilities: List[str], whitelist: List[str],
               bb: Dict) -> Tuple[Dict[str, Dict], Dict[str, Dict]]:
    """
    Return (per_cap_aggregates, per_cap_detail).

    per_cap_aggregates : {cap: W9 result}
    per_cap_detail     : {cap: {resource_cost, recommendations,
                                history_len, learned_memory_len}}
    """
    now = time.time()

    disabled_map = _extract_disabled_map(bb)

    aggregates: Dict[str, Dict] = {}
    detail: Dict[str, Dict] = {}
    for cap in capabilities:
        if _pair_disabled(disabled_map, cap, "layer5"):
            continue
        sections = _read_all(cap, whitelist, bb, now)
        composed = _isolated(cap, _compose, cap, sections, now)
        if composed is None:
            continue
        ok = _isolated(cap, _write_capability, cap, composed)
        if not ok:
            continue
        aggregates[cap] = composed.get("aggregates", {})
        memory = composed.get("learned_memory", {})
        if not isinstance(memory, dict):
            memory = {}
        succ = memory.get("successful_actions")
        ineff = memory.get("ineffective_actions")
        detail[cap] = {
            "resource_cost": composed.get("resource_cost", {}),
            "recommendations": composed.get("recommendations", {}),
            "history_len": len(composed.get("history", [])),
            "learned_memory_len": (
                (len(succ) if isinstance(succ, list) else 0)
                + (len(ineff) if isinstance(ineff, list) else 0)
            ),
        }
    return aggregates, detail


# ----------------------------------------------------------------------
# E1 — Lifecycle Worker
# ----------------------------------------------------------------------

def _signal_handler(sig, frame) -> None:
    global _running
    _log(f"shutdown signal {sig}")
    _running = False


def _reset_skip_state() -> None:
    global _skip_started_mono, _skip_warned_at
    _skip_started_mono = None
    _skip_warned_at = set()


def _handle_skip() -> None:
    """
    Track consecutive skips by elapsed monotonic time from the
    first skip. The read failure itself is already logged by
    _read_bb_snapshot; this function adds escalating warnings at
    fixed fractions of the hard watchdog threshold.
    """
    global _skip_started_mono, _skip_warned_at
    now_mono = time.monotonic()
    if _skip_started_mono is None:
        _skip_started_mono = now_mono
        _skip_warned_at = set()
    elapsed = now_mono - _skip_started_mono
    hard = BASE_CYCLE_SECONDS * WATCHDOG_MULTIPLIER
    for frac in SKIP_WARN_FRACTIONS:
        if frac in _skip_warned_at:
            continue
        if elapsed >= hard * frac:
            _log(f"blackboard unreadable for {elapsed:.0f}s "
                 f"({int(frac * 100)}% of watchdog threshold)")
            _skip_warned_at.add(frac)


def main() -> None:
    global _running
    global _last_progress_mono

    _log("Feedback engine starting")

    if not os.path.exists(SYSTEM_CONFIG_FILE):
        _log(f"config not found at {SYSTEM_CONFIG_FILE}")
        sys.exit(1)
    if not os.path.exists(BLACKBOARD_FILE):
        _log(f"blackboard not found at {BLACKBOARD_FILE}")
        sys.exit(1)

    if not _acquire_pid_file():
        _log("another instance is already running; exiting")
        sys.exit(1)

    signal.signal(signal.SIGINT, _signal_handler)
    signal.signal(signal.SIGTERM, _signal_handler)
    if hasattr(signal, "SIGBREAK"):
        try:
            signal.signal(signal.SIGBREAK, _signal_handler)
        except (ValueError, OSError):
            pass
    atexit.register(_shutdown)

    _validate_whitelist_at_startup()
    _log_audit("feedback engine started")

    # Initialize progress timestamp before the first heartbeat write
    # and before the watchdog starts.
    _last_progress_mono = time.monotonic()
    _reset_skip_state()
    _write_heartbeat()

    threading.Thread(target=_watchdog, daemon=True,
                     name="feedback_watchdog").start()

    capabilities: List[str] = []

    try:
        while _running:
            bb = _read_bb_snapshot()
            if bb is None:
                _handle_skip()
                _write_heartbeat()
                sleep_total = _cycle_sleep(capabilities, {})
                slept = 0.0
                while _running and slept < sleep_total:
                    time.sleep(0.5)
                    slept += 0.5
                continue

            _reset_skip_state()

            config = _read_config()
            disabled_map = _extract_disabled_map(bb)
            capabilities = _rebuild_capabilities(
                capabilities, config, disabled_map)

            capabilities_attempted = len(capabilities)

            if capabilities:
                whitelist = _read_whitelist()
                result = _isolated(
                    "cycle", _run_cycle, capabilities, whitelist, bb)
                if isinstance(result, tuple):
                    per_cap_aggregates, per_cap_detail = result
                else:
                    per_cap_aggregates, per_cap_detail = {}, {}

                now = time.time()
                global_result_pair = _isolated(
                    "global", _write_global, per_cap_aggregates, now,
                    capabilities_attempted)
                if isinstance(global_result_pair, tuple):
                    global_result, written = global_result_pair
                else:
                    global_result, written = {}, False

                if written:
                    _isolated("persist", _persist,
                              per_cap_aggregates, per_cap_detail,
                              global_result, now,
                              capabilities_attempted)
                else:
                    _log("global write failed; skipping persistence")

                # Progress is only claimed when at least one
                # capability write succeeded.
                if per_cap_aggregates:
                    _last_progress_mono = time.monotonic()
            else:
                _log("no capabilities assigned to layer5")
                now = time.time()
                _isolated("global", _write_global, {}, now, 0)
                # An intentionally empty capability set is progress.
                _last_progress_mono = time.monotonic()

            _write_heartbeat()

            sleep_total = _cycle_sleep(capabilities, bb)
            slept = 0.0
            while _running and slept < sleep_total:
                time.sleep(0.5)
                slept += 0.5
    finally:
        _shutdown()
        _log("Feedback engine stopped")
        _log_audit("feedback engine stopped")


if __name__ == "__main__":
    main() 