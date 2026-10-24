"""
feedback/feedback_analysis.py — Layer 5 Feedback, pure analysis.

Layer 5 closes the loop. It measures what the response did, judges
whether it worked, remembers outcomes, and produces bounded
adjustments for the layers upstream.

This file owns computation. feedback_engine.py owns I/O, timing,
and persistence. No worker in this file reads the Blackboard, opens
a file, calls a subprocess, or reads the clock.

Ten workers
-----------
  W1  compute_risk_reduction       NIST SP 800-55
  W2  compute_false_positive       NIST SP 800-94 / Splunk ES
  W3  compute_resource_cost        NIST SP 800-137
  W4  compute_response_time        NIST SP 800-61 / SANS MTTD-MTTR
  W5  build_recommendation         Snort thresholds / GCP Armor
  W6  update_detector_weights      de Castro & Von Zuben (CLONALG)
  W7  update_memory                NIST SP 800-61 / AIS immune memory
  W8  append_history               Knuth TAOCP Vol 1
  W9  rollup_aggregates            NIST SP 800-92 / ISO 27004
  W10 aggregate_global             SOC-CMM / NIST SP 800-55

Shared invariants
-----------------
  I1  Purity — no Blackboard, no file, no subprocess, no socket.
  I2  Determinism — same inputs, same outputs.
  I3  Non-mutation — inputs are never written to.
  I4  Refusal over correction — an invalid argument returns the
      empty form; an invalid Config raises FeedbackError.
  I5  Bounds from Config, invariants from the worker.
  I6  One output schema per worker.
  I7  No worker calls another.
  I8  Every aggregate is either a finite float (measured) or None
      (no usable samples). Missing data and measured zero are
      distinguishable by inspection of the return value.
  I9  Every worker names its anchor in its docstring.
  I10 One public surface: the ten worker functions and
      FeedbackError.

Clock contract
--------------
All timestamps (ts, state_entered_at, now) MUST be epoch seconds
from the same monotonic source. Mixing clocks or passing ISO
strings is a caller bug and produces undefined results. The
worker coerces numeric strings via float(); any other string
form is refused.

Action schema (produced by response_engine, read here)
------------------------------------------------------
  ts              float  epoch seconds
  action          str
  target          str
  method          str
  risk_at_action  int    0–100
  state_at_action str    GREEN / YELLOW / ORANGE / RED
  false_positive  bool
  fp_source       str
  error           str    optional

State section schema (produced by state_engine, read here)
----------------------------------------------------------
  state              str
  previous_state     str
  state_entered_at   float  set on transition only
  state_timestamp    float  refreshed every cycle
  state_healthy      bool
  risk_input         int
  _de_escalation_counter  int

Feedback history schema (written by the engine, read by W3/W9)
--------------------------------------------------------------
  ts     float  epoch seconds
  cpu    float  0–100
  mem    float  0–100
  risk_reduction      float  optional
  fp                  bool   optional
  response_time       float  optional
"""

import copy
import math

from config import Config


# ======================================================================
# Public exception type
# ======================================================================

class FeedbackError(Exception):
    """Structural invariant breach. Config is malformed, or the
    caller passed an argument that violates the contract in a way
    that cannot be handled by returning a refusal form."""


# ======================================================================
# Config validation at import — fail loud
# ======================================================================

_REQUIRED = (
    "FEEDBACK_EVAL_CYCLES",
    "FEEDBACK_CYCLE_SECONDS",
    "FEEDBACK_MAX_ACTION_AGE_SECONDS",
    "FEEDBACK_FP_WINDOW_SECONDS",
    "FEEDBACK_SUCCESS_THRESHOLD",
    "FEEDBACK_MIN_ACTION_COUNT",
    "FEEDBACK_HISTORY_MAX",
    "FEEDBACK_RECOMMEND_THRESHOLD_MIN_DELTA",
    "FEEDBACK_RECOMMEND_THRESHOLD_MAX_DELTA",
    "FEEDBACK_AUTO_DETECTOR_WEIGHT_MIN",
    "FEEDBACK_AUTO_DETECTOR_WEIGHT_MAX",
    "FEEDBACK_AUTO_DETECTOR_WEIGHT_DELTA",
)


def _validate_config_at_import():
    bad = []
    for name in _REQUIRED:
        if not hasattr(Config, name):
            bad.append(name + " (missing)")
            continue
        v = getattr(Config, name)
        if isinstance(v, bool):
            bad.append(name + " (bool)")
            continue
        try:
            f = float(v)
        except (TypeError, ValueError):
            bad.append(name + " (not numeric)")
            continue
        if math.isnan(f) or math.isinf(f):
            bad.append(name + " (NaN/Inf)")
    if bad:
        raise ImportError(
            "feedback_analysis requires numeric Config attributes: "
            + "; ".join(bad)
        )

    eval_window = (float(Config.FEEDBACK_EVAL_CYCLES)
                   * float(Config.FEEDBACK_CYCLE_SECONDS))
    max_age = float(Config.FEEDBACK_MAX_ACTION_AGE_SECONDS)
    if eval_window >= max_age:
        raise ImportError(
            "FEEDBACK_EVAL_CYCLES * FEEDBACK_CYCLE_SECONDS must be "
            "strictly less than FEEDBACK_MAX_ACTION_AGE_SECONDS "
            f"(got window={eval_window}, max_age={max_age})"
        )

    if int(Config.FEEDBACK_MIN_ACTION_COUNT) < 1:
        raise ImportError("FEEDBACK_MIN_ACTION_COUNT must be >= 1")

    if float(Config.FEEDBACK_AUTO_DETECTOR_WEIGHT_DELTA) <= 0.0:
        raise ImportError(
            "FEEDBACK_AUTO_DETECTOR_WEIGHT_DELTA must be > 0"
        )

    for name in ("FEEDBACK_EVAL_CYCLES", "FEEDBACK_HISTORY_MAX",
                 "FEEDBACK_MIN_ACTION_COUNT"):
        v = getattr(Config, name)
        if isinstance(v, bool):
            raise ImportError(f"{name} must be int, got bool")
        if isinstance(v, int):
            continue
        f = float(v)
        if f != int(f):
            raise ImportError(
                f"{name} must be integer-valued, got {v}"
            )


_validate_config_at_import()


# ======================================================================
# Private constants
# ======================================================================

_RELEASE_ACTIONS = frozenset({"release_isolation", "release_ip"})

_VALID_STATES = frozenset({"GREEN", "YELLOW", "ORANGE", "RED"})

_DETECTOR_WEIGHT_FLOOR = 0.1
_DETECTOR_WEIGHT_CEILING = 10.0

_REDUCTION_EFFECTIVE = 20.0

_FP_RATE_HIGH = 0.3
_FP_RATE_DELTA_SCALE = 10
_FP_RATE_DELTA_FLOOR = 1
_RECOMMEND_REDUCTION_DELTA_FLOOR = -5

_MEMORY_CAP = 200

_VALID_FP_STRINGS = {
    "true": True,
    "false": False,
    "1": True,
    "0": False,
    "yes": True,
    "no": False,
}


# ======================================================================
# Private helpers
# ======================================================================

def _num(v, lo=None, hi=None):
    """Return v as a finite float within [lo, hi], or None."""
    if isinstance(v, bool):
        return None
    if v is None:
        return None
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    if math.isnan(f) or math.isinf(f):
        return None
    if lo is not None and f < lo:
        return None
    if hi is not None and f > hi:
        return None
    return f


def _int_in_range(v, lo, hi):
    """Return int(v) within [lo, hi] if integer-valued, else None."""
    if isinstance(v, bool):
        return None
    if v is None:
        return None
    if isinstance(v, int):
        return v if lo <= v <= hi else None
    f = _num(v)
    if f is None or f != int(f):
        return None
    i = int(f)
    return i if lo <= i <= hi else None


def _is_release(action_type):
    if not isinstance(action_type, str):
        return False
    return action_type.strip().lower() in _RELEASE_ACTIONS


def _norm_state(s):
    if not isinstance(s, str):
        return ""
    u = s.strip().upper()
    return u if u in _VALID_STATES else ""


def _norm_ip(s):
    if not isinstance(s, str):
        return ""
    return s.strip().lower()


def _fp_value(v):
    """Normalise an FP flag: bool, int 0/1, float 0.0/1.0, or the
    string enum. Anything else → None."""
    if isinstance(v, bool):
        return v
    if isinstance(v, int):
        if v == 0:
            return False
        if v == 1:
            return True
        return None
    if isinstance(v, float):
        if v == 0.0:
            return False
        if v == 1.0:
            return True
        return None
    if isinstance(v, str):
        return _VALID_FP_STRINGS.get(v.strip().lower())
    return None


# ======================================================================
# W1 — Risk Reduction Measurer
# ======================================================================

def compute_risk_reduction(ais_now, response_section, now):
    """
    How much has risk fallen since each judged action?

    Anchor
    ------
    NIST SP 800-55 Rev 1 — Performance Measurement Guide for
    Information Security.

    Contract
    --------
    Inputs  : ais_now (dict with "risk"),
              response_section (dict with "actions"),
              now (numeric epoch seconds).
    Output  : {"avg_reduction_points": float or None,
               "actions_judged": int}.
              The average is None when zero actions were judged.
    Refuses : zero-count form when now is invalid, when ais_now.risk
              is invalid, or when no action qualifies.

    Judged actions are older than
    FEEDBACK_EVAL_CYCLES * FEEDBACK_CYCLE_SECONDS and no older than
    FEEDBACK_MAX_ACTION_AGE_SECONDS. Boundary: age == eval_window is
    excluded; age == max_age is included.

    Negative reductions are legitimate observations and included.
    """
    n = _num(now, lo=0.0)
    if n is None:
        return {"avg_reduction_points": None, "actions_judged": 0}
    now = n

    if not isinstance(ais_now, dict):
        return {"avg_reduction_points": None, "actions_judged": 0}
    current_risk = _int_in_range(ais_now.get("risk"), 0, 100)
    if current_risk is None:
        return {"avg_reduction_points": None, "actions_judged": 0}

    actions = response_section.get("actions") \
        if isinstance(response_section, dict) else None
    if not isinstance(actions, list):
        actions = []

    eval_window = (float(Config.FEEDBACK_EVAL_CYCLES)
                   * float(Config.FEEDBACK_CYCLE_SECONDS))
    max_age = float(Config.FEEDBACK_MAX_ACTION_AGE_SECONDS)

    deltas = []
    for action in actions:
        if not isinstance(action, dict):
            continue
        if _is_release(action.get("action")):
            continue
        ts = _num(action.get("ts"), lo=0.0)
        if ts is None:
            continue
        age = now - ts
        if age <= eval_window or age > max_age:
            continue
        risk_at = _int_in_range(action.get("risk_at_action"), 0, 100)
        if risk_at is None:
            continue
        deltas.append(risk_at - current_risk)

    if not deltas:
        return {"avg_reduction_points": None, "actions_judged": 0}
    return {
        "avg_reduction_points": sum(deltas) / len(deltas),
        "actions_judged": len(deltas),
    }


# ======================================================================
# W2 — False Positive Detector
# ======================================================================

def compute_false_positive(response_section, whitelist_ips,
                            state_section):
    """
    Which response actions were probably wrong?

    Anchor
    ------
    NIST SP 800-94 Section 2.3 — FP/FN definitions.
    Splunk ES Notable Event Review Workflow — operator marking.
    AWS GuardDuty suppression rules — whitelist confirmation.

    Contract
    --------
    Inputs  : response_section (dict with "actions"),
              whitelist_ips (list of strings),
              state_section (dict with "state", "state_entered_at").
    Output  : {"false_positives": [
                 {"target": str, "fp_source": str,
                  "signals": [str], "ts": float}, ...]}.
    Refuses : no refusal form; malformed actions are skipped.

    Source priority : operator > whitelist > heuristic.
    All matching signals are collected under "signals"; the top
    one names "fp_source".

    The fast-de-escalation heuristic uses state_section.state_entered_at,
    which the state engine updates only on a real transition. The
    per-cycle state_timestamp is not used. History-based heuristics
    are not accepted: no producer writes a state history.
    """
    if not isinstance(response_section, dict):
        return {"false_positives": []}

    actions = response_section.get("actions")
    if not isinstance(actions, list):
        actions = []

    whitelist = set()
    if isinstance(whitelist_ips, list):
        for ip in whitelist_ips:
            x = _norm_ip(ip)
            if x:
                whitelist.add(x)

    if not isinstance(state_section, dict):
        state_section = {}

    current_state = _norm_state(state_section.get("state"))
    state_entered_at = _num(
        state_section.get("state_entered_at"), lo=0.0)

    fp_window = float(Config.FEEDBACK_FP_WINDOW_SECONDS)

    results = []
    for action in actions:
        if not isinstance(action, dict):
            continue
        if _is_release(action.get("action")):
            continue

        ts = _num(action.get("ts"), lo=0.0)
        if ts is None:
            continue

        target_raw = action.get("target")
        target = target_raw if isinstance(target_raw, str) else ""
        target_norm = _norm_ip(target)

        signals = []

        if action.get("false_positive") is True:
            src = action.get("fp_source")
            signals.append(src if isinstance(src, str) and src
                           else "operator")

        if target_norm and target_norm in whitelist:
            signals.append("whitelist")

        if _norm_state(action.get("state_at_action")) in ("ORANGE", "RED"):
            if (current_state == "GREEN"
                    and state_entered_at is not None):
                delta = state_entered_at - ts
                if 0 <= delta <= fp_window:
                    signals.append("heuristic_fast_deescalation")

        if not signals:
            continue

        seen = set()
        ordered = [s for s in signals
                   if not (s in seen or seen.add(s))]

        results.append({
            "target": target,
            "fp_source": ordered[0],
            "signals": ordered,
            "ts": ts,
        })

    return {"false_positives": results}


# ======================================================================
# W3 — Resource Cost Measurer
# ======================================================================

def compute_resource_cost(history, response_section,
                            monitor_section, now):
    """
    What did the response cost in CPU and memory?

    Anchor
    ------
    NIST SP 800-137 Chapter 3 — cost of controls. Layer 1
    publishes the current snapshot. The engine records each
    snapshot into feedback history. This worker looks up the
    history sample closest before each judged action and compares
    it to the current snapshot.

    Contract
    --------
    Inputs  : history (list of {"ts","cpu","mem"}),
              response_section (dict with "actions"),
              monitor_section (dict with "detail.cpu_percent",
                "detail.memory_percent"),
              now (numeric epoch seconds).
    Output  : {"avg_cpu_percent_delta": float or None,
               "avg_mem_percent_delta": float or None,
               "samples": int}.
              The averages are None when zero samples were computed.
    Refuses : zero-count when current CPU or memory is missing,
              when now is invalid, or when no history sample exists
              within max_age before any judged action.
    """
    now_v = _num(now, lo=0.0)
    if now_v is None:
        return {"avg_cpu_percent_delta": None,
                "avg_mem_percent_delta": None, "samples": 0}
    now = now_v

    if not isinstance(monitor_section, dict):
        return {"avg_cpu_percent_delta": None,
                "avg_mem_percent_delta": None, "samples": 0}
    detail = monitor_section.get("detail")
    if not isinstance(detail, dict):
        return {"avg_cpu_percent_delta": None,
                "avg_mem_percent_delta": None, "samples": 0}

    current_cpu = _num(detail.get("cpu_percent"), 0.0, 100.0)
    current_mem = _num(detail.get("memory_percent"), 0.0, 100.0)
    if current_cpu is None or current_mem is None:
        return {"avg_cpu_percent_delta": None,
                "avg_mem_percent_delta": None, "samples": 0}

    samples = []
    if isinstance(history, list):
        for entry in history:
            if not isinstance(entry, dict):
                continue
            ets = _num(entry.get("ts"), lo=0.0)
            ecpu = _num(entry.get("cpu"), 0.0, 100.0)
            emem = _num(entry.get("mem"), 0.0, 100.0)
            if ets is None or ecpu is None or emem is None:
                continue
            samples.append((ets, ecpu, emem))
    samples.sort(key=lambda x: x[0])

    actions = response_section.get("actions") \
        if isinstance(response_section, dict) else None
    if not isinstance(actions, list):
        actions = []

    eval_window = (float(Config.FEEDBACK_EVAL_CYCLES)
                   * float(Config.FEEDBACK_CYCLE_SECONDS))
    max_age = float(Config.FEEDBACK_MAX_ACTION_AGE_SECONDS)

    cpu_deltas = []
    mem_deltas = []
    for action in actions:
        if not isinstance(action, dict):
            continue
        if _is_release(action.get("action")):
            continue
        ts = _num(action.get("ts"), lo=0.0)
        if ts is None:
            continue
        age = now - ts
        if age <= eval_window or age > max_age:
            continue

        chosen = None
        for s_ts, s_cpu, s_mem in samples:
            if s_ts > ts:
                break
            if ts - s_ts > max_age:
                continue
            chosen = (s_cpu, s_mem)
        if chosen is None:
            continue

        cpu_deltas.append(current_cpu - chosen[0])
        mem_deltas.append(current_mem - chosen[1])

    n = len(cpu_deltas)
    if n == 0:
        return {"avg_cpu_percent_delta": None,
                "avg_mem_percent_delta": None, "samples": 0}
    return {
        "avg_cpu_percent_delta": sum(cpu_deltas) / n,
        "avg_mem_percent_delta": sum(mem_deltas) / n,
        "samples": n,
    }


# ======================================================================
# W4 — Response Time Measurer
# ======================================================================

def compute_response_time(state_section, response_section):
    """
    How long after the last state change did the response fire?

    Anchor
    ------
    NIST SP 800-61 Section 3 — incident response lifecycle.
    SANS MTTD/MTTR definitions.

    Contract
    --------
    Inputs  : state_section (dict with "state_entered_at"),
              response_section (dict with "actions").
    Output  : {"avg_seconds": float or None, "samples": int}.
              The average is None when zero samples were computed.
    Refuses : zero-count when state_entered_at is missing or
              non-positive. No fallback to state_timestamp; that
              field is refreshed every cycle and would measure
              against the latest cycle boundary, not the transition.
    """
    if not isinstance(state_section, dict):
        return {"avg_seconds": None, "samples": 0}

    state_ts = _num(state_section.get("state_entered_at"), lo=0.001)
    if state_ts is None:
        return {"avg_seconds": None, "samples": 0}

    actions = response_section.get("actions") \
        if isinstance(response_section, dict) else None
    if not isinstance(actions, list):
        actions = []

    deltas = []
    for action in actions:
        if not isinstance(action, dict):
            continue
        if _is_release(action.get("action")):
            continue
        ts = _num(action.get("ts"), lo=0.0)
        if ts is None or ts < state_ts:
            continue
        deltas.append(ts - state_ts)

    if not deltas:
        return {"avg_seconds": None, "samples": 0}
    return {
        "avg_seconds": sum(deltas) / len(deltas),
        "samples": len(deltas),
    }


# ======================================================================
# W5 — Threshold Recommender
# ======================================================================

def build_recommendation(fp_rate, risk_reduction_avg, action_count):
    """
    Recommend a bounded threshold change. Recommend-only.

    Anchor
    ------
    Snort 3 User Manual "Configuring Thresholds".
    Google Cloud Armor adaptive protection whitepaper.

    Contract
    --------
    Inputs  : fp_rate (0.0–1.0), risk_reduction_avg (float or None),
              action_count (int >= 1, must be actions_judged from
              W1, not len(actions)).
    Output  : {"recommendations":
                 {"threshold_deltas": {"GREEN_TO_YELLOW": int}}}
              or {"recommendations": {}}.
    Refuses : empty recommendations when action_count is invalid or
              below FEEDBACK_MIN_ACTION_COUNT; when fp_rate is
              outside [0, 1]; when risk_reduction_avg is None or
              non-finite.

    Branches mutually exclusive: fp_rate strictly greater than 0.3
    raises; risk_reduction strictly less than SUCCESS_THRESHOLD
    lowers; otherwise empty.
    """
    min_count = int(Config.FEEDBACK_MIN_ACTION_COUNT)
    if isinstance(action_count, bool) or not isinstance(action_count, int):
        return {"recommendations": {}}
    if action_count < min_count:
        return {"recommendations": {}}

    fp = _num(fp_rate, 0.0, 1.0)
    red = _num(risk_reduction_avg)
    if fp is None or red is None:
        return {"recommendations": {}}

    max_d = float(Config.FEEDBACK_RECOMMEND_THRESHOLD_MAX_DELTA)
    min_d = float(Config.FEEDBACK_RECOMMEND_THRESHOLD_MIN_DELTA)
    success = float(Config.FEEDBACK_SUCCESS_THRESHOLD)

    if fp > _FP_RATE_HIGH:
        delta = int(min(
            max_d,
            max(_FP_RATE_DELTA_FLOOR,
                int(fp * _FP_RATE_DELTA_SCALE))
        ))
        return {"recommendations": {
            "threshold_deltas": {"GREEN_TO_YELLOW": delta}}}

    if red < success:
        delta = int(max(min_d, _RECOMMEND_REDUCTION_DELTA_FLOOR))
        return {"recommendations": {
            "threshold_deltas": {"GREEN_TO_YELLOW": delta}}}

    return {"recommendations": {}}


# ======================================================================
# W6 — Detector Weight Adjuster
# ======================================================================

def update_detector_weights(detector_stats, action_outcomes,
                            current_weights):
    """
    Amplify effective detectors, dampen ineffective ones.

    Anchor
    ------
    de Castro & Von Zuben (2002) — CLONALG.
    Hofmeyr & Forrest (2000) — weight update.

    Contract
    --------
    Inputs  : detector_stats (dict of {name: any}),
              action_outcomes (dict of {name:
                {"avg_reduction": float}}),
              current_weights (dict of {name: float}).
    Output  : {"detector_weights": {name: float}}.
    Raises  : FeedbackError if Config bounds are non-numeric or
              inconsistent after clamping to the module hard range.
              (The delta positivity invariant is enforced at import.)

    A missing or malformed outcome leaves the detector's current
    weight unchanged. The dead band is
    [FEEDBACK_SUCCESS_THRESHOLD, _REDUCTION_EFFECTIVE].

    Note: weight == 0.0 is not a disable signal. Disabling a
    detector is done via ACF layer configuration, not by weight.
    """
    if not isinstance(detector_stats, dict):
        detector_stats = {}
    if not isinstance(action_outcomes, dict):
        action_outcomes = {}
    if not isinstance(current_weights, dict):
        current_weights = {}

    step = float(Config.FEEDBACK_AUTO_DETECTOR_WEIGHT_DELTA)

    cfg_min = _num(Config.FEEDBACK_AUTO_DETECTOR_WEIGHT_MIN)
    cfg_max = _num(Config.FEEDBACK_AUTO_DETECTOR_WEIGHT_MAX)
    if cfg_min is None or cfg_max is None:
        raise FeedbackError(
            "FEEDBACK_AUTO_DETECTOR_WEIGHT_MIN/MAX must be numeric"
        )

    w_min = max(cfg_min, _DETECTOR_WEIGHT_FLOOR)
    w_max = min(cfg_max, _DETECTOR_WEIGHT_CEILING)
    if w_min > w_max:
        raise FeedbackError(
            "Detector weight bounds inconsistent after clamping: "
            f"min={w_min}, max={w_max}"
        )

    success = float(Config.FEEDBACK_SUCCESS_THRESHOLD)

    result = {}
    for name in detector_stats.keys():
        if not isinstance(name, str):
            continue

        current = _num(current_weights.get(name))
        if current is None:
            current = 1.0

        outcome = action_outcomes.get(name)
        if not isinstance(outcome, dict):
            result[name] = max(w_min, min(w_max, current))
            continue

        avg_red = _num(outcome.get("avg_reduction"))
        if avg_red is None:
            result[name] = max(w_min, min(w_max, current))
            continue

        if avg_red > _REDUCTION_EFFECTIVE:
            new = current + step
        elif avg_red < success:
            new = current - step
        else:
            new = current

        result[name] = max(w_min, min(w_max, new))

    return {"detector_weights": result}


# ======================================================================
# W7 — Memory Keeper
# ======================================================================

def update_memory(existing_memory, actions, judgment, current_risk=None):
    """
    Append judged actions to success/ineffective memory.

    Anchor
    ------
    NIST SP 800-61 Section 3.3.2 — Incident Documentation.
    AIS literature — immune memory.

    Contract
    --------
    Inputs  : existing_memory (dict with lists "successful_actions"
                and "ineffective_actions"),
              actions (list of action dicts),
              judgment (dict with "avg_reduction_points"),
              current_risk (optional int 0–100).
    Output  : {"successful_actions": [...],
               "ineffective_actions": [...]}.
    Raises  : FeedbackError when current_risk is provided but not an
              integer in [0, 100]; when current_risk is not provided
              and judgment.avg_reduction_points is missing or
              non-finite.

    When current_risk is provided, each action is classified by
    risk_at_action > current_risk. An action with a missing or
    invalid risk_at_action is skipped in that mode.

    When current_risk is not provided, the batch is classified by
    the judgment average.

    Duplicates suppressed by (action, normalised target, ts).
    Each list capped at _MEMORY_CAP entries.
    """
    if not isinstance(existing_memory, dict):
        existing_memory = {}
    if not isinstance(actions, list):
        actions = []
    if not isinstance(judgment, dict):
        judgment = {}

    current = None
    if current_risk is not None:
        current = _int_in_range(current_risk, 0, 100)
        if current is None:
            raise FeedbackError(
                f"current_risk must be an integer in [0,100], "
                f"got {current_risk!r}"
            )

    avg_red = _num(judgment.get("avg_reduction_points"))
    if current is None and avg_red is None:
        raise FeedbackError(
            "judgment.avg_reduction_points is required when "
            "current_risk is not provided"
        )

    def _as_list(key):
        v = existing_memory.get(key)
        return list(v) if isinstance(v, list) else []

    successful = _as_list("successful_actions")
    ineffective = _as_list("ineffective_actions")

    success = float(Config.FEEDBACK_SUCCESS_THRESHOLD)

    seen = set()
    for e in successful + ineffective:
        if isinstance(e, dict):
            seen.add((
                e.get("action"),
                _norm_ip(e.get("target")),
                e.get("ts"),
            ))

    for action in actions:
        if not isinstance(action, dict):
            continue
        act_type = action.get("action", "")
        if _is_release(act_type):
            continue
        ts = _num(action.get("ts"), lo=0.0)
        if ts is None:
            continue
        risk_at = _int_in_range(action.get("risk_at_action"), 0, 100)

        if current is not None:
            if risk_at is None:
                continue
            is_success = risk_at > current
        else:
            is_success = avg_red > success

        target_raw = action.get("target")
        target = target_raw if isinstance(target_raw, str) else ""
        target_key = _norm_ip(target)

        key = (act_type, target_key, ts)
        if key in seen:
            continue
        seen.add(key)

        entry = {
            "action": act_type,
            "target": target,
            "risk_at_action": risk_at,
            "ts": ts,
        }
        if is_success:
            successful.append(entry)
        else:
            ineffective.append(entry)

    return {
        "successful_actions": successful[-_MEMORY_CAP:],
        "ineffective_actions": ineffective[-_MEMORY_CAP:],
    }


# ======================================================================
# W8 — History Buffer
# ======================================================================

def append_history(history, entry):
    """
    Append one cycle snapshot to a rolling history.

    Anchor
    ------
    Knuth, TAOCP Vol 1, Section 2.2.2 — ring buffer.
    Python collections.deque(maxlen=N).

    Contract
    --------
    Inputs  : history (list), entry (dict).
    Output  : {"history": [...]} capped at
              Config.FEEDBACK_HISTORY_MAX.
    Refuses : non-list history treated as empty; non-dict entry
              treated as {}. Cap of 0 yields empty. Invalid cap is
              rejected at import.

    The entry is deep-copied so callers may reuse their dict.
    """
    if not isinstance(history, list):
        history = []
    if not isinstance(entry, dict):
        entry = {}

    cap = int(Config.FEEDBACK_HISTORY_MAX)

    new_history = list(history)
    try:
        new_history.append(copy.deepcopy(entry))
    except Exception:
        new_history.append(dict(entry))

    if cap == 0:
        return {"history": []}
    if len(new_history) > cap:
        new_history = new_history[-cap:]
    return {"history": new_history}


# ======================================================================
# W9 — Aggregate Roller
# ======================================================================

def rollup_aggregates(history):
    """
    Compute medium-term averages over the ring buffer.

    Anchor
    ------
    NIST SP 800-92 Chapter 6 — log aggregation.
    ISO/IEC 27004 Chapter 8 — analysis and evaluation.

    Contract
    --------
    Inputs  : history (list of entries with optional
              "risk_reduction", "fp", "response_time").
    Output  : {"risk_reduction_avg_points": float or None,
               "false_positive_rate": float or None,
               "response_time_avg_seconds": float or None}.

    An average is None when no entry provided a usable value for
    that measure. Missing data and measured zero are distinguishable
    by the caller.
    """
    if not isinstance(history, list):
        history = []

    reductions = []
    fps = []
    times = []

    for entry in history:
        if not isinstance(entry, dict):
            continue

        rr = _num(entry.get("risk_reduction"))
        if rr is not None:
            reductions.append(rr)

        if "fp" in entry:
            fv = _fp_value(entry.get("fp"))
            if fv is not None:
                fps.append(fv)

        rt = _num(entry.get("response_time"), lo=0.0)
        if rt is not None:
            times.append(rt)

    return {
        "risk_reduction_avg_points": (
            sum(reductions) / len(reductions)
            if reductions else None
        ),
        "false_positive_rate": (
            sum(1 for f in fps if f) / len(fps)
            if fps else None
        ),
        "response_time_avg_seconds": (
            sum(times) / len(times) if times else None
        ),
    }


# ======================================================================
# W10 — Global Aggregator
# ======================================================================

def aggregate_global(per_capability):
    """
    Roll up per-capability aggregates into a global view.

    Anchor
    ------
    SOC-CMM Section 7 — metrics aggregation.
    NIST SP 800-55 reporting phase.

    Contract
    --------
    Inputs  : per_capability (dict keyed by capability name; values
              are W9 outputs).
    Output  : {"risk_reduction_avg_points": float or None,
               "false_positive_rate": float or None}.

    Each aggregate is None when no capability provided a usable
    value for that measure. Missing data and measured zero are
    distinguishable by the caller.
    """
    if not isinstance(per_capability, dict):
        per_capability = {}

    reductions = []
    fp_rates = []

    for _, data in per_capability.items():
        if not isinstance(data, dict):
            continue

        rr = _num(data.get("risk_reduction_avg_points"))
        if rr is not None:
            reductions.append(rr)

        fr = _num(data.get("false_positive_rate"), 0.0, 1.0)
        if fr is not None:
            fp_rates.append(fr)

    return {
        "risk_reduction_avg_points": (
            sum(reductions) / len(reductions)
            if reductions else None
        ),
        "false_positive_rate": (
            sum(fp_rates) / len(fp_rates) if fp_rates else None
        ),
    }