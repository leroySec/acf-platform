# console/views.py
# ============================================================================
# CONSOLE VIEWS — Render the work area content for every view
# ============================================================================
# Every renderer returns a list of (text, color) tuples.
# The app calls ui.render_work_area() once per frame with the returned list.
#
# This module NEVER prints, writes, or reads from stdin.
#
# FIXES APPLIED (round 1):
#   P1.1  _safe_time_str guards per-event timestamps
#   P1.2  Bounded log reads via deque
#   P1.3  _iter_bb_items yields only string keys
#   P2.1  _col uses ui._visible_width and correct truncation
#   P2.2  Engine column shows the basename only
#   P3.2  _log_view_error writes to acf.log
#   P3.3  _fit_widths (first attempt)
#
# FIXES APPLIED (round 2):
#   P0    _fit_widths iteratively shrinks columns from right to left
#   P1.1  True reverse read of log tails (bounded I/O and memory)
#   P1.2  Bounded event message length in render_diag_events
#   P1.3  render_system_config uses Config.SYSTEM_CONFIG_FILE
#   P2    _capability_type is now used
#   P2    _read_log_tail guards lines <= 0
#   P3    _short_engine_path handles command-line strings
#
# FIXES APPLIED (round 3):
#   P1    render_diag_events hides debug by default; "diag events all"
#         shows every level
#   P1    render_diag_layer added: filters events by source and groups
#         by capability for per-layer diag commands
#   P1    LIVE_VIEWS set added: names the views the app redraws in place
# ============================================================================

import os
import time
from typing import Dict, Any, List, Tuple, Optional, Iterable

from config import Config

from . import actions
from . import ui
from . import state as console_state


Line = Tuple[str, str]

# Cached terminal width; refreshed per render() call.
_TERM_WIDTH = 80

# Bounds
LOG_TAIL_LINES = 500
LOG_SHOW_LINES = 40
LOG_TAIL_MAX_BYTES = 1024 * 1024   # 1 MB read cap per tail call

# Minimum width any column can be shrunk to
MIN_COL_WIDTH = 4

# Levels hidden from diag events unless the caller asks for all.
_HIDDEN_LEVELS = frozenset({"debug"})

# Layer name -> event src value. Used by render_diag_layer.
_DIAG_SOURCE_FOR_LAYER: Dict[str, str] = {
    "reader":   "reader",
    "monitor":  "monitor_engine",
    "ais":      "ais_engine",
    "state":    "state_engine",
    "response": "response_engine",
    "mtd":      "mtd_engine",
}

# Views the app redraws in place until the user presses a key.
LIVE_VIEWS = frozenset({
    "layers",
    "engines",
    "engines_heartbeat",
    "diag_events",
    "diag_layer",
    "diag_health",
    "diag_failures",
    "diag_ips",
})


# ----------------------------------------------------------------------
# Diagnostics
# ----------------------------------------------------------------------
def _log_view_error(view: str, message: str):
    """Append a diagnostic line to acf.log without disturbing the work area."""
    try:
        with open(Config.LOG_FILE, "a") as f:
            ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())
            f.write(f"[VIEWS] {ts} | {view} | {message}\n")
    except Exception:
        pass


# ----------------------------------------------------------------------
# Safe time formatting
# ----------------------------------------------------------------------
def _safe_time_str(ts: Any) -> str:
    """Return HH:MM:SS for a numeric timestamp, or '--:--:--' on failure."""
    try:
        if not isinstance(ts, (int, float)):
            return "--:--:--"
        if ts <= 0:
            return "--:--:--"
        return time.strftime("%H:%M:%S", time.localtime(ts))
    except Exception:
        return "--:--:--"


# ----------------------------------------------------------------------
# Blackboard iteration
# ----------------------------------------------------------------------
def _iter_bb_items(bb: Any) -> Iterable[Tuple[str, Any]]:
    """Yield (key, value) pairs from a dict-like Blackboard, string keys only."""
    if not isinstance(bb, dict):
        return
    for key, val in bb.items():
        if isinstance(key, str):
            yield key, val


# ----------------------------------------------------------------------
# Bounded log tail reader (reverse seek)
# ----------------------------------------------------------------------
def _read_log_tail(path: str, lines: int, max_bytes: int = LOG_TAIL_MAX_BYTES) -> List[str]:
    """
    Read up to `lines` lines from the end of a file.
    Seeks from the end and reads growing chunks, so both I/O and memory
    stay bounded regardless of file size.
    Returns an empty list on any failure or when lines <= 0.
    """
    if not isinstance(lines, int) or lines <= 0:
        return []

    try:
        with open(path, "rb") as f:
            f.seek(0, os.SEEK_END)
            size = f.tell()
            if size == 0:
                return []

            read_size = min(size, max_bytes)
            while True:
                start = size - read_size
                f.seek(start)
                data = f.read(read_size)
                text = data.decode("utf-8", errors="replace")
                split = text.splitlines()

                if start == 0:
                    return split[-lines:]

                if len(split) > lines:
                    return split[-lines:]

                if read_size >= size:
                    return split[-lines:]

                read_size = min(size, read_size * 2)
    except Exception:
        return []


# ----------------------------------------------------------------------
# Column helpers
# ----------------------------------------------------------------------
def _col(text: str, width: int) -> str:
    """Pad or truncate text to a fixed display width."""
    if text is None:
        text = ""
    if not isinstance(text, str):
        text = str(text)

    if width <= 0:
        return ""

    text_width = ui._visible_width(text)
    if text_width == width:
        return text
    if text_width < width:
        return text + " " * (width - text_width)

    limit = width - 1
    result = []
    w = 0
    for ch in text:
        cw = ui._visible_width(ch)
        if w + cw > limit:
            break
        result.append(ch)
        w += cw
    return "".join(result) + " "


def _row(cells: List[str], widths: List[int]) -> str:
    """Join cells with two-space separators. Lengths must match."""
    return "  ".join(_col(c, w) for c, w in zip(cells, widths))


def _divider(widths: List[int]) -> str:
    total = sum(widths) + 2 * (len(widths) - 1)
    return "-" * total


def _fit_widths(widths: List[int]) -> List[int]:
    """
    Shrink columns from right to left until the total width fits the
    terminal. Each column is only shrunk down to MIN_COL_WIDTH.
    """
    if not widths:
        return widths

    cols = _TERM_WIDTH
    if cols <= 0:
        cols = 80

    separators = 2 * (len(widths) - 1)
    adjusted = list(widths)
    total = sum(adjusted) + separators

    idx = len(adjusted) - 1
    while total > cols and idx >= 0:
        available = adjusted[idx] - MIN_COL_WIDTH
        if available <= 0:
            idx -= 1
            continue
        need = total - cols
        shrink = min(available, need)
        adjusted[idx] -= shrink
        total -= shrink
        idx -= 1

    return adjusted


def _truncate_line(text: str, width: int) -> str:
    """Truncate a line to fit within `width` columns, with an ASCII marker."""
    if width <= 0 or not text:
        return text or ""
    if ui._visible_width(text) <= width:
        return text

    marker = "..."
    marker_w = len(marker)
    limit = width - marker_w
    if limit <= 0:
        return marker[:width]

    result = []
    w = 0
    for ch in text:
        cw = ui._visible_width(ch)
        if w + cw > limit:
            break
        result.append(ch)
        w += cw
    return "".join(result) + marker


# ----------------------------------------------------------------------
# Capability helpers
# ----------------------------------------------------------------------
def _capability_type(name: str) -> str:
    """Return 'service' for hardcoded capabilities, 'custom' otherwise."""
    if name in Config.SERVICE_MAP:
        return "service"
    return "custom"


def _matches_filter(source: str) -> bool:
    current = console_state.get_filter()
    if not current:
        return True
    return source == current


def _short_engine_path(engine: str) -> str:
    """Return the basename of an engine path or command line."""
    if not isinstance(engine, str) or not engine:
        return "-"

    if " " in engine:
        tokens = engine.split()
        for tok in reversed(tokens):
            if "/" in tok or "\\" in tok:
                engine = tok
                break
        else:
            engine = tokens[-1]

    base = os.path.basename(engine)
    return base or engine


# ----------------------------------------------------------------------
# Capabilities
# ----------------------------------------------------------------------
def render_capabilities(args: List[str]) -> List[Line]:
    lines: List[Line] = []

    caps = actions.get_capabilities_flat() or {}
    paths = actions.get_capability_paths_flat() or {}

    service_names = list(Config.SERVICE_MAP.keys())
    custom_names = sorted(n for n in caps if n not in Config.SERVICE_MAP)

    rows: List[Tuple[str, str, str, str]] = []
    for name in service_names:
        enabled = caps.get(name, False)
        path = paths.get(name, "")
        rows.append((name, _capability_type(name), "ON" if enabled else "OFF", path or "-"))
    for name in custom_names:
        enabled = caps.get(name, False)
        path = paths.get(name, "")
        rows.append((name, _capability_type(name), "ON" if enabled else "OFF", path or "-"))

    widths = _fit_widths([16, 9, 6, 50])
    lines.append((_row(["Name", "Type", "State", "Path"], widths), ""))
    lines.append((_divider(widths), ""))

    any_shown = False
    for name, kind, state, path in rows:
        if not _matches_filter(name):
            continue
        any_shown = True
        color = ui.color_for_level("info") if state == "ON" else ""
        lines.append((_row([name, kind, state, path], widths), color))

    if not any_shown:
        lines.append(("  (no capabilities match the current filter)", ""))

    return lines


# ----------------------------------------------------------------------
# Layers
# ----------------------------------------------------------------------
def render_layers(args: List[str]) -> List[Line]:
    lines: List[Line] = []
    snapshot = actions.get_layer_snapshot()
    layer_map = snapshot.get("layers", {}) if isinstance(snapshot, dict) else {}

    widths = _fit_widths([10, 12, 14, 8, 8, 24])
    lines.append((_row(
        ["Layer", "State", "Engine", "PID", "Display", "Reason"],
        widths,
    ), ""))
    lines.append((_divider(widths), ""))

    for layer_id in console_state.LAYER_IDS:
        if not _matches_filter(layer_id):
            continue
        info = layer_map.get(layer_id, {}) if isinstance(layer_map, dict) else {}
        if not isinstance(info, dict):
            info = {}
        state = info.get("state", "UNKNOWN")
        engine = _short_engine_path(info.get("engine", "-"))
        pid = str(info.get("pid") or "-")
        reason = info.get("reason", "")
        display = "ON" if console_state.is_displayed(layer_id) else "OFF"

        color = ""
        s = (state or "").upper()
        if s == "RUNNING":
            color = ui.color_for_state("GREEN")
        elif s == "FAILED":
            color = ui.color_for_state("RED")
        elif s == "DISABLED":
            color = ui.color_for_state("YELLOW")

        lines.append((_row(
            [layer_id, state, engine, pid, display, reason],
            widths,
        ), color))

    return lines


# ----------------------------------------------------------------------
# Engines
# ----------------------------------------------------------------------
def render_engines(args: List[str]) -> List[Line]:
    lines: List[Line] = []
    snapshot = actions.get_layer_snapshot()
    layer_map = snapshot.get("layers", {}) if isinstance(snapshot, dict) else {}
    now = time.time()

    widths = _fit_widths([10, 20, 12, 12, 24])
    lines.append((_row(
        ["Layer", "Engine", "State", "Heartbeat", "Reason"],
        widths,
    ), ""))
    lines.append((_divider(widths), ""))

    for layer_id in console_state.LAYER_IDS:
        if not _matches_filter(layer_id):
            continue
        info = layer_map.get(layer_id, {}) if isinstance(layer_map, dict) else {}
        if not isinstance(info, dict):
            info = {}
        state = info.get("state", "UNKNOWN")
        engine = _short_engine_path(info.get("engine", "-"))
        hb = info.get("last_heartbeat") or 0
        if isinstance(hb, (int, float)) and hb > 0:
            age = int(now - hb)
            hb_str = f"{age}s" if age < 3600 else "stale"
        else:
            hb_str = "-"
        reason = info.get("reason", "")
        lines.append((_row(
            [layer_id, engine, state, hb_str, reason],
            widths,
        ), ""))

    return lines


def render_engines_heartbeat(args: List[str]) -> List[Line]:
    lines: List[Line] = []
    snapshot = actions.get_layer_snapshot()
    layer_map = snapshot.get("layers", {}) if isinstance(snapshot, dict) else {}
    now = time.time()

    lines.append(("Heartbeat (seconds since last update)", ""))
    lines.append(("-" * 40, ""))
    for layer_id in console_state.LAYER_IDS:
        if not _matches_filter(layer_id):
            continue
        info = layer_map.get(layer_id, {}) if isinstance(layer_map, dict) else {}
        if not isinstance(info, dict):
            info = {}
        hb = info.get("last_heartbeat") or 0
        if isinstance(hb, (int, float)) and hb > 0:
            age = int(now - hb)
            color = ui.color_for_state("GREEN") if age < 30 else ui.color_for_state("YELLOW")
            lines.append((f"  {layer_id:10} {age}s", color))
        else:
            lines.append((f"  {layer_id:10} -", ""))

    return lines


# ----------------------------------------------------------------------
# System
# ----------------------------------------------------------------------
def render_system(args: List[str]) -> List[Line]:
    return [
        ("System", ""),
        ("", ""),
        ("  1  View configuration      system config", ""),
        ("  2  View Blackboard         system blackboard", ""),
        ("  3  View audit log          system audit", ""),
        ("  4  Show resource usage     system resources", ""),
        ("  5  Reload configuration    reload", ""),
        ("  6  Reload all              reload all", ""),
    ]


def render_system_config(args: List[str]) -> List[Line]:
    import json
    try:
        with open(Config.SYSTEM_CONFIG_FILE, "r") as f:
            data = json.load(f)
    except Exception as e:
        return [(f"  Could not read {Config.SYSTEM_CONFIG_FILE}: {e}",
                 ui.color_for_level("error"))]

    text = json.dumps(data, indent=2)
    lines: List[Line] = [(Config.SYSTEM_CONFIG_FILE, "")]
    lines.append(("-" * 40, ""))
    for row in text.splitlines():
        lines.append((row, ""))
    return lines


def render_system_blackboard(args: List[str]) -> List[Line]:
    import json
    bb = actions.get_blackboard()
    if not bb:
        return [("  Blackboard is empty or unavailable.", ui.color_for_level("warn"))]

    text = json.dumps(bb, indent=2, default=str)
    lines: List[Line] = [("Blackboard", "")]
    lines.append(("-" * 40, ""))
    for row in text.splitlines():
        lines.append((row, ""))
    return lines


def render_system_audit(args: List[str]) -> List[Line]:
    tail = _read_log_tail(Config.LOG_FILE, LOG_SHOW_LINES)
    if not tail:
        return [(f"  No audit log data (or {Config.LOG_FILE} unreadable).",
                 ui.color_for_level("warn"))]

    lines: List[Line] = [("Recent audit log", "")]
    lines.append(("-" * 40, ""))
    for row in tail:
        lines.append((row.rstrip("\n"), ""))
    return lines


def render_system_resources(args: List[str]) -> List[Line]:
    try:
        import psutil
    except ImportError:
        return [("  psutil not installed; resource usage unavailable.",
                 ui.color_for_level("warn"))]

    lines: List[Line] = [("Resource usage (this console process)", "")]
    lines.append(("-" * 50, ""))
    try:
        proc = psutil.Process()
        cpu = proc.cpu_percent(interval=0.1)
        mem = proc.memory_info().rss / (1024 * 1024)
        lines.append((f"  CPU: {cpu:.1f}%", ""))
        lines.append((f"  RAM: {mem:.1f} MB", ""))
        lines.append((f"  Threads: {proc.num_threads()}", ""))
        lines.append(("", ""))
        lines.append(("System", ""))
        lines.append(("-" * 50, ""))
        lines.append((f"  CPU: {psutil.cpu_percent(interval=0.1):.1f}%", ""))
        mem = psutil.virtual_memory()
        lines.append((f"  RAM: {mem.percent:.1f}%", ""))
    except Exception as e:
        lines.append((f"  Error: {e}", ui.color_for_level("error")))

    return lines


# ----------------------------------------------------------------------
# Diagnostics
# ----------------------------------------------------------------------
def render_diagnostics(args: List[str]) -> List[Line]:
    return [
        ("Diagnostics", ""),
        ("", ""),
        ("  1  Show state and risk     diag summary", ""),
        ("  2  Show failure counts     diag failures", ""),
        ("  3  Show attacker IPs       diag ips", ""),
        ("  4  Show recent events      diag events", ""),
        ("  5  Show engine health      diag health", ""),
        ("", ""),
        ("  Per-layer event streams:", ""),
        ("     diag reader      diag monitor     diag ais", ""),
        ("     diag state       diag response    diag mtd", ""),
    ]


def render_diag_state(args: List[str]) -> List[Line]:
    bb = actions.get_blackboard()
    state_obj = bb.get("layer_3_state", {}) if isinstance(bb, dict) else {}
    state = state_obj.get("state", "N/A") if isinstance(state_obj, dict) else "N/A"

    risk = 0
    for key, val in _iter_bb_items(bb):
        if not key.startswith("layer_2_ais_"):
            continue
        if not isinstance(val, dict):
            continue
        try:
            r = int(val.get("risk", 0) or 0)
            if r > risk:
                risk = r
        except Exception:
            continue

    color = ui.color_for_state(state)
    return [
        (f"State:  {state}", color),
        (f"Risk:   {risk}%", ""),
        ("", ""),
        (f"Layers running:  {_count_running_layers()}", ""),
        (f"Active filter:   {console_state.get_filter() or '(none)'}", ""),
        (f"Layout:          {console_state.get_layout()}", ""),
    ]


def _count_running_layers() -> int:
    snap = actions.get_layer_snapshot()
    layers = snap.get("layers", {}) if isinstance(snap, dict) else {}
    if not isinstance(layers, dict):
        return 0
    return sum(1 for info in layers.values()
               if isinstance(info, dict) and info.get("state") == "RUNNING")


def render_diag_failures(args: List[str]) -> List[Line]:
    bb = actions.get_blackboard()
    lines: List[Line] = [("Failure counts", "")]
    lines.append(("-" * 40, ""))

    found = False
    for key, val in _iter_bb_items(bb):
        if not key.startswith("layer_1_monitor_"):
            continue
        name = key[len("layer_1_monitor_"):]
        if not _matches_filter(name):
            continue
        failures = val.get("last_failures", 0) if isinstance(val, dict) else 0
        lines.append((f"  {name:20} {failures}", ""))
        found = True

    if not found:
        lines.append(("  (no failure data available)", ""))
    return lines


def render_diag_ips(args: List[str]) -> List[Line]:
    bb = actions.get_blackboard()
    lines: List[Line] = [("Last attacker IP per capability", "")]
    lines.append(("-" * 50, ""))

    found = False
    for key, val in _iter_bb_items(bb):
        if not key.startswith("layer_1_monitor_"):
            continue
        name = key[len("layer_1_monitor_"):]
        if not _matches_filter(name):
            continue
        ip = val.get("last_attacker_ip", "0.0.0.0") if isinstance(val, dict) else "0.0.0.0"
        lines.append((f"  {name:20} {ip}", ""))
        found = True

    if not found:
        lines.append(("  (no attacker data available)", ""))
    return lines


def render_diag_events(args: List[str]) -> List[Line]:
    show_all = bool(args) and str(args[0]).lower() in ("all", "--all", "-a")
    current_filter = console_state.get_filter()
    events = console_state.get_recent_events(current_filter, count=100)

    shown_title = "all levels" if show_all else "info and above"
    lines: List[Line] = [
        (f"Recent events (filter: {current_filter or 'none'}, {shown_title})", ""),
        ("-" * 60, ""),
    ]

    if not events:
        lines.append(("  (no events)", ""))
        return lines

    max_width = _TERM_WIDTH - 2 if _TERM_WIDTH > 10 else 78

    rendered = 0
    for ev in reversed(events):
        if rendered >= 40:
            break
        if not isinstance(ev, dict):
            continue
        level = ev.get("level", "info")
        if isinstance(level, str) and level.lower() in _HIDDEN_LEVELS and not show_all:
            continue
        ts = ev.get("ts", 0)
        time_str = _safe_time_str(ts)
        src = ev.get("src", "unknown")
        layer = ev.get("layer", "-")
        msg = ev.get("msg", "")
        if not isinstance(msg, str):
            msg = str(msg)

        text = f"  [{time_str}] [{src}] [{layer}] {msg}"
        if ui._visible_width(text) > max_width:
            text = _truncate_line(text, max_width)

        color = ui.color_for_level(level) if isinstance(level, str) else ""
        lines.append((text, color))
        rendered += 1

    if rendered == 0:
        lines.append(("  (no events at this level)", ""))

    return lines


def render_diag_layer(args: List[str]) -> List[Line]:
    """
    Render one layer's event stream, grouped by capability.

    args[0] is the layer name as typed: reader, monitor, ais,
    state, response, or mtd. The mapping to the emitting engine's
    `src` value is in _DIAG_SOURCE_FOR_LAYER.
    """
    if not args:
        return [("  No layer specified.", ui.color_for_level("warn"))]
    layer_name = str(args[0]).lower()
    source = _DIAG_SOURCE_FOR_LAYER.get(layer_name)
    if source is None:
        return [(f"  Unknown layer: {layer_name}", ui.color_for_level("error"))]

    events = console_state.get_recent_events(None, count=500)
    filtered = [
        ev for ev in events
        if isinstance(ev, dict) and ev.get("src") == source
    ]

    lines: List[Line] = [
        (f"{layer_name} events  (src={source}, {len(filtered)} event(s))", ""),
        ("=" * 60, ""),
    ]

    if not filtered:
        lines.append(("", ""))
        lines.append((f"  (no events from {layer_name} in the buffer)", ""))
        return lines

    by_capability: Dict[str, List[Dict[str, Any]]] = {}
    for ev in filtered:
        cap = ev.get("capability")
        if not isinstance(cap, str) or not cap:
            cap = "(no capability)"
        by_capability.setdefault(cap, []).append(ev)

    max_width = _TERM_WIDTH - 2 if _TERM_WIDTH > 10 else 78

    for cap in sorted(by_capability.keys()):
        lines.append(("", ""))
        lines.append((f"  {cap}", ui.color_for_level("info")))
        lines.append(("  " + "-" * 40, ""))
        for ev in by_capability[cap]:
            ts = ev.get("ts", 0)
            time_str = _safe_time_str(ts)
            level = ev.get("level", "info")
            msg = ev.get("msg", "")
            if not isinstance(msg, str):
                msg = str(msg)
            text = f"    [{time_str}] [{level}] {msg}"
            if ui._visible_width(text) > max_width:
                text = _truncate_line(text, max_width)
            color = ui.color_for_level(level) if isinstance(level, str) else ""
            lines.append((text, color))

    return lines


def render_diag_health(args: List[str]) -> List[Line]:
    snap = actions.get_layer_snapshot()
    layers = snap.get("layers", {}) if isinstance(snap, dict) else {}

    lines: List[Line] = [("Engine health", "")]
    lines.append(("-" * 40, ""))

    for layer_id in console_state.LAYER_IDS:
        info = layers.get(layer_id, {}) if isinstance(layers, dict) else {}
        if not isinstance(info, dict):
            info = {}
        state = info.get("state", "UNKNOWN")
        if state == "RUNNING":
            marker = "OK"
            color = ui.color_for_state("GREEN")
        elif state == "DISABLED":
            marker = "--"
            color = ""
        else:
            marker = "!!"
            color = ui.color_for_state("RED")
        lines.append((f"  {layer_id:10} {marker}  {state}", color))

    return lines


# ----------------------------------------------------------------------
# Per-source views
# ----------------------------------------------------------------------
def render_telemetry(args: List[str]) -> List[Line]:
    if not args:
        return [("  No capability specified.", ui.color_for_level("warn"))]
    name = args[0]

    bb = actions.get_blackboard()
    key = f"layer_1_monitor_{name}"
    data = bb.get(key) if isinstance(bb, dict) else None
    if not isinstance(data, dict):
        return [(f"  No telemetry for '{name}'", ui.color_for_level("warn"))]

    lines: List[Line] = [f"Telemetry for {name}", ""]
    lines.append(("-" * 40, ""))
    for k, v in sorted(data.items()):
        if not isinstance(k, str):
            k = str(k)
        lines.append((f"  {k:24} {v}", ""))
    return lines


def render_layer_status(args: List[str]) -> List[Line]:
    if not args:
        return [("  No layer specified.", ui.color_for_level("warn"))]
    layer_id = args[0]

    snap = actions.get_layer_snapshot()
    layers = snap.get("layers", {}) if isinstance(snap, dict) else {}
    info = layers.get(layer_id) if isinstance(layers, dict) else None
    if not isinstance(info, dict):
        return [(f"  Unknown layer: {layer_id}", ui.color_for_level("error"))]

    lines: List[Line] = [f"Layer {layer_id}", ""]
    lines.append(("-" * 40, ""))
    for k in ("state", "pid", "engine", "reason", "failure_count",
              "backoff_level", "last_heartbeat"):
        lines.append((f"  {k:16} {info.get(k, '-')}", ""))
    return lines


def render_engine_logs(args: List[str]) -> List[Line]:
    if not args:
        return [("  No engine specified.", ui.color_for_level("warn"))]
    name = args[0]

    tail = _read_log_tail(Config.LOG_FILE, LOG_TAIL_LINES)
    if not tail:
        return [(f"  No log data (or {Config.LOG_FILE} unreadable).",
                 ui.color_for_level("warn"))]

    matched = [row.rstrip("\n") for row in tail if name in row][-30:]
    if not matched:
        return [(f"  No log entries for '{name}'", ui.color_for_level("warn"))]

    lines: List[Line] = [f"Recent log entries for {name}", ""]
    lines.append(("-" * 60, ""))
    for row in matched:
        lines.append((row, ""))
    return lines


# ----------------------------------------------------------------------
# Help
# ----------------------------------------------------------------------
def render_help(args: List[str]) -> List[Line]:
    from . import commands
    topic = args[0] if args else "overview"
    text = commands.HELP_TEXT.get(topic)
    if text is None:
        return [(f"  Unknown help topic: {topic}", ui.color_for_level("error"))]
    lines: List[Line] = [f"Help: {topic}", ""]
    lines.append(("-" * 40, ""))
    for row in text.splitlines():
        lines.append((row, ""))
    return lines


# ----------------------------------------------------------------------
# Dispatcher
# ----------------------------------------------------------------------
VIEWS = {
    "capabilities": render_capabilities,
    "layers": render_layers,
    "engines": render_engines,
    "engines_heartbeat": render_engines_heartbeat,
    "system": render_system,
    "system_config": render_system_config,
    "system_blackboard": render_system_blackboard,
    "system_audit": render_system_audit,
    "system_resources": render_system_resources,
    "diagnostics": render_diagnostics,
    "diag_state": render_diag_state,
    "diag_failures": render_diag_failures,
    "diag_ips": render_diag_ips,
    "diag_events": render_diag_events,
    "diag_health": render_diag_health,
    "diag_layer": render_diag_layer,
    "telemetry": render_telemetry,
    "layer_status": render_layer_status,
    "engine_logs": render_engine_logs,
    "help": render_help,
}


def render(view_name: str, args: Optional[List[str]] = None) -> List[Line]:
    """
    Dispatch to the appropriate renderer.
    Returns a list of (text, color) tuples. Never raises.
    """
    global _TERM_WIDTH
    try:
        _TERM_WIDTH = ui.get_size()[0]
    except Exception:
        _TERM_WIDTH = 80

    if args is None:
        args = []

    fn = VIEWS.get(view_name)
    if fn is None:
        return [(f"  Unknown view: {view_name}", ui.color_for_level("error"))]

    try:
        lines = fn(args)
        if not isinstance(lines, list):
            _log_view_error(view_name, "renderer returned non-list")
            return [("  Renderer returned invalid data", ui.color_for_level("error"))]

        clean: List[Line] = []
        for item in lines:
            if isinstance(item, tuple) and len(item) == 2:
                text, color = item
                if not isinstance(text, str):
                    text = str(text)
                if not isinstance(color, str):
                    color = ""
                clean.append((text, color))
            else:
                clean.append((str(item), ""))
        return clean
    except Exception as e:
        _log_view_error(view_name, f"exception: {e}")
        return [(f"  View error: {e}", ui.color_for_level("error"))]
