#!/usr/bin/env python3
# ============================================================================
# GUI — ACF graphical presentation
# ============================================================================
# Runs in the orchestrator's process, on the orchestrator's main thread.
# Blocks on mainloop() until the operator closes the window or the
# orchestrator signals shutdown.
#
# Data sources (all live, no static content):
#   event stream  : event_reader.start_reader (router subscription)
#   capabilities  : system_config.json capability_layers (fallback: blackboard)
#   layer cards   : blackboard sections per (capability, layer)
#   heartbeats    : %TEMP%\acf_<engine>.heartbeat  (one file per engine)
#   system stats  : psutil
#   failures/IPs  : blackboard
#   commands      : console.commands.dispatch
#
# Debug:  python gui/app.py --probe
# Reads only. Writes nothing except through console.actions via dispatch.
# ============================================================================

import json
import os
import queue
import re
import sys
import time
import traceback
import tkinter as tk
import tkinter.font as tkfont
from collections import Counter, deque
from datetime import datetime
from tkinter import ttk
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config
from platform_utils import get_temp_dir

try:
    from event_reader import start_reader
    _READER_AVAILABLE = True
except ImportError:
    _READER_AVAILABLE = False
    def start_reader(handler):
        pass

try:
    from console import commands as _console_commands
    _COMMANDS_AVAILABLE = True
except Exception:
    _COMMANDS_AVAILABLE = False

try:
    from console import views as _console_views
    _VIEWS_AVAILABLE = True
except Exception:
    _VIEWS_AVAILABLE = False

try:
    from console import state as _console_state
    _CONSOLE_STATE_AVAILABLE = True
except Exception:
    _CONSOLE_STATE_AVAILABLE = False

try:
    import psutil
except Exception:
    psutil = None

# ───────────────────────── theme ─────────────────────────
BG, PANEL, PANEL2 = "#0a1120", "#0f1829", "#131e33"
BORDER, TEXT, MUTED = "#1f2d49", "#e6edf7", "#8794ab"
ACCENT = "#2f6df6"
GREEN, YELLOW, ORANGE = "#22c55e", "#eab308", "#f97316"
RED, PURPLE, BLUE = "#ef4444", "#a855f7", "#3b82f6"

FONT = ("Helvetica", 10)
FONT_B = ("Helvetica", 10, "bold")
FONT_S = ("Helvetica", 9)
FONT_T = ("Helvetica", 11, "bold")
FONT_H = ("Helvetica", 15, "bold")
FONT_XS = ("Helvetica", 8)
MONO = ("Courier", 9)

STATE_COLOR = {"GREEN": GREEN, "YELLOW": YELLOW, "ORANGE": ORANGE, "RED": RED}
STATE_LABEL = {"GREEN": "Healthy", "YELLOW": "Elevated",
               "ORANGE": "Warning", "RED": "Critical"}
STATE_RANK = {"GREEN": 0, "YELLOW": 1, "ORANGE": 2, "RED": 3}

def init_fonts():
    global FONT, FONT_B, FONT_S, FONT_T, FONT_H, FONT_XS, MONO
    fams = set(tkfont.families())
    ui = next((f for f in ("Segoe UI", "SF Pro Text", "Helvetica Neue", "Inter",
                           "DejaVu Sans", "Ubuntu", "Arial") if f in fams),
              "Helvetica")
    mono = next((f for f in ("Consolas", "SF Mono", "Menlo", "DejaVu Sans Mono",
                             "Ubuntu Mono", "Courier New") if f in fams),
                "Courier")
    FONT, FONT_B, FONT_S = (ui, 10), (ui, 10, "bold"), (ui, 9)
    FONT_T, FONT_H, FONT_XS = (ui, 11, "bold"), (ui, 15, "bold"), (ui, 8)
    MONO = (mono, 9)

def tint(color, amount=0.18, base=PANEL):
    c = [int(color[i:i + 2], 16) for i in (1, 3, 5)]
    b = [int(base[i:i + 2], 16) for i in (1, 3, 5)]
    return "#%02x%02x%02x" % tuple(
        int(b[i] + (c[i] - b[i]) * amount) for i in range(3))

def pill(parent, text, color, base=PANEL, dot=False):
    t = ("● " if dot else "") + text
    return tk.Label(parent, text=t, bg=tint(color, 0.22, base), fg=color,
                    font=FONT_S, padx=8, pady=1)

def set_pill(frame, text, color, base=PANEL, dot=False, side="left"):
    sig = (text, color, base, dot)
    if getattr(frame, "_sig", None) == sig:
        return
    frame._sig = sig
    for w in frame.winfo_children():
        w.destroy()
    if text:
        pill(frame, text, color, base=base, dot=dot).pack(side=side)

def card(parent, border=BORDER, bg=PANEL):
    return tk.Frame(parent, bg=bg, highlightbackground=border,
                    highlightthickness=1)

def btn(parent, text, command, bg=PANEL2, fg=TEXT, active=ACCENT, **kw):
    b = tk.Label(parent, text=text, bg=bg, fg=fg,
                 font=kw.pop("font", FONT_S),
                 padx=kw.pop("padx", 10), pady=kw.pop("pady", 4),
                 cursor="hand2", **kw)
    b.bind("<Button-1>", lambda e: command())
    b.bind("<Enter>", lambda e: b.configure(bg=active))
    b.bind("<Leave>", lambda e: b.configure(bg=bg))
    return b

def shield(parent, size=34, color=ACCENT, bg=PANEL):
    c = tk.Canvas(parent, width=size, height=size, bg=bg,
                  highlightthickness=0)
    s = size
    c.create_polygon([s * .5, 2, s - 4, s * .18, s - 4, s * .55,
                      s * .5, s - 2, 4, s * .55, 4, s * .18],
                     outline=color, fill=tint(color, .25, bg), width=2)
    return c

def make_tree(parent, cols, widths, height):
    t = ttk.Treeview(parent, columns=cols, show="headings", height=height,
                     style="Dark.Treeview", selectmode="browse")
    for c, w in zip(cols, widths):
        t.heading(c, text=c, anchor="w")
        t.column(c, width=w, anchor="w", stretch=(c == cols[-1]), minwidth=40)
    t.pack(fill="x", padx=4, pady=(0, 4))
    for lvl, col in {"info": TEXT, "warn": YELLOW, "error": RED,
                     "cycle": GREEN, "debug": MUTED,
                     "Blocked": RED, "Monitored": YELLOW,
                     "Normal": TEXT}.items():
        t.tag_configure(lvl, foreground=col)
    return t

def sync_tree(tree, rows, tag_fn=None):
    sig = tuple(rows)
    if getattr(tree, "_sig", None) == sig:
        return
    tree._sig = sig
    tree.delete(*tree.get_children())
    for r in rows:
        tree.insert("", "end", values=r,
                    tags=((tag_fn(r),) if tag_fn else ()))

def _set_label_text(lbl, text):
    if lbl.cget("text") != text:
        lbl.configure(text=text)

def style_ttk(root):
    s = ttk.Style(root)
    s.theme_use("clam")
    s.configure("Dark.Treeview", background=PANEL, fieldbackground=PANEL,
                foreground=TEXT, rowheight=22, borderwidth=0, font=FONT_S)
    s.configure("Dark.Treeview.Heading", background=PANEL, foreground=MUTED,
                relief="flat", font=FONT_S)
    s.map("Dark.Treeview", background=[("selected", "#1c2d52")])
    s.map("Dark.Treeview.Heading", background=[("active", PANEL)])
    s.configure("TNotebook", background=PANEL, borderwidth=0)
    s.configure("TNotebook.Tab", background=PANEL, foreground=MUTED,
                padding=(12, 5), borderwidth=0, font=FONT_S)
    s.map("TNotebook.Tab", background=[("selected", PANEL)],
          foreground=[("selected", TEXT)])
    s.configure("TCombobox", fieldbackground=PANEL2, background=PANEL2,
                foreground=TEXT, arrowcolor=TEXT, bordercolor=BORDER)
    s.map("TCombobox", fieldbackground=[("readonly", PANEL2)])
    s.configure("Vertical.TScrollbar", background=PANEL2, troughcolor=BG,
                bordercolor=BG, arrowcolor=MUTED)
    root.option_add("*TCombobox*Listbox.background", PANEL2)
    root.option_add("*TCombobox*Listbox.foreground", TEXT)

class ScrollFrame(tk.Frame):
    def __init__(self, parent, bg=BG):
        super().__init__(parent, bg=bg)
        self.canvas = tk.Canvas(self, bg=bg, highlightthickness=0, width=1)
        self.vsb = ttk.Scrollbar(self, orient="vertical",
                                 command=self.canvas.yview)
        self.inner = tk.Frame(self.canvas, bg=bg)
        self._win = self.canvas.create_window((0, 0), window=self.inner,
                                              anchor="nw")
        self.canvas.configure(yscrollcommand=self.vsb.set)
        self.canvas.pack(side="left", fill="both", expand=True)
        self.vsb.pack(side="right", fill="y")
        self._pending_resize = None
        self.inner.bind("<Configure>", self._on_inner_configure)
        self.canvas.bind("<Configure>", self._on_canvas_configure)

    def _on_inner_configure(self, _e=None):
        if self._pending_resize is not None:
            return
        self._pending_resize = self.after(100, self._do_resize)

    def _do_resize(self):
        self._pending_resize = None
        try:
            self.canvas.configure(scrollregion=self.canvas.bbox("all"))
        except Exception:
            pass

    def _on_canvas_configure(self, e):
        try:
            self.canvas.itemconfigure(self._win, width=e.width)
        except Exception:
            pass

# ───────────────────────── shutdown flag ─────────────────────────
_shutdown_requested = False

def request_shutdown():
    global _shutdown_requested
    _shutdown_requested = True

def is_shutdown_requested() -> bool:
    return _shutdown_requested

# ───────────────────────── event queue ─────────────────────────
_event_queue: "queue.Queue[dict]" = queue.Queue(maxsize=4000)

def _on_event(event):
    try:
        _event_queue.put_nowait(event)
    except queue.Full:
        pass
    if _CONSOLE_STATE_AVAILABLE:
        try:
            _console_state.add_event(event)
        except Exception:
            pass

# ───────────────────────── live reads ─────────────────────────
_bb_cache: Dict[str, Any] = {"mtime": 0.0, "data": {}}
_cfg_cache: Dict[str, Any] = {"mtime": 0.0, "data": {}}
_ls_cache: Dict[str, Any] = {"mtime": 0.0, "data": {}}

def _read_json_cached(path: str, cache: Dict[str, Any]) -> Dict[str, Any]:
    try:
        mtime = os.path.getmtime(path)
    except OSError:
        return {}
    if mtime != cache["mtime"]:
        try:
            with open(path, "r", encoding="utf-8") as f:
                cache["data"] = json.load(f)
            cache["mtime"] = mtime
        except Exception:
            return cache["data"] if isinstance(cache["data"], dict) else {}
    data = cache["data"]
    return data if isinstance(data, dict) else {}

def read_blackboard() -> Dict[str, Any]:
    return _read_json_cached(Config.BLACKBOARD_FILE, _bb_cache)

def read_config() -> Dict[str, Any]:
    return _read_json_cached(Config.SYSTEM_CONFIG_FILE, _cfg_cache)

def read_layer_state() -> Dict[str, Any]:
    return _read_json_cached(Config.LAYER_STATE_FILE, _ls_cache)

# ───────────────────────── engine heartbeat files ─────────────────────────
_ENGINE_HEARTBEAT_FILES = [
    ("reader",          "acf_reader.heartbeat"),
    ("monitor_engine",  "acf_monitor_engine.heartbeat"),
    ("ais_engine",      "acf_ais_engine.heartbeat"),
    ("state_engine",    "acf_state_engine.heartbeat"),
    ("response_engine", "acf_response_engine.heartbeat"),
    ("mtd_engine",      "acf_mtd_engine.heartbeat"),
]

def engine_heartbeats() -> List[Tuple[str, int, float]]:
    out = []
    for name, filename in _ENGINE_HEARTBEAT_FILES:
        path = os.path.join(get_temp_dir(), filename)
        try:
            ts = os.path.getmtime(path)
        except OSError:
            ts = 0.0
        out.append((name, 0, ts))
    return out

# ───────────────────────── layer metadata ─────────────────────────
LAYER_DEFS = [
    ("reader",  "R",   "Reader",     MUTED),
    ("layer1",  "L1",  "Monitoring", GREEN),
    ("layer2",  "L2",  "AIS",        BLUE),
    ("layer3",  "L3",  "State",      YELLOW),
    ("layer4a", "L4a", "Response",   RED),
    ("layer4c", "L4c", "MTD",        PURPLE),
]
LAYER_KEYS = [k for k, _, _, _ in LAYER_DEFS]
LAYER_META = {k: (s, n, c) for k, s, n, c in LAYER_DEFS}
LAYER_NUM = {
    "reader":  "R - Reader",
    "layer1":  "1 - Monitoring",
    "layer2":  "2 - AIS",
    "layer3":  "3 - State",
    "layer4a": "4a - Response",
    "layer4c": "4c - MTD",
}

SECTION_FMT = {
    "reader":  "reader_{cap}",
    "layer1":  "layer_1_monitor_{cap}",
    "layer2":  "layer_2_ais_{cap}",
    "layer3":  "layer_3_state_{cap}",
    "layer4a": "layer_4a_response_{cap}",
    "layer4c": "layer_4c_mtd_{cap}",
}

CAP_PREFIXES = ("reader_", "layer_1_monitor_", "layer_2_ais_",
                "layer_3_state_", "layer_4a_response_", "layer_4c_mtd_")

_ALIASES = [("layer4a", ("layer4a", "l4a", "4a", "response")),
            ("layer4c", ("layer4c", "l4c", "4c", "mtd")),
            ("layer1",  ("layer1", "l1", "1", "monitor", "reader")),
            ("layer2",  ("layer2", "l2", "2", "ais")),
            ("layer3",  ("layer3", "l3", "3", "state"))]

def norm_layer(name) -> Optional[str]:
    s = re.sub(r"[^a-z0-9]", "", str(name).lower())
    for key, toks in _ALIASES:
        if any(s.startswith(t) for t in toks):
            return key
    return None

def capabilities_from_blackboard(bb: Dict[str, Any]) -> List[str]:
    caps = set()
    for k in bb:
        if isinstance(k, str):
            for p in CAP_PREFIXES:
                if k.startswith(p) and len(k) > len(p):
                    caps.add(k[len(p):])
    return sorted(caps)

def capabilities_from_config() -> List[str]:
    cfg = read_config()
    cl = cfg.get("capability_layers", {})
    if isinstance(cl, dict) and cl:
        return sorted(cl.keys())
    enabled = cfg.get("enabled_capabilities", {})
    if isinstance(enabled, dict):
        out = [k for k, v in enabled.items() if k != "custom" and v]
        custom = enabled.get("custom", {})
        if isinstance(custom, dict):
            out += [k for k, v in custom.items() if v]
        return sorted(out)
    return []

def get_capabilities(bb: Dict[str, Any]) -> List[str]:
    return capabilities_from_config() or capabilities_from_blackboard(bb)

def layers_for(cap: str) -> List[str]:
    cfg = read_config()
    cl = cfg.get("capability_layers", {})
    if isinstance(cl, dict) and isinstance(cl.get(cap), list):
        return [n for n in (norm_layer(x) for x in cl[cap]) if n]
    enabled = cfg.get("enabled_capabilities", {})
    if isinstance(enabled, dict):
        custom = enabled.get("custom", {})
        if (isinstance(custom, dict) and custom.get(cap)) or enabled.get(cap):
            return list(LAYER_KEYS)
    return []

def _fmt_age(ts) -> str:
    if not isinstance(ts, (int, float)) or ts <= 0:
        return "—"
    age = int(time.time() - ts)
    if age < 60:
        return f"{age}s ago"
    if age < 3600:
        return f"{age // 60}m ago"
    return f"{age // 3600}h ago"

def _fmt_hhmmss(ts) -> str:
    if not isinstance(ts, (int, float)) or ts <= 0:
        return "--:--:--"
    try:
        return time.strftime("%H:%M:%S", time.localtime(ts))
    except Exception:
        return "--:--:--"

# ───────────────────────── observation extraction ─────────────────────────
def observation_for(bb: Dict[str, Any], cap: str, layer_key: str
                    ) -> Tuple[str, str, str, Optional[Tuple[str, str]]]:
    ts_str, main, extra = "--:--:--", "no data", ""
    badge: Optional[Tuple[str, str]] = None

    if layer_key == "reader":
        sec = bb.get(f"reader_{cap}")
        if isinstance(sec, dict):
            ts_str = _fmt_hhmmss(sec.get("reading_timestamp"))
            n = sec.get("last_failures_cumulative", 0)
            ready = sec.get("reader_ready")
            main = f"{n} cumulative failures"
            extra = f"backend={sec.get('backend', '?')}  ready={ready}"
            badge = ("Ready", GREEN) if ready else ("Not ready", YELLOW)
        return ts_str, main, extra, badge

    if layer_key == "layer1":
        sec = bb.get(f"layer_1_monitor_{cap}")
        if isinstance(sec, dict):
            ts_str = _fmt_hhmmss(sec.get("monitoring_timestamp"))
            n = sec.get("last_failures", 0)
            h = sec.get("monitor_healthy")
            main = f"{n} detections"
            extra = f"healthy={h}"
            badge = ("Healthy", GREEN) if h else ("Degraded", YELLOW)
            return ts_str, main, extra, badge
        sec = bb.get("layer_1_sensor_ext")
        if cap == "sensor" and isinstance(sec, dict):
            ts_str = _fmt_hhmmss(sec.get("sensor_timestamp")
                                 or sec.get("monitoring_timestamp"))
            main = (f"cpu={sec.get('cpu_percent', '?')}% "
                    f"mem={sec.get('memory_percent', '?')}%")
            extra = (f"conns={sec.get('active_connections', '?')} "
                     f"unknown={sec.get('unknown_connection_count', '?')}")
            badge = ("Healthy", GREEN)
        return ts_str, main, extra, badge

    if layer_key == "layer2":
        sec = bb.get(f"layer_2_ais_{cap}")
        if isinstance(sec, dict):
            ts_str = _fmt_hhmmss(sec.get("ais_timestamp"))
            risk = sec.get("risk", 0)
            det = sec.get("detail", {}) if isinstance(sec.get("detail"), dict) else {}
            behavs = det.get("behaviors", {}) if isinstance(det, dict) else {}
            bname = (next(iter(behavs.keys()), None)
                     if isinstance(behavs, dict) and behavs else None)
            main = bname or "no behavior"
            extra = f"risk: {risk}    attacker: {sec.get('attacker_ip', '—')}"
            try:
                r = int(risk or 0)
            except Exception:
                r = 0
            badge = ("High risk", RED) if r >= 65 else ("Healthy", GREEN)
        return ts_str, main, extra, badge

    if layer_key == "layer3":
        sec = bb.get(f"layer_3_state_{cap}")
        if isinstance(sec, dict):
            ts_str = _fmt_hhmmss(sec.get("state_timestamp"))
            cur = str(sec.get("state", "?")).upper()
            prev = str(sec.get("previous_state", "?")).upper()
            main = f"{prev} → {cur}"
            det = sec.get("detail", {}) if isinstance(sec.get("detail"), dict) else {}
            extra = f"reason: {det.get('transition', '—')}"
            badge = (main if prev != cur else cur, STATE_COLOR.get(cur, MUTED))
        return ts_str, main, extra, badge

    if layer_key == "layer4a":
        sec = bb.get(f"layer_4a_response_{cap}")
        if isinstance(sec, dict):
            ts_str = _fmt_hhmmss(sec.get("response_timestamp"))
            blocked = sec.get("blocked_ips") or []
            iso = sec.get("isolation_active")
            actions = sec.get("actions") or []
            last = actions[-1] if actions else {}
            main = (last.get("action", "no action")
                    if isinstance(last, dict) else "no action")
            extra = (f"blocked: {len(blocked)}    isolated: {iso}    "
                     f"method: {sec.get('method', '—')}")
            badge = ("Active", RED) if blocked or iso else ("Idle", MUTED)
        return ts_str, main, extra, badge

    if layer_key == "layer4c":
        sec = bb.get(f"layer_4c_mtd_{cap}")
        if isinstance(sec, dict):
            ts_str = _fmt_hhmmss(sec.get("mtd_timestamp"))
            port = sec.get("port")
            actions = sec.get("actions") or []
            reg = sec.get("action_registry", {})
            ready = [n for n, v in (reg.items() if isinstance(reg, dict) else [])
                     if isinstance(v, dict)
                     and v.get("preflight_status") == "READY"]
            main = f"port {port}"
            extra = f"actions: {len(actions)}    ready: {','.join(ready) or '—'}"
            badge = ("Active", PURPLE) if actions else ("Idle", MUTED)
        return ts_str, main, extra, badge

    return ts_str, main, extra, badge

def level_of(layer_key: str, main: str, badge) -> Optional[str]:
    if badge is None:
        return None
    if layer_key == "reader":
        return "info" if badge[0] == "Ready" else "warn"
    if layer_key == "layer1":
        m = re.match(r"(\d+) detections", main)
        if m and int(m.group(1)) > 0:
            return "error"
        return "warn" if badge[1] == YELLOW else "info"
    if layer_key in ("layer2", "layer3"):
        return {RED: "error", YELLOW: "warn", ORANGE: "warn"}.get(badge[1], "info")
    return "info"

def overall_state(bb: Dict[str, Any]) -> str:
    worst = None
    for k, v in bb.items():
        if isinstance(k, str) and k.startswith("layer_3_state") \
                and isinstance(v, dict):
            st = str(v.get("state", "")).upper()
            if st in STATE_RANK and (worst is None
                                     or STATE_RANK[st] > STATE_RANK[worst]):
                worst = st
    return worst or "N/A"

def system_health() -> Dict[str, Any]:
    bb = read_blackboard()
    cfg = read_config()

    layers_cfg = cfg.get("layers", {}) if isinstance(cfg, dict) else {}
    layers_enabled = (sum(1 for v in layers_cfg.values() if v)
                      if isinstance(layers_cfg, dict) and layers_cfg else None)

    running = 0
    total = len(_ENGINE_HEARTBEAT_FILES)
    now = time.time()
    for _name, filename in _ENGINE_HEARTBEAT_FILES:
        try:
            age = now - os.path.getmtime(
                os.path.join(get_temp_dir(), filename))
            if age < 60:
                running += 1
        except OSError:
            pass

    caps = get_capabilities(bb)
    caps_live = sum(1 for c in caps if any(
        isinstance(bb.get(SECTION_FMT[k].format(cap=c)), dict)
        for k in LAYER_KEYS))
    return {
        "layers_enabled": layers_enabled,
        "layers_total": len([k for k in LAYER_KEYS if k != "reader"]),
        "engines_running": running,
        "engines_total": total,
        "capabilities": caps,
        "caps_total": len(caps),
        "caps_live": caps_live,
        "state": overall_state(bb),
        "bb": bb,
    }

def recent_failures(bb: Dict[str, Any], limit: int = 5
                    ) -> List[Tuple[str, str, str, str]]:
    out = []
    for k, v in bb.items():
        if isinstance(k, str) and k.startswith("layer_1_monitor_") \
                and isinstance(v, dict):
            n = v.get("last_failures")
            if isinstance(n, int) and n > 0:
                out.append((_fmt_hhmmss(v.get("monitoring_timestamp")), "L1",
                            k[len("layer_1_monitor_"):], f"{n} detections"))
    for k, v in bb.items():
        if isinstance(k, str) and k.startswith("layer_4a_response_") \
                and isinstance(v, dict):
            for a in (v.get("actions") or [])[-3:]:
                if isinstance(a, dict) and a.get("error"):
                    out.append((_fmt_hhmmss(a.get("ts")), "L4a",
                                k[len("layer_4a_response_"):],
                                str(a.get("error"))[:60]))
    return out[:limit]

def top_ips(bb: Dict[str, Any], limit: int = 6
            ) -> List[Tuple[str, int, int, str]]:
    rows: Dict[str, Dict[str, Any]] = {}
    for k, v in bb.items():
        if isinstance(k, str) and k.startswith("layer_2_ais_") \
                and isinstance(v, dict):
            for t in v.get("known_threats") or []:
                if not isinstance(t, dict):
                    continue
                ip = t.get("ip") or t.get("actor")
                if not isinstance(ip, str) or not ip:
                    continue
                e = rows.setdefault(ip, {"hits": 0, "conf": 0, "blocked": False})
                try:
                    e["hits"] += int(t.get("hits", 0) or 0)
                    e["conf"] = max(e["conf"],
                                    int(t.get("confidence", 0) or 0))
                except Exception:
                    pass
    for k, v in bb.items():
        if isinstance(k, str) and k.startswith("layer_4a_response_") \
                and isinstance(v, dict):
            for b in v.get("blocked_ips") or []:
                ip = (b.get("ip") if isinstance(b, dict)
                      else b if isinstance(b, str) else None)
                if isinstance(ip, str):
                    rows.setdefault(ip, {"hits": 0, "conf": 0,
                                         "blocked": False})["blocked"] = True
    out = []
    for ip, e in rows.items():
        status = ("Blocked" if e["blocked"]
                  else "Monitored" if e["conf"] >= 50 else "Normal")
        out.append((ip, e["hits"], e["conf"], status))
    out.sort(key=lambda r: (-r[1], -r[2]))
    return out[:limit]

def active_entities(bb: Dict[str, Any]):
    ips = [(ip, st) for ip, _h, _c, st in top_ips(bb, 6)]
    groups, behaviors = Counter(), Counter()
    for k, v in bb.items():
        if isinstance(k, str) and k.startswith("layer_2_ais_") \
                and isinstance(v, dict):
            det = v.get("detail", {}) if isinstance(v.get("detail"), dict) else {}
            g = v.get("group_id") or v.get("group") \
                or det.get("group_id") or det.get("group")
            if g:
                groups[f"#{g}"] += 1
            b = det.get("behaviors")
            if isinstance(b, dict):
                for name in b:
                    behaviors[str(name)] += 1
    return (ips,
            [(g, n) for g, n in groups.most_common(6)],
            [(b, n) for b, n in behaviors.most_common(6)])

# ───────────────────────── main window ─────────────────────────
class ACFApp(tk.Tk):

    def __init__(self):
        super().__init__()
        init_fonts()
        self.title("ACF – Autonomous Cybersecurity Framework")
        sw, sh = self.winfo_screenwidth(), self.winfo_screenheight()
        w = min(1536, sw - 40)
        h = min(960, sh - 90)
        self.geometry(f"{w}x{h}+{max(0, (sw - w) // 2)}"
                      f"+{max(0, (sh - h) // 2 - 20)}")
        self.minsize(1000, 600)
        self.configure(bg=BG)
        style_ttk(self)
        self.start = time.time()

        self.nav_labels: Dict[str, tk.Label] = {}
        self.cap_labels: Dict[str, tk.Label] = {}
        self.selected_cap: Optional[str] = None
        self.selected_layer = "layer1"
        self.layer_cards: Dict[str, Dict[str, Any]] = {}
        self.hb_rows: Dict[str, Dict[str, tk.Label]] = {}
        self.cur_obs: Dict[Tuple[str, str], Dict[str, Any]] = {}
        self.history: Dict[Tuple[str, str], deque] = {}
        self.events: deque = deque(maxlen=1000)
        self.paused = False
        self.selected_filter = "all"
        self.cmd_history: List[str] = []
        self.cmd_hist_idx = -1
        self._scrollers: List[ScrollFrame] = []
        self._last_render_ts = 0.0

        self.columnconfigure(1, weight=1)
        self.rowconfigure(1, weight=1)

        self.build_topbar()
        self.build_sidebar()
        self.build_center()
        self.build_right()
        self.bind_all("<MouseWheel>", self._on_wheel)
        self.bind_all("<Button-4>", self._on_wheel)
        self.bind_all("<Button-5>", self._on_wheel)

        self.tick()
        self.refresh()
        self.drain_events()
        self.poll_shutdown()

    def _on_wheel(self, e):
        w = self.winfo_containing(e.x_root, e.y_root)
        if w is None or w.winfo_class() in ("Treeview", "Text",
                                             "TCombobox", "Listbox"):
            return
        step = -3 if (getattr(e, "num", 0) == 4
                      or getattr(e, "delta", 0) > 0) else 3
        while w is not None:
            for sf in self._scrollers:
                if w is sf or w is sf.canvas or w is sf.inner:
                    sf.canvas.yview_scroll(step, "units")
                    return
            w = w.master

    def _scroll_frame(self, parent, bg=BG) -> ScrollFrame:
        sf = ScrollFrame(parent, bg=bg)
        self._scrollers.append(sf)
        return sf

    # ── top bar ──
    def build_topbar(self):
        bar = tk.Frame(self, bg=PANEL, highlightbackground=BORDER,
                       highlightthickness=1)
        bar.grid(row=0, column=0, columnspan=3, sticky="ew")

        logo = tk.Frame(bar, bg=PANEL)
        logo.pack(side="left", padx=14, pady=8)
        shield(logo).pack(side="left")
        t = tk.Frame(logo, bg=PANEL)
        t.pack(side="left", padx=8)
        tk.Label(t, text="ACF", bg=PANEL, fg=TEXT,
                 font=(FONT_H[0], 16, "bold")).pack(anchor="w")
        tk.Label(t, text="Autonomous Cybersecurity Framework",
                 bg=PANEL, fg=MUTED, font=FONT_XS).pack(anchor="w")

        self.chip_health, self.chip_dot = self._chip(bar, "System: --", MUTED)
        self.chip_layers, _ = self._chip(bar, "Layers  --")
        self.chip_engines, _ = self._chip(bar, "Engines  --")
        self.chip_caps, _ = self._chip(bar, "Capabilities  --")
        self.chip_uptime, _ = self._chip(bar, "Uptime  --")
        self.err_lbl = tk.Label(bar, text="", bg=PANEL, fg=RED, font=FONT_S)
        self.err_lbl.pack(side="left", padx=10)

        self.clock_lbl = tk.Label(bar, bg=PANEL, fg=TEXT, font=FONT)
        self.clock_lbl.pack(side="right", padx=14)

    def _chip(self, parent, text, color=None):
        f = tk.Frame(parent, bg=PANEL2, highlightbackground=BORDER,
                     highlightthickness=1)
        f.pack(side="left", padx=6, pady=10)
        dot = None
        if color:
            dot = tk.Label(f, text="●", bg=PANEL2, fg=color)
            dot.pack(side="left", padx=(8, 2))
        lbl = tk.Label(f, text=text, bg=PANEL2, fg=TEXT, font=FONT,
                       padx=6, pady=3)
        lbl.pack(side="left")
        return lbl, dot

    def _noop(self):
        pass

    # ── sidebar ──
    def build_sidebar(self):
        wrap = tk.Frame(self, bg=PANEL, width=235,
                        highlightbackground=BORDER, highlightthickness=1)
        wrap.grid(row=1, column=0, sticky="ns")
        wrap.pack_propagate(False)
        sf = self._scroll_frame(wrap, bg=PANEL)
        sf.pack(fill="both", expand=True)
        sb = sf.inner

        tk.Label(sb, text="▣  Capabilities", bg=PANEL, fg=TEXT, font=FONT_B,
                 anchor="w").pack(fill="x", padx=14, pady=(14, 6))
        self.cap_container = tk.Frame(sb, bg=PANEL)
        self.cap_container.pack(fill="x")

        tk.Label(sb, text="▣  System Views", bg=PANEL, fg=TEXT, font=FONT_B,
                 anchor="w").pack(fill="x", padx=14, pady=(14, 6))
        for name in ("Summary", "Health", "Failures", "IPs", "Events (Live)",
                     "System", "Configuration", "Logs", "Help"):
            lb = tk.Label(sb, text=f"  •   {name}", anchor="w", bg=PANEL,
                          fg=TEXT, font=FONT, padx=10, pady=4, cursor="hand2")
            lb.pack(fill="x", padx=8, pady=1)
            lb.bind("<Button-1>", lambda e, n=name: self.show_view(n))
            self.nav_labels[name] = lb

        tk.Label(sb, text="▣  Quick Commands", bg=PANEL, fg=TEXT,
                 font=FONT_B, anchor="w").pack(fill="x", padx=14, pady=(14, 6))

        qk = tk.Frame(sb, bg=PANEL)
        qk.pack(fill="x", padx=10, pady=(0, 8))
        qk.columnconfigure((0, 1), weight=1, uniform="q")

        quick = [
            "diag events", "diag events all",
            "diag summary", "diag state",
            "diag ips", "diag failures",
            "diag reader", "diag monitor",
            "diag ais", "diag response",
            "diag mtd", "diag health",
        ]
        for i, cmd in enumerate(quick):
            btn(qk, f"⊕  {cmd}", lambda c=cmd: self.run_cmd(c),
                anchor="w", padx=6, pady=3).grid(
                row=i // 2, column=i % 2, sticky="ew", padx=2, pady=1)

    def rebuild_capability_list(self, caps: List[str]):
        if set(self.cap_labels) == set(caps) and (self.cap_labels or not caps):
            return
        for w in self.cap_container.winfo_children():
            w.destroy()
        self.cap_labels.clear()
        if not caps:
            tk.Label(self.cap_container,
                     text="  no capabilities found\n  (run: gui.py --probe)",
                     bg=PANEL, fg=YELLOW, font=FONT_S, justify="left",
                     anchor="w").pack(fill="x", padx=8, pady=4)
            return
        for cap in caps:
            lb = tk.Label(self.cap_container, text=f"  ◇   {cap}", anchor="w",
                          bg=PANEL, fg=TEXT, font=FONT, padx=10, pady=6,
                          cursor="hand2")
            lb.pack(fill="x", padx=8, pady=1)
            lb.bind("<Button-1>", lambda e, c=cap: self.select_capability(c))
            self.cap_labels[cap] = lb
        if self.selected_cap not in caps:
            self.select_capability(caps[0])
        else:
            self.select_capability(self.selected_cap)

    def select_capability(self, cap: str):
        for c, lb in self.cap_labels.items():
            lb.configure(bg=ACCENT if c == cap else PANEL,
                         fg="white" if c == cap else TEXT)
        self.selected_cap = cap
        self.render_events()

    # ── center ──
    def build_center(self):
        sf = self._scroll_frame(self)
        sf.grid(row=1, column=1, sticky="nsew", padx=(10, 6), pady=8)
        c = sf.inner
        c.columnconfigure(0, weight=1)

        head = tk.Frame(c, bg=BG)
        head.grid(row=0, column=0, sticky="ew", pady=(0, 8))
        shield(head, 28, GREEN, BG).pack(side="left")
        tk.Label(head, text="ACF Platform", bg=BG, fg=TEXT,
                 font=FONT_H).pack(side="left", padx=8)

        for i, (key, short, name, color) in enumerate(LAYER_DEFS, start=1):
            self.build_layer_card(c, key, short, name, color).grid(
                row=i, column=0, sticky="ew", pady=4)

        self.build_details(c, row=len(LAYER_DEFS) + 1)
        self.build_bottom(c, row=len(LAYER_DEFS) + 2)

    def build_layer_card(self, parent, key, short, name, color):
        outer = card(parent, border=color)
        top = tk.Frame(outer, bg=PANEL)
        top.pack(fill="x", padx=10, pady=(8, 4))
        tk.Label(top, text=short, fg=color, bg=tint(color, .2),
                 font=(FONT_B[0], 12, "bold"), width=4, height=2,
                 highlightbackground=color,
                 highlightthickness=1).pack(side="left")
        title = tk.Frame(top, bg=PANEL)
        title.pack(side="left", padx=10)
        tk.Label(title, text=name, bg=PANEL, fg=TEXT,
                 font=(FONT_B[0], 13, "bold")).pack(side="left")
        tk.Label(title, text=f" ({short})", bg=PANEL, fg=MUTED,
                 font=FONT).pack(side="left", pady=(3, 0))
        hdr_badge = tk.Frame(title, bg=PANEL)
        hdr_badge.pack(side="left", padx=10)
        arrow = tk.Label(top, text="⌃", bg=PANEL, fg=MUTED, cursor="hand2")
        arrow.pack(side="right")

        body = tk.Frame(outer, bg=PANEL2, highlightbackground=BORDER,
                        highlightthickness=1)
        body.pack(fill="x", padx=(66, 10), pady=(0, 8))

        # one block per capability (sub-headings), populated on refresh
        caps_container = tk.Frame(body, bg=PANEL2)
        caps_container.pack(fill="x")

        def toggle(_e=None):
            if body.winfo_ismapped():
                body.pack_forget()
                arrow.configure(text="⌄")
            else:
                body.pack(fill="x", padx=(66, 10), pady=(0, 8))
                arrow.configure(text="⌃")
        arrow.bind("<Button-1>", toggle)

        def bind_select(w):
            if w is not arrow:
                w.bind("<Button-1>",
                       lambda e, k=key: self.select_layer(k), add="+")
            for ch in w.winfo_children():
                bind_select(ch)
        bind_select(outer)

        self.layer_cards[key] = {
            "card": outer, "hdr": hdr_badge,
            "container": caps_container, "color": color,
            "cap_blocks": {},   # cap -> {"cur":{...}, "prev":{...}}
        }
        return outer

    def _make_obs_row(self, parent, label, active):
        r = tk.Frame(parent, bg=PANEL2)
        r.pack(fill="x", padx=10, pady=2)
        tk.Label(r, text=label, width=18, anchor="w", bg=PANEL2,
                 fg=TEXT if active else MUTED,
                 font=FONT_S).pack(side="left")
        tm = tk.Label(r, text="--:--:--", bg=PANEL2, fg=MUTED,
                      font=FONT_S, width=9)
        tm.pack(side="left")
        main = tk.Label(r, text="—", bg=PANEL2,
                        fg=TEXT if active else MUTED,
                        font=FONT_B if active else FONT_S, anchor="w")
        main.pack(side="left", padx=(8, 14))
        extra = tk.Label(r, text="", bg=PANEL2,
                         fg=TEXT if active else MUTED, font=FONT_S)
        extra.pack(side="left")
        badge = tk.Frame(r, bg=PANEL2)
        badge.pack(side="right")
        return {"row": r, "time": tm, "main": main, "extra": extra,
                "badge": badge}

    def _cap_block_for(self, key: str, cap: str):
        cell = self.layer_cards.get(key)
        if cell is None:
            return None
        blocks = cell["cap_blocks"]
        if cap in blocks:
            return blocks[cap]
        parent = cell["container"]
        frame = tk.Frame(parent, bg=PANEL2)
        frame.pack(fill="x", pady=(6, 2))
        tk.Label(frame, text=cap, bg=PANEL2, fg=TEXT,
                 font=FONT_B, anchor="w").pack(fill="x", padx=10)
        cur = self._make_obs_row(frame, "Current observation", True)
        prev = self._make_obs_row(frame, "Previous observation", False)
        sep = tk.Frame(frame, bg=BORDER, height=1)
        sep.pack(fill="x", padx=10, pady=(4, 0))
        blocks[cap] = {"frame": frame, "cur": cur, "prev": prev}
        return blocks[cap]

    def select_layer(self, key: str):
        self.selected_layer = key
        for k, cell in self.layer_cards.items():
            cell["card"].configure(highlightthickness=2 if k == key else 1)
        self.update_details(read_blackboard())

    def build_details(self, parent, row):
        box = card(parent)
        box.grid(row=row, column=0, sticky="ew", pady=(6, 4))
        nb = ttk.Notebook(box)
        nb.pack(fill="x")
        t1 = tk.Frame(nb, bg=PANEL)
        t2 = tk.Frame(nb, bg=PANEL)
        t3 = tk.Frame(nb, bg=PANEL)
        nb.add(t1, text="Observation Details")
        nb.add(t2, text="Evidence")
        nb.add(t3, text="History")
        btn(box, "View Full Event", self.view_full_event).place(
            relx=1.0, x=-10, y=4, anchor="ne")

        head = tk.Frame(t1, bg=PANEL)
        head.pack(fill="x", padx=10, pady=(8, 4))
        self.detail_badge = tk.Frame(head, bg=PANEL)
        self.detail_badge.pack(side="left")
        self.detail_title = tk.Label(head, text="—", bg=PANEL, fg=TEXT,
                                     font=FONT_T)
        self.detail_title.pack(side="left", padx=8)

        grid = tk.Frame(t1, bg=PANEL)
        grid.pack(fill="x", padx=10, pady=(0, 8))
        grid.columnconfigure((0, 1), weight=1, uniform="g")
        self.detail_left = self._kv_table(
            grid, 0, ["WHEN", "LAYER", "CAPABILITY", "FROM (previous)",
                      "TO (current)", "WHY / CONTEXT", "SOURCE"])
        self.detail_right = self._kv_table(
            grid, 1, [f"_{i}" for i in range(7)], title="Related Evidence")

        self.evid_tree = make_tree(t2, ("Time", "Level", "Source", "Message"),
                                   (62, 52, 90, 300), height=6)
        self.hist_tree = make_tree(
            t3, ("Time", "Observation", "Detail", "Status"),
            (70, 200, 260, 90), height=6)

    def _kv_table(self, grid, col, keys, title=None):
        f = tk.Frame(grid, bg=PANEL2, highlightbackground=BORDER,
                     highlightthickness=1)
        f.grid(row=0, column=col, sticky="nsew", padx=(0 if col == 0 else 8, 0))
        if title:
            tk.Label(f, text=title, bg=PANEL2, fg=TEXT,
                     font=FONT_B).pack(anchor="w", padx=8, pady=(6, 2))
        rows = []
        for k in keys:
            r = tk.Frame(f, bg=PANEL2)
            r.pack(fill="x", padx=8, pady=1)
            kl = tk.Label(r, text=k if not k.startswith("_") else "",
                          width=15, anchor="w", bg=PANEL2, fg=MUTED,
                          font=FONT_S)
            kl.pack(side="left")
            vl = tk.Label(r, text="—" if not k.startswith("_") else "",
                          anchor="w", bg=PANEL2, fg=TEXT, font=FONT_S,
                          wraplength=240, justify="left")
            vl.pack(side="left", fill="x", expand=True)
            rows.append((kl, vl))
        tk.Frame(f, bg=PANEL2, height=4).pack()
        return rows

    def build_bottom(self, parent, row):
        wrap = tk.Frame(parent, bg=BG)
        wrap.grid(row=row, column=0, sticky="ew", pady=(4, 0))
        wrap.columnconfigure(0, weight=3)
        wrap.columnconfigure(1, weight=2)

        q = card(wrap)
        q.grid(row=0, column=0, sticky="nsew", padx=(0, 8))
        tk.Label(q, text="Command Console", bg=PANEL, fg=TEXT,
                 font=FONT_S).grid(row=0, column=0, columnspan=3,
                                    sticky="w", padx=8, pady=4)

        self.cmd_var = tk.StringVar(value="")
        self.cmd_entry = tk.Entry(q, textvariable=self.cmd_var,
                                  bg="#080e1a", fg=TEXT,
                                  insertbackground=TEXT, relief="flat",
                                  font=MONO)
        self.cmd_entry.grid(row=1, column=0, columnspan=2,
                            sticky="ew", padx=(8, 4), pady=(0, 6))
        self.cmd_entry.bind("<Return>",
                            lambda e: self.run_cmd(self.cmd_var.get()))
        self.cmd_entry.bind("<Up>", lambda e: self._history_step(-1))
        self.cmd_entry.bind("<Down>", lambda e: self._history_step(1))

        btn(q, "Run", lambda: self.run_cmd(self.cmd_var.get()),
            bg=ACCENT, fg="white", active="#4a82ff",
            padx=12, pady=3).grid(row=1, column=2, padx=(0, 8),
                                   pady=(0, 6), sticky="ew")

        self.console_out = tk.Text(q, height=8, bg="#080e1a", fg=TEXT,
                                   font=MONO, relief="flat", wrap="word")
        self.console_out.grid(row=2, column=0, columnspan=3,
                              sticky="ew", padx=8, pady=(0, 8))
        self.console_out.configure(state="disabled")

        q.columnconfigure(0, weight=1)
        q.columnconfigure(1, weight=0)
        q.columnconfigure(2, weight=0)

        r = card(wrap)
        r.grid(row=0, column=1, sticky="nsew")
        tk.Label(r, text="Recent Change", bg=PANEL, fg=TEXT,
                 font=FONT_S).pack(anchor="w", padx=8, pady=4)
        self.recent_body = tk.Frame(r, bg=PANEL)
        self.recent_body.pack(fill="x", padx=8, pady=(0, 8))

    # ── right panel ──
    def build_right(self):
        wrap = tk.Frame(self, bg=BG, width=490)
        wrap.grid(row=1, column=2, sticky="ns", padx=(0, 10), pady=8)
        wrap.pack_propagate(False)
        sf = self._scroll_frame(wrap)
        sf.pack(fill="both", expand=True)
        rp = sf.inner
        rp.columnconfigure(0, weight=1)

        live = card(rp)
        live.grid(row=0, column=0, sticky="ew")
        h = tk.Frame(live, bg=PANEL)
        h.pack(fill="x", padx=10, pady=6)
        tk.Label(h, text="●", fg=BLUE, bg=PANEL,
                 font=(FONT[0], 12)).pack(side="left")
        self.live_title = tk.Label(h, text="Live View", bg=PANEL,
                                   fg=TEXT, font=FONT_T)
        self.live_title.pack(side="left", padx=6)
        self.pause_btn = btn(h, "Pause", self.toggle_pause, pady=1)
        self.pause_btn.pack(side="right", padx=(6, 0))

        self.filter_var = tk.StringVar(value="All capabilities")
        self.filter_cb = ttk.Combobox(h, textvariable=self.filter_var,
                                      values=["All capabilities"],
                                      state="readonly", width=18)
        self.filter_cb.pack(side="right", padx=6)
        self.filter_cb.bind("<<ComboboxSelected>>",
                            lambda e: self._on_filter_change())
        tk.Label(h, text="2s refresh", bg=PANEL, fg=MUTED,
                 font=FONT_XS).pack(side="right", padx=6)

        nb = ttk.Notebook(live)
        nb.pack(fill="x")
        ev = tk.Frame(nb, bg=PANEL)
        evf = tk.Frame(nb, bg=PANEL)
        nb.add(ev, text="Events")
        nb.add(evf, text="Warnings / Errors")
        cols = ("Time", "Level", "Source", "Message")
        widths = (62, 50, 90, 260)
        self.ev_tree = make_tree(ev, cols, widths, height=9)
        self.evf_tree = make_tree(evf, cols, widths, height=9)

        so = card(rp)
        so.grid(row=1, column=0, sticky="ew", pady=8)
        h = tk.Frame(so, bg=PANEL)
        h.pack(fill="x", padx=10, pady=6)
        tk.Label(h, text="System Overview", bg=PANEL, fg=TEXT,
                 font=FONT_T).pack(side="left")
        self.overview_badge = tk.Frame(h, bg=PANEL)
        self.overview_badge.pack(side="right")

        stats = tk.Frame(so, bg=PANEL)
        stats.pack(fill="x", padx=10)

        def statbox(items):
            f = tk.Frame(stats, bg=PANEL2, highlightbackground=BORDER,
                         highlightthickness=1)
            f.pack(side="left", fill="x", expand=True, padx=3)
            labels = {}
            for i, k in enumerate(items):
                s = tk.Frame(f, bg=PANEL2)
                s.grid(row=0, column=i, padx=8, pady=4)
                tk.Label(s, text=k, bg=PANEL2, fg=MUTED,
                         font=FONT_XS).pack(anchor="w")
                v = tk.Label(s, text="—", bg=PANEL2, fg=TEXT,
                             font=(FONT_B[0], 13, "bold"))
                v.pack(anchor="w")
                labels[k] = v
            return labels

        self.stat_engines = statbox(["Engines", "Layers", "Capabilities"])
        self.stat_res = statbox(["CPU", "Memory", "Disk"])

        tk.Label(so, text="Engine Heartbeat", bg=PANEL, fg=TEXT,
                 font=FONT_B).pack(anchor="w", padx=10, pady=(8, 2))
        self.hb_container = tk.Frame(so, bg=PANEL)
        self.hb_container.pack(fill="x")
        tk.Frame(so, bg=PANEL, height=6).pack()

        fl = card(rp)
        fl.grid(row=2, column=0, sticky="ew")
        h = tk.Frame(fl, bg=PANEL)
        h.pack(fill="x", padx=10, pady=6)
        tk.Label(h, text="⚠", fg=RED, bg=PANEL).pack(side="left")
        tk.Label(h, text=" Recent Failures", bg=PANEL, fg=TEXT,
                 font=FONT_T).pack(side="left")
        self.fail_badge = tk.Frame(h, bg=PANEL)
        self.fail_badge.pack(side="right")
        self.fail_tree = make_tree(fl, ("Time", "Layer", "Engine", "Message"),
                                   (62, 50, 80, 260), height=3)

        ip = card(rp)
        ip.grid(row=3, column=0, sticky="ew", pady=8)
        tk.Label(ip, text="Top IPs (24h)", bg=PANEL, fg=TEXT,
                 font=FONT_T).pack(anchor="w", padx=10, pady=6)
        self.ip_tree = make_tree(ip, ("IP", "Hits", "Conf", "Status"),
                                 (140, 50, 60, 110), height=5)

        ae = card(rp)
        ae.grid(row=4, column=0, sticky="ew")
        tk.Label(ae, text="Active Entities", bg=PANEL, fg=TEXT,
                 font=FONT_T).pack(anchor="w", padx=10, pady=6)
        nb2 = ttk.Notebook(ae)
        nb2.pack(fill="x")
        tabs = {}
        for name, cols, widths in (
            ("IPs", ("IP", "Status"), (200, 120)),
            ("Groups", ("Group", "Capabilities"), (200, 120)),
            ("Behaviors", ("Behavior", "Count"), (200, 120))):
            fr = tk.Frame(nb2, bg=PANEL)
            nb2.add(fr, text=name)
            tabs[name] = make_tree(fr, cols, widths, height=4)
        self.ent_ips = tabs["IPs"]
        self.ent_groups = tabs["Groups"]
        self.ent_behav = tabs["Behaviors"]

    def _on_filter_change(self):
        v = self.filter_var.get()
        self.selected_filter = "all" if v == "All capabilities" else v
        self.render_events()

    # ── live view controls ──
    def toggle_pause(self):
        self.paused = not self.paused
        self.pause_btn.configure(text="Resume" if self.paused else "Pause")
        if not self.paused:
            self.render_events()

    # ── behaviour ──
    def tick(self):
        if _shutdown_requested:
            self.quit()
            return
        self.clock_lbl.configure(
            text=datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
        s = int(time.time() - self.start)
        d, s = divmod(s, 86400)
        h, s = divmod(s, 3600)
        self.chip_uptime.configure(text=f"Uptime  {d}d {h}h {s // 60}m")
        self.after(1000, self.tick)

    def poll_shutdown(self):
        if _shutdown_requested:
            self.quit()
            return
        self.after(200, self.poll_shutdown)

    def drain_events(self):
        got = 0
        while got < 300:
            try:
                ev = _event_queue.get_nowait()
            except queue.Empty:
                break
            self._store_event(ev)
            got += 1
        if got and not self.paused:
            now = time.time()
            if now - self._last_render_ts >= 1.0:
                self._last_render_ts = now
                self.render_events()
        self.after(250, self.drain_events)

    def _store_event(self, ev):
        if not isinstance(ev, dict):
            return
        lvl = str(ev.get("level", "info")).lower()
        lvl = {"warning": "warn", "err": "error",
               "critical": "error"}.get(lvl, lvl)
        if lvl not in ("info", "warn", "error", "cycle", "debug"):
            lvl = "info"
        msg = ev.get("msg", "")
        self.events.append({
            "ts": _fmt_hhmmss(ev.get("ts", time.time())),
            "lvl": lvl,
            "src": str(ev.get("src", "?")),
            "cap": ev.get("capability") or "-",
            "msg": (msg if isinstance(msg, str) else str(msg))[:150]})

    def _visible(self, e) -> bool:
        if self.selected_filter == "all":
            return True
        return e["cap"] == self.selected_filter or e["cap"] == "-"

    def render_events(self):
        newest_first = list(reversed(self.events))
        all_rows = [(e["ts"], e["lvl"], e["src"], e["msg"])
                    for e in newest_first if self._visible(e)]
        bad_rows = [(e["ts"], e["lvl"], e["src"], e["msg"])
                    for e in newest_first
                    if self._visible(e) and e["lvl"] in ("warn", "error")]
        tag = lambda r: r[1]
        sync_tree(self.ev_tree, all_rows[:200], tag)
        sync_tree(self.evf_tree, bad_rows[:200], tag)

    def refresh(self):
        if _shutdown_requested:
            return
        try:
            self._refresh_impl()
            if self.err_lbl.cget("text"):
                self.err_lbl.configure(text="")
        except Exception as e:
            traceback.print_exc()
            self.err_lbl.configure(text=f"UI error: {e}")
        self.after(2000, self.refresh)

    def _refresh_impl(self):
        info = system_health()
        bb = info["bb"]
        self.rebuild_capability_list(info["capabilities"])

        st = info["state"]
        col = STATE_COLOR.get(st, MUTED)
        _set_label_text(self.chip_health,
                        f"System: {STATE_LABEL.get(st, st)}")
        if self.chip_dot:
            if self.chip_dot.cget("fg") != col:
                self.chip_dot.configure(fg=col)
        le = info["layers_enabled"]
        _set_label_text(self.chip_layers,
                        f"Layers  {'—' if le is None else le}/{info['layers_total']}")
        _set_label_text(self.chip_engines,
                        f"Engines  {info['engines_running']}/{info['engines_total']}")
        _set_label_text(self.chip_caps,
                        f"Capabilities  {info['caps_live']}/{info['caps_total']}")
        set_pill(self.overview_badge, STATE_LABEL.get(st, st), col,
                 dot=True, side="right")

        _set_label_text(
            self.stat_engines["Engines"],
            f"{info['engines_running']}/{info['engines_total']}")
        _set_label_text(
            self.stat_engines["Layers"],
            f"{'—' if le is None else le}/{info['layers_total']}")
        _set_label_text(
            self.stat_engines["Capabilities"],
            f"{info['caps_live']}/{info['caps_total']}")
        if psutil:
            try:
                _set_label_text(
                    self.stat_res["CPU"],
                    f"{psutil.cpu_percent(None):.0f}%")
                _set_label_text(
                    self.stat_res["Memory"],
                    f"{psutil.virtual_memory().percent:.0f}%")
                _set_label_text(
                    self.stat_res["Disk"],
                    f"{psutil.disk_usage(os.path.abspath(os.sep)).percent:.0f}%")
            except Exception:
                pass

        self.update_heartbeats()

        fails = recent_failures(bb)
        set_pill(self.fail_badge, str(len(fails)),
                 RED if fails else GREEN, dot=True, side="right")
        sync_tree(self.fail_tree, fails)
        ips = top_ips(bb)
        sync_tree(self.ip_tree,
                  [(i, h, c, "● " + s) for i, h, c, s in ips],
                  tag_fn=lambda r: r[3].replace("● ", ""))
        e_ips, e_groups, e_beh = active_entities(bb)
        sync_tree(self.ent_ips, [("● " + i, s) for i, s in e_ips],
                  tag_fn=lambda r: r[1])
        sync_tree(self.ent_groups, e_groups)
        sync_tree(self.ent_behav, e_beh)

        # capability filter dropdown
        wanted = ["All capabilities"] + list(info["capabilities"])
        if list(self.filter_cb["values"]) != wanted:
            self.filter_cb.configure(values=wanted)
        if self.filter_var.get() not in wanted:
            self.filter_var.set("All capabilities")
            self.selected_filter = "all"

        if self.selected_cap:
            self.update_layer_cards(bb, info["capabilities"])
            self.update_details(bb)
            self.update_recent(bb, self.selected_cap)

    def update_heartbeats(self):
        beats = engine_heartbeats()
        seen = set()
        for name, _pid, ts in beats:
            seen.add(name)
            age = (time.time() - ts) if ts > 0 else 9999
            col = GREEN if age < 30 else YELLOW if age < 300 else RED
            row = self.hb_rows.get(name)
            if row is None:
                fr = tk.Frame(self.hb_container, bg=PANEL)
                fr.pack(fill="x", padx=10)
                dot = tk.Label(fr, text="●", bg=PANEL)
                dot.pack(side="left")
                tk.Label(fr, text=f" {name}", bg=PANEL, fg=TEXT,
                         font=FONT_S, width=18,
                         anchor="w").pack(side="left")
                agel = tk.Label(fr, text="", bg=PANEL, fg=MUTED,
                                font=FONT_S, width=10)
                agel.pack(side="left", padx=16)
                row = {"frame": fr, "dot": dot, "age": agel}
                self.hb_rows[name] = row
            if row["dot"].cget("fg") != col:
                row["dot"].configure(fg=col)
            new_age = _fmt_age(ts)
            if row["age"].cget("text") != new_age:
                row["age"].configure(text=new_age)
        for name in list(self.hb_rows):
            if name not in seen:
                self.hb_rows.pop(name)["frame"].destroy()

    def update_layer_cards(self, bb, capabilities: List[str]):
        configured = {}
        for key in LAYER_KEYS:
            configured[key] = {cap for cap in capabilities
                               if key in layers_for(cap)}
        for key in LAYER_KEYS:
            cell = self.layer_cards[key]
            present_caps = []
            worst_badge = None
            worst_rank = -1
            for cap in capabilities:
                sec_name = SECTION_FMT[key].format(cap=cap)
                has_section = isinstance(bb.get(sec_name), dict)
                is_configured = cap in configured[key]
                if not (has_section or is_configured):
                    continue
                present_caps.append(cap)

                ts_str, main, extra, badge = observation_for(bb, cap, key)
                lvl = level_of(key, main, badge)
                obs = {"ts": ts_str, "main": main, "extra": extra,
                       "badge": badge, "lvl": lvl}
                hist = self.history.setdefault((cap, key), deque(maxlen=60))
                last = self.cur_obs.get((cap, key))
                if last and (last["main"], last["extra"]) != (main, extra):
                    hist.append(last)
                self.cur_obs[(cap, key)] = obs

                block = self._cap_block_for(key, cap)
                if block is not None:
                    self._fill_row(block["cur"], ts_str, main, extra,
                                   (lvl, {"error": RED, "warn": YELLOW,
                                          "info": BLUE}[lvl]) if lvl else None)
                    if hist:
                        p = hist[-1]
                        self._fill_row(block["prev"], p["ts"], p["main"],
                                       p["extra"], None)
                    else:
                        self._fill_row(block["prev"], "--:--:--", "—",
                                       "(no earlier observation yet)", None)

                if badge:
                    rank = STATE_RANK.get(badge[0], 0)
                    if badge[1] == RED:
                        rank = max(rank, 3)
                    elif badge[1] == YELLOW:
                        rank = max(rank, 1)
                    if rank > worst_rank:
                        worst_rank = rank
                        worst_badge = badge

            # remove blocks for capabilities that no longer have this layer
            for cap in list(cell["cap_blocks"].keys()):
                if cap not in present_caps:
                    cell["cap_blocks"].pop(cap)["frame"].destroy()

            if worst_badge:
                set_pill(cell["hdr"], worst_badge[0], worst_badge[1],
                         dot="→" not in worst_badge[0])
            else:
                set_pill(cell["hdr"], "no data", MUTED)

    def _fill_row(self, row, ts, main, extra, badge):
        sig = (ts, main[:70], extra[:90], badge)
        if row.get("_sig") == sig:
            return
        row["_sig"] = sig
        row["time"].configure(text=ts)
        row["main"].configure(text=main[:70])
        row["extra"].configure(text=extra[:90])
        if badge:
            set_pill(row["badge"], badge[0], badge[1],
                     base=PANEL2, side="right")
        else:
            set_pill(row["badge"], "", "", base=PANEL2)

    def _section_for_selected(self, bb):
        if not self.selected_cap:
            return None, None
        name = SECTION_FMT[self.selected_layer].format(cap=self.selected_cap)
        sec = bb.get(name)
        return name, sec if isinstance(sec, dict) else None

    def update_details(self, bb):
        cap, key = self.selected_cap, self.selected_layer
        if not cap:
            return
        short, lname, color = LAYER_META[key]
        cur = self.cur_obs.get((cap, key))
        hist = self.history.get((cap, key), deque())
        prev = hist[-1] if hist else None
        sec_name, sec = self._section_for_selected(bb)

        if cur and cur["lvl"]:
            set_pill(self.detail_badge, cur["lvl"],
                     {"error": RED, "warn": YELLOW, "info": BLUE}[cur["lvl"]])
        else:
            set_pill(self.detail_badge, "—", MUTED)
        _set_label_text(self.detail_title,
                        f"{lname} ({short}): {cur['main']}" if cur
                        else f"{lname} ({short})")

        today = datetime.now().strftime("%Y-%m-%d")
        vals = [f"{today} {cur['ts']}" if cur and cur["ts"] != "--:--:--"
                else "—",
                LAYER_NUM[key], cap,
                prev["main"] if prev else "N/A",
                cur["main"] if cur else "—",
                cur["extra"] if cur and cur["extra"] else "—",
                sec_name or "—"]
        for (_k, v), text in zip(self.detail_left, vals):
            _set_label_text(v, text)

        items = []
        if sec:
            for k, v in sec.items():
                if isinstance(v, (list, dict)):
                    items.append((k.replace("_", " "),
                                  f"{type(v).__name__}[{len(v)}]"))
                else:
                    items.append((k.replace("_", " "), str(v)[:60]))
        for i, (kl, vl) in enumerate(self.detail_right):
            k, v = items[i] if i < len(items) else ("", "")
            _set_label_text(kl, k)
            _set_label_text(vl, v)

        sync_tree(self.hist_tree,
                  [(h["ts"], h["main"][:40], h["extra"][:60],
                    h["badge"][0] if h["badge"] else "—")
                   for h in reversed(hist)])
        ev_rows = [(e["ts"], e["lvl"], e["src"], e["msg"])
                   for e in reversed(self.events) if e["cap"] == cap][:40]
        sync_tree(self.evid_tree, ev_rows, tag_fn=lambda r: r[1])

    def view_full_event(self):
        _name, sec = self._section_for_selected(read_blackboard())
        win = tk.Toplevel(self)
        win.title(f"{_name or 'no section'} — full record")
        win.configure(bg=BG)
        win.geometry("720x560")
        t = tk.Text(win, bg="#080e1a", fg=TEXT, font=MONO,
                    relief="flat", wrap="none")
        t.pack(fill="both", expand=True, padx=8, pady=8)
        t.insert("end", json.dumps(sec, indent=2, default=str)
                 if sec else "(no data)")
        t.configure(state="disabled")

    def update_recent(self, bb, cap):
        sec = bb.get(f"layer_3_state_{cap}")
        sig = None
        if isinstance(sec, dict):
            sig = (sec.get("state"), sec.get("previous_state"),
                   sec.get("state_timestamp"))
        if getattr(self.recent_body, "_sig", 0) == (cap, sig):
            return
        self.recent_body._sig = (cap, sig)
        for w in self.recent_body.winfo_children():
            w.destroy()
        if not isinstance(sec, dict):
            tk.Label(self.recent_body, text="no state changes yet",
                     bg=PANEL, fg=MUTED, font=FONT_S).pack(anchor="w")
            return
        cur = str(sec.get("state", "?")).upper()
        prev = str(sec.get("previous_state", "?")).upper()
        col = STATE_COLOR.get(cur, MUTED)
        head = tk.Frame(self.recent_body, bg=PANEL)
        head.pack(fill="x")
        tk.Label(head, text="●", fg=col, bg=PANEL).pack(side="left")
        tk.Label(head, text=f"  {_fmt_hhmmss(sec.get('state_timestamp'))}"
                            f"   State changed",
                 bg=PANEL, fg=TEXT, font=FONT_S).pack(side="left")
        tk.Label(self.recent_body, text=f"{prev} → {cur}",
                 bg=PANEL, fg=col, font=FONT_S).pack(anchor="w",
                                                     padx=22, pady=(4, 0))
        det = sec.get("detail", {}) if isinstance(sec.get("detail"), dict) else {}
        tk.Label(self.recent_body,
                 text=f"Reason: {det.get('transition', '—')}",
                 bg=PANEL, fg=MUTED, font=FONT_S).pack(anchor="w",
                                                       padx=22,
                                                       pady=(0, 6))

    # ── command console ──
    def run_cmd(self, line: str):
        if not line:
            return
        self.cmd_history.append(line)
        self.cmd_hist_idx = len(self.cmd_history)
        out = self._dispatch(line)
        self.console_out.configure(state="normal")
        self.console_out.insert("end", f"> {line}\n{out}\n\n")
        try:
            n = int(self.console_out.index("end-1c").split(".")[0])
            if n > 500:
                self.console_out.delete("1.0", f"{n - 500}.0")
        except Exception:
            pass
        self.console_out.see("end")
        self.console_out.configure(state="disabled")
        self.cmd_var.set("")
        self.cmd_entry.focus_set()

    def _history_step(self, delta: int):
        if not self.cmd_history:
            return
        self.cmd_hist_idx = max(0, min(len(self.cmd_history) - 1,
                                       self.cmd_hist_idx + delta))
        self.cmd_var.set(self.cmd_history[self.cmd_hist_idx])
        self.cmd_entry.icursor("end")

    def _dispatch(self, line: str) -> str:
        if not _COMMANDS_AVAILABLE:
            return "console.commands not available"
        try:
            result = _console_commands.dispatch(line)
        except Exception as e:
            return f"error: {e}"
        kind = result.get("kind", "")
        msg = result.get("message", "")
        data = result.get("data", {}) or {}
        if kind == "ok":
            return msg or "(ok)"
        if kind == "error":
            return msg or "(error)"
        if kind == "quit":
            request_shutdown()
            return "shutting down"
        if kind == "view" and _VIEWS_AVAILABLE:
            try:
                lines = _console_views.render(data.get("view", ""),
                                              data.get("args", []))
                return "\n".join(text for text, _ in lines)
            except Exception as e:
                return f"view error: {e}"
        if kind == "menu":
            return f"menu: {data.get('menu', '')} (not shown in GUI)"
        if kind == "back":
            return "(back — no menu in GUI)"
        return str(result)

    def show_view(self, name: str):
        mapping = {"Summary": "diag summary", "Health": "diag health",
                   "Failures": "diag failures", "IPs": "diag ips",
                   "Events (Live)": "diag events", "System": "system",
                   "Configuration": "system config",
                   "Logs": "system audit", "Help": "help"}
        for n, lb in self.nav_labels.items():
            lb.configure(bg=ACCENT if n == name else PANEL)
        cmd = mapping.get(name)
        if cmd:
            self.run_cmd(cmd)

# ───────────────────────── diagnostics ─────────────────────────
def probe():
    cfg, bb, snap = read_config(), read_blackboard(), read_layer_state()
    print("config file      :", Config.SYSTEM_CONFIG_FILE,
          "(%d keys)" % len(cfg))
    print("blackboard file  :", Config.BLACKBOARD_FILE,
          "(%d keys)" % len(bb))
    print("layer-state file :", Config.LAYER_STATE_FILE)
    print("\ncapability_layers:", json.dumps(cfg.get("capability_layers"),
                                              indent=1))
    print("enabled_capabilities:",
          json.dumps(cfg.get("enabled_capabilities"), indent=1))
    print("capabilities used by GUI:", get_capabilities(bb))
    print("\nheartbeat files in", get_temp_dir(), ":")
    for name, filename in _ENGINE_HEARTBEAT_FILES:
        p = os.path.join(get_temp_dir(), filename)
        try:
            age = int(time.time() - os.path.getmtime(p))
            print(f"  {name:18} {filename:35} age={age}s")
        except OSError:
            print(f"  {name:18} {filename:35} MISSING")
    print("\nblackboard top-level keys:")
    for k in sorted(bb):
        print("  ", k)
    for cap in get_capabilities(bb):
        print(f"\n[{cap}] layers per config -> {layers_for(cap)}")
        for k in LAYER_KEYS:
            n = SECTION_FMT[k].format(cap=cap)
            print(f"   {k:8} section {n!r:42} "
                  f"{'FOUND' if n in bb else 'MISSING'}")

# ───────────────────────── entry point ─────────────────────────
def run_gui():
    if _READER_AVAILABLE:
        try:
            start_reader(_on_event)
        except Exception:
            traceback.print_exc()
    app = ACFApp()
    try:
        app.mainloop()
    finally:
        try:
            app.destroy()
        except Exception:
            pass

def main():
    if "--probe" in sys.argv:
        probe()
    else:
        run_gui()

if __name__ == "__main__":
    main()