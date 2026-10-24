# console/state.py
# ============================================================================
# CONSOLE STATE — Local state for the terminal console
# ============================================================================
# Holds layout, filter, view, toggles, event buffer, and preferences.
# Thread-safe: main loop and event handler both access it.
#
# DEPENDENCIES:
#   - platform_utils (for get_temp_dir)
#   - colorama NOT required here (this is state, not rendering)
# ============================================================================

import os
import json
import threading
import time
from collections import deque
from typing import Any, Dict, List, Optional

from platform_utils import get_temp_dir


# ----------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------
PREFERENCES_FILE = os.path.join(get_temp_dir(), "acf_console_prefs.json")

LAYER_IDS = ["layer1", "layer2", "layer3", "layer4a", "layer4c", "layer5"]

EVENT_BUFFER_MAX = 500
HISTORY_MAX = 200
VALID_LAYOUTS = ("single", "side-by-side", "stacked")
DEFAULT_LAYOUT = "single"
DEFAULT_VIEW = "dashboard"


# ----------------------------------------------------------------------
# Internal state (module-level, protected by _lock)
# ----------------------------------------------------------------------
_layout: str = DEFAULT_LAYOUT
_filter: Optional[str] = None
_view: str = DEFAULT_VIEW
_menu: Optional[str] = None
_toggles: Dict[str, bool] = {layer: True for layer in LAYER_IDS}
_events: deque = deque(maxlen=EVENT_BUFFER_MAX)
_history: deque = deque(maxlen=HISTORY_MAX)
_shutdown_requested: bool = False
_status_message: str = ""
_status_until: float = 0.0

_lock = threading.Lock()


# ----------------------------------------------------------------------
# Layout
# ----------------------------------------------------------------------
def get_layout() -> str:
    with _lock:
        return _layout


def set_layout(value: str):
    # Edge case 8: invalid layout coerced to default
    global _layout
    if value not in VALID_LAYOUTS:
        value = DEFAULT_LAYOUT
    with _lock:
        _layout = value


# ----------------------------------------------------------------------
# Filter
# ----------------------------------------------------------------------
def get_filter() -> Optional[str]:
    with _lock:
        return _filter


def set_filter(source: Optional[str]):
    # Edge case 4: filter set to unknown source is allowed;
    # the view layer decides what to do with it.
    global _filter
    with _lock:
        _filter = source


def clear_filter():
    global _filter
    with _lock:
        _filter = None


# ----------------------------------------------------------------------
# View and menu
# ----------------------------------------------------------------------
def get_view() -> str:
    with _lock:
        return _view


def set_view(value: str):
    global _view
    with _lock:
        _view = value


def get_menu() -> Optional[str]:
    with _lock:
        return _menu


def set_menu(value: Optional[str]):
    global _menu
    with _lock:
        _menu = value


# ----------------------------------------------------------------------
# Display toggles (per layer)
# ----------------------------------------------------------------------
def is_displayed(layer_id: str) -> bool:
    with _lock:
        return _toggles.get(layer_id, True)


def set_displayed(layer_id: str, value: bool):
    # Edge case 5: unknown layer ignored
    with _lock:
        if layer_id in _toggles:
            _toggles[layer_id] = bool(value)


def toggle_display(layer_id: str) -> bool:
    with _lock:
        if layer_id in _toggles:
            _toggles[layer_id] = not _toggles[layer_id]
            return _toggles[layer_id]
        return False


def get_all_toggles() -> Dict[str, bool]:
    with _lock:
        return dict(_toggles)


# ----------------------------------------------------------------------
# Events
# ----------------------------------------------------------------------
def add_event(event: Dict):
    # Edge case 6: deque drops oldest automatically
    with _lock:
        _events.append(event)


def get_recent_events(source: Optional[str] = None, count: int = 50) -> List[Dict]:
    with _lock:
        events = list(_events)
    if source:
        events = [e for e in events if e.get("src") == source]
    return events[-count:]


def clear_events():
    with _lock:
        _events.clear()


# ----------------------------------------------------------------------
# Prompt history
# ----------------------------------------------------------------------
def add_history(line: str):
    # Edge case 7: deque drops oldest automatically
    with _lock:
        _history.append(line)


def get_history() -> List[str]:
    with _lock:
        return list(_history)


# ----------------------------------------------------------------------
# Status message (short-lived flash)
# ----------------------------------------------------------------------
def set_status(message: str, duration: float = 3.0):
    global _status_message, _status_until
    with _lock:
        _status_message = message
        _status_until = time.time() + duration


def get_status() -> str:
    with _lock:
        if _status_until > time.time():
            return _status_message
        return ""


# ----------------------------------------------------------------------
# Shutdown flag
# ----------------------------------------------------------------------
def is_shutdown_requested() -> bool:
    with _lock:
        return _shutdown_requested


def request_shutdown():
    global _shutdown_requested
    with _lock:
        _shutdown_requested = True


# ----------------------------------------------------------------------
# Preferences (optional, opt-in by caller)
# ----------------------------------------------------------------------
def save_preferences():
    # Edge case 2: failures are swallowed; preferences are cosmetic
    try:
        with open(PREFERENCES_FILE, "w") as f:
            json.dump({
                "layout": get_layout(),
                "display_toggles": get_all_toggles(),
            }, f, indent=2)
    except Exception:
        pass


def load_preferences():
    # Edge case 1: file missing -> defaults stay in place
    # Edge case 2: file corrupt -> ignored
    try:
        with open(PREFERENCES_FILE, "r") as f:
            prefs = json.load(f)
        if "layout" in prefs:
            set_layout(prefs["layout"])
        if "display_toggles" in prefs:
            for layer, enabled in prefs["display_toggles"].items():
                set_displayed(layer, enabled)
    except Exception:
        pass