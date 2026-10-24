# console/app.py
# ============================================================================
# CONSOLE APP — Main loop
# ============================================================================
# Coordinate: render status bar, render work area, prompt, dispatch, react.
#
# This module does not parse, execute, or store. It calls the modules that do.
#
# ENTRY POINT: run_console()
#
# FIXES APPLIED:
#   P0    Reader lifecycle — console only starts the reader, never stops it.
#         The reader thread is a daemon; it dies with the process.
#   P1.1  Menu target validated before assignment.
#   P1.2  system_config.json cached by mtime.
#   P2.1  Status bar refreshes after each command (documented limitation).
#   P2.2  EOF / Ctrl+C prints a message before exiting.
#   P2.3  View output truncated at terminal height.
#   P2.4  Unknown result kinds are logged.
#
# ROUND 3:
#   P1    Live views redraw until a key is pressed. Static views wait once.
#         Live mode only activates on an interactive TTY.
# ============================================================================

import json
import os
import time
from typing import Optional, Tuple, Dict, Any

from config import Config

from . import ui
from . import state
from . import commands
from . import views
from . import menus
from . import events
from . import actions


# Live views redraw every _LIVE_REFRESH_SECONDS until a key is pressed.
_LIVE_REFRESH_SECONDS = 3.0


# ----------------------------------------------------------------------
# Module-level cache for system_config.json
# ----------------------------------------------------------------------
_config_cache: Dict[str, Any] = {"mtime": 0.0, "data": {}}


def _load_config_cached() -> Dict[str, Any]:
    """Read system_config.json, cached by mtime."""
    try:
        mtime = os.path.getmtime(Config.SYSTEM_CONFIG_FILE)
    except OSError:
        return {}
    if mtime != _config_cache["mtime"]:
        try:
            with open(Config.SYSTEM_CONFIG_FILE, "r") as f:
                _config_cache["data"] = json.load(f)
            _config_cache["mtime"] = mtime
        except Exception:
            return {}
    data = _config_cache["data"]
    return data if isinstance(data, dict) else {}


# ----------------------------------------------------------------------
# View error logging
# ----------------------------------------------------------------------
def _log_app_error(message: str):
    try:
        with open(Config.LOG_FILE, "a") as f:
            ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())
            f.write(f"[CONSOLE_APP] {ts} | {message}\n")
    except Exception:
        pass


# ----------------------------------------------------------------------
# Status bar data
# ----------------------------------------------------------------------
def _status_bar_data() -> Tuple[str, Optional[int], int, int, int, int]:
    bb = actions.get_blackboard()
    snap = actions.get_layer_snapshot()

    state_str = "N/A"
    if isinstance(bb, dict):
        so = bb.get("layer_3_state", {})
        if isinstance(so, dict):
            state_str = so.get("state") or "N/A"

    risk: Optional[int] = None
    if isinstance(bb, dict):
        for k, v in bb.items():
            if not isinstance(k, str) or not k.startswith("layer_2_ais_"):
                continue
            if not isinstance(v, dict):
                continue
            try:
                r = int(v.get("risk", 0) or 0)
            except Exception:
                continue
            if risk is None or r > risk:
                risk = r

    layers = snap.get("layers", {}) if isinstance(snap, dict) else {}
    if not isinstance(layers, dict):
        layers = {}
    engines_running = sum(
        1 for info in layers.values()
        if isinstance(info, dict) and info.get("state") == "RUNNING"
    )
    engines_total = len(state.LAYER_IDS)

    cfg = _load_config_cached()
    layers_cfg = cfg.get("layers", {}) if isinstance(cfg, dict) else {}
    if not isinstance(layers_cfg, dict):
        layers_cfg = {}
    layers_enabled = sum(1 for v in layers_cfg.values() if v)
    layers_total = len(state.LAYER_IDS)

    return state_str, risk, engines_running, engines_total, layers_enabled, layers_total


def _draw_status_bar():
    s, risk, er, et, le, lt = _status_bar_data()
    ui.render_status_bar(
        state=s,
        risk=risk,
        engines_running=er,
        engines_total=et,
        layers_enabled=le,
        layers_total=lt,
        time_str=time.strftime("%H:%M:%S"),
    )


# ----------------------------------------------------------------------
# Work area
# ----------------------------------------------------------------------
def _render_menu(menu_name: str):
    menu = menus.get_menu(menu_name)
    if menu is None:
        ui.print_error(f"Unknown menu: {menu_name}")
        return
    ui.render_header(menu["title"])
    for key, label, _ in menu["items"]:
        ui.print_line(f"  {key}  {label}")
    ui.print_line("")


def _render_dashboard():
    lines = views.render("layers")
    ui.render_work_area(lines)


def _render_frame(current_menu: Optional[str]):
    _draw_status_bar()
    ui.clear_from_row(3)
    ui.move_cursor(3, 1)
    if current_menu:
        _render_menu(current_menu)
    else:
        _render_dashboard()


# ----------------------------------------------------------------------
# Prompt
# ----------------------------------------------------------------------
def _build_prompt(current_menu: Optional[str]) -> str:
    if current_menu:
        return f"acf/{current_menu}> "
    return "acf> "


# ----------------------------------------------------------------------
# Result handling
# ----------------------------------------------------------------------
def _handle_prompt(data: dict) -> Optional[str]:
    fields = data.get("fields", [])
    template = data.get("template", "")
    if not isinstance(fields, list) or not isinstance(template, str) or not template:
        return None

    values = {}
    for entry in fields:
        if not isinstance(entry, tuple) or len(entry) != 2:
            continue
        name, text = entry
        try:
            val = input(text).strip()
        except (EOFError, KeyboardInterrupt):
            ui.print_warning("Cancelled.")
            return None
        if not val:
            ui.print_warning("Empty value; cancelled.")
            return None
        values[name] = val

    try:
        return template.format(**values)
    except Exception:
        ui.print_error("Could not build command.")
        return None


def _show_view(view_name: str, args: list):
    """
    Render a view.

    Live views redraw in place until the user presses a key.
    Static views render once and wait for Enter.
    Live mode only activates on an interactive TTY.
    """
    if view_name in views.LIVE_VIEWS and getattr(ui, "_IS_TTY", False):
        _show_live_view(view_name, args)
        return

    lines = views.render(view_name, args)

    try:
        _, rows = ui.get_size()
    except Exception:
        rows = 24

    max_lines = max(5, rows - 6)
    if len(lines) > max_lines:
        shown = lines[:max_lines]
        remaining = len(lines) - max_lines
        shown.append((f"  ... {remaining} more lines truncated ...", ""))
        lines = shown

    ui.render_work_area(lines)
    try:
        input("\nPress Enter to continue...")
    except (EOFError, KeyboardInterrupt):
        ui.print_line("")


def _show_live_view(view_name: str, args: list):
    """
    Redraw a view every _LIVE_REFRESH_SECONDS until the user presses a key.

    Keeps the status bar live. Truncates content to fit the terminal.
    Never blocks longer than one refresh interval per iteration.
    """
    try:
        while True:
            _draw_status_bar()
            ui.clear_from_row(3)
            ui.move_cursor(3, 1)

            try:
                _, rows = ui.get_size()
            except Exception:
                rows = 24

            lines = views.render(view_name, args)
            max_lines = max(5, rows - 4)
            if len(lines) > max_lines:
                shown = lines[:max_lines - 1]
                remaining = len(lines) - (max_lines - 1)
                shown.append((f"  ... {remaining} more lines truncated ...", ""))
                lines = shown

            ui.render_work_area(lines)
            ui.print_line("")
            ui.print_line("  (press Enter to return to the prompt)", "")

            waited = 0.0
            while waited < _LIVE_REFRESH_SECONDS:
                if ui.key_pressed():
                    ui.consume_pending_keys()
                    return
                time.sleep(0.1)
                waited += 0.1
    except (KeyboardInterrupt, EOFError):
        return


def _handle_result(result: dict, current_menu: Optional[str]) -> Optional[str]:
    kind = result.get("kind", "")
    message = result.get("message", "")
    data = result.get("data", {})

    if kind == "ok":
        if message:
            ui.print_success(message)
        return current_menu

    if kind == "error":
        ui.print_error(message or "Error")
        return current_menu

    if kind == "menu":
        target = data.get("menu", "main")
        if menus.get_menu(target) is None:
            ui.print_error(f"Unknown menu: {target}")
            return current_menu
        return target

    if kind == "back":
        if current_menu and current_menu != "main":
            return "main"
        return current_menu

    if kind == "quit":
        try:
            confirm = input("Exit the console and stop the ACF? [y/N] ").strip().lower()
        except (EOFError, KeyboardInterrupt):
            return current_menu
        if confirm == "y":
            state.request_shutdown()
        return current_menu

    if kind == "prompt":
        line = _handle_prompt(data)
        if not line:
            return current_menu
        new_result = commands.dispatch(line, current_menu=None)
        return _handle_result(new_result, current_menu)

    if kind == "view":
        view_name = data.get("view", "")
        args = data.get("args", [])
        if not isinstance(args, list):
            args = []
        _show_view(view_name, args)
        return current_menu

    _log_app_error(f"Unknown result kind from dispatch: {kind!r}")
    return current_menu


# ----------------------------------------------------------------------
# Entry point
# ----------------------------------------------------------------------
def run_console():
    """
    Start the console. Blocks until the user quits.
    Called by orchestrator.main() in place of interactive_prompt().

    Lifecycle:
      - Registers the console's event handler with the shared reader thread.
      - The reader thread is a daemon; the console does not stop it.
        When the process exits, the daemon thread ends with it. This avoids
        a cross-module lifecycle conflict where the console could tear down
        a reader that another component started.
      - On normal exit, the terminal is restored via ui.deinit().
    """
    ui.init()
    ui.clear_screen()

    try:
        from event_reader import start_reader
        start_reader(events.on_event)
    except ImportError:
        pass

    current_menu: Optional[str] = None

    try:
        while not state.is_shutdown_requested():
            _render_frame(current_menu)
            prompt = _build_prompt(current_menu)
            try:
                line = input(prompt)
            except EOFError:
                ui.print_line("")
                ui.print_line("Input closed. Exiting console.")
                break
            except KeyboardInterrupt:
                ui.print_line("")
                ui.print_line("Interrupted. Exiting console.")
                break

            result = commands.dispatch(line, current_menu=current_menu)
            current_menu = _handle_result(result, current_menu)
    finally:
        ui.deinit()
        ui.print_line("Console exited.")