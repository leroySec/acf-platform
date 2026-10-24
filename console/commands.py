# console/commands.py
# ============================================================================
# CONSOLE COMMANDS — Parser and dispatcher
# ============================================================================
# Turns a line of user input into a structured result the app can act on.
#
# RESULT CONTRACT:
#   dispatch() returns a dict with:
#     kind:    "ok" | "error" | "menu" | "back" | "quit" | "prompt" | "view"
#     message: str (may be empty)
#     data:    dict (may be empty)
#   data contents per kind:
#     "menu":   {"menu": "<name>"}
#     "view":   {"view": "<name>", "args": [...]}
#     "prompt": {
#         "parts":    [...],
#         "fields":   [(name, prompt_text), ...],
#         "template": "the command to re-dispatch, with {field} placeholders",
#     }
#
# FIXES APPLIED (round 1):
#   P0  "quit" is handled
#   P1  Usage errors for incomplete commands
#   P1  Engine-vs-layer semantics clarified
#   P2  All action calls wrapped via _call_action
#   P2  current_menu is used for bare-digit selection
#   P3  Input length limit (4096 chars)
#   P3  Help topics validated
#
# FIXES APPLIED (round 2):
#   P0  Single-character menu keys (b, q, digits) resolve through the menu
#   P1  Prompt results include a template so the app can re-dispatch cleanly
#   P1  filter set / display layout / display show / display hide accept
#       both the direct and the prompt-concatenated forms
#   P2  Guard against a None command from menus
#   P2  _call_action normalises None messages to ""
#   P3  Removed redundant length check in _tokenize
#
# FIXES APPLIED (round 3):
#   P1  Per-layer diag commands: diag reader, diag monitor, diag ais,
#       diag state, diag response, diag mtd — each filters the event
#       buffer to one engine's source.
#   P1  diag events accepts "all" to show every level including debug.
#   P1  diag summary added for the previous state-and-risk view.
# ============================================================================

from typing import Dict, Any, List, Tuple, Optional, Callable

try:
    from . import actions
    from . import menus
    _IMPORTS_OK = True
except Exception:
    actions = None
    menus = None
    _IMPORTS_OK = False


MAX_LINE_LENGTH = 4096


# ----------------------------------------------------------------------
# Result builders
# ----------------------------------------------------------------------
def _ok(message: str = "") -> Dict[str, Any]:
    return {"kind": "ok", "message": message, "data": {}}


def _error(message: str) -> Dict[str, Any]:
    return {"kind": "error", "message": message, "data": {}}


def _menu(name: str) -> Dict[str, Any]:
    return {"kind": "menu", "message": "", "data": {"menu": name}}


def _back() -> Dict[str, Any]:
    return {"kind": "back", "message": "", "data": {}}


def _quit() -> Dict[str, Any]:
    return {"kind": "quit", "message": "", "data": {}}


def _view(name: str, *args) -> Dict[str, Any]:
    return {"kind": "view", "message": "", "data": {"view": name, "args": list(args)}}


def _prompt(parts: List[str], fields: List[Tuple[str, str]], template: str = "") -> Dict[str, Any]:
    return {
        "kind": "prompt",
        "message": "",
        "data": {
            "parts": parts,
            "fields": fields,
            "template": template,
        },
    }


# ----------------------------------------------------------------------
# Safe action wrapper
# ----------------------------------------------------------------------
def _call_action(fn: Callable, *args) -> Tuple[bool, str]:
    """
    Call an actions.* function safely.
    Returns (success, message). Never raises.
    """
    if actions is None:
        return False, "Actions module not available"
    try:
        ok, msg = fn(*args)
        if not isinstance(ok, bool):
            return False, "Action returned unexpected result"
        if msg is None:
            msg = ""
        elif not isinstance(msg, str):
            msg = str(msg)
        return ok, msg
    except Exception as e:
        return False, f"Action failed: {e}"


# ----------------------------------------------------------------------
# Prompt specifications and command templates
# ----------------------------------------------------------------------
PROMPT_SPECS: Dict[str, List[Tuple[str, str]]] = {
    "enable capability": [("name", "Enter capability name: ")],
    "disable capability": [("name", "Enter capability name: ")],
    "capability path": [
        ("name", "Enter capability name: "),
        ("path", "Enter new log path: "),
    ],
    "capability telemetry": [("name", "Enter capability name: ")],
    "capability add": [
        ("name", "Enter custom log name: "),
        ("path", "Enter log file path: "),
    ],
    "capability remove": [("name", "Enter custom log name: ")],
    "layer enable": [("layer", "Enter layer id (e.g., layer1): ")],
    "layer disable": [("layer", "Enter layer id (e.g., layer1): ")],
    "layer restart": [("layer", "Enter layer id (e.g., layer1): ")],
    "layer display": [("layer", "Enter layer id (e.g., layer1): ")],
    "layer status": [("layer", "Enter layer id (e.g., layer1): ")],
    "engine restart": [("name", "Enter engine name (or 'all'): ")],
    "engine logs": [("name", "Enter engine name: ")],
    "system reload": [],
    "system reload all": [],
    "display layout": [
        ("layout", "Enter layout (single / side-by-side / stacked): "),
    ],
    "display show": [("source", "Enter capability or layer name: ")],
    "display hide": [("source", "Enter capability or layer name: ")],
    "filter set": [("source", "Enter source name: ")],
}


COMMAND_TEMPLATES: Dict[str, str] = {
    "enable capability": "enable {name}",
    "disable capability": "disable {name}",
    "capability path": "path {name} {path}",
    "capability telemetry": "telemetry {name}",
    "capability add": "add {name} {path}",
    "capability remove": "remove {name}",
    "layer enable": "layer enable {layer}",
    "layer disable": "layer disable {layer}",
    "layer restart": "layer restart {layer}",
    "layer display": "layer display {layer}",
    "layer status": "layer status {layer}",
    "engine restart": "engine restart {name}",
    "engine logs": "engine logs {name}",
    "system reload": "system reload",
    "system reload all": "system reload all",
    "display layout": "display layout {layout}",
    "display show": "display show {source}",
    "display hide": "display hide {source}",
    "filter set": "filter set {source}",
}


def get_prompt_fields(parts: List[str]) -> Optional[List[Tuple[str, str]]]:
    if not parts:
        return None
    key = " ".join(parts)
    return PROMPT_SPECS.get(key)


def get_command_template(parts: List[str]) -> str:
    if not parts:
        return ""
    return COMMAND_TEMPLATES.get(" ".join(parts), "")


# ----------------------------------------------------------------------
# Help text
# ----------------------------------------------------------------------
HELP_TEXT: Dict[str, str] = {
    "overview": (
        "The ACF console lets you observe and control the ACF.\n"
        "Type a menu number to act, or type a command directly.\n"
        "Type 'help commands' for the full command list.\n"
        "Type 'menu' to open the main menu.\n"
        "Type 'quit' to exit (with confirmation)."
    ),
    "commands": (
        "Navigation:\n"
        "  menu                 Open the main menu\n"
        "  menu <name>          Open a named menu\n"
        "  back                 Return to the previous menu\n"
        "  home                 Return to the main menu\n"
        "  quit                 Exit the console (with confirmation)\n"
        "\nCapabilities:\n"
        "  capabilities         List all capabilities\n"
        "  enable <name>        Enable a capability\n"
        "  disable <name>       Disable a capability\n"
        "  path <name> <path>   Change a capability's log path\n"
        "  telemetry <name>     Show telemetry for one capability\n"
        "  add <name> <path>    Add a custom log\n"
        "  remove <name>        Remove a custom log\n"
        "\nLayers:\n"
        "  layers               List all layers\n"
        "  layer enable <id>\n"
        "  layer disable <id>\n"
        "  layer restart <id>\n"
        "  layer display <id>   Toggle display of a layer\n"
        "  layer status <id>\n"
        "\nEngines (aliases for their layers):\n"
        "  engines              List all engines\n"
        "  engines heartbeat\n"
        "  engine restart <n>   Restarts the layer that hosts <n>\n"
        "\nDiagnostics:\n"
        "  diag events          Summary of cycles per capability\n"
        "  diag events all      Every event, all levels\n"
        "  diag summary         State and risk summary\n"
        "  diag failures        Failure counts\n"
        "  diag ips             Last attacker IP per capability\n"
        "  diag health          Engine health markers\n"
        "  diag reader          Reader events, grouped by capability\n"
        "  diag monitor         Layer 1 (monitor_engine) events\n"
        "  diag ais             Layer 2 (ais_engine) events\n"
        "  diag state           Layer 3 (state_engine) events\n"
        "  diag response        Layer 4a (response_engine) events\n"
        "  diag mtd             Layer 4c (mtd_engine) events\n"
        "\nSystem:\n"
        "  system config\n"
        "  system blackboard\n"
        "  system audit\n"
        "  system resources\n"
        "  reload               Reload configuration\n"
        "  reload all           Restart layers and capabilities\n"
        "\nDisplay:\n"
        "  layout <mode>        single | side-by-side | stacked\n"
        "  filter <source>      Filter the work area\n"
        "  filter clear\n"
        "  display reset        Reset layout, filter, toggles\n"
    ),
    "navigation": (
        "Menus are numbered. Type the number to select an item.\n"
        "Type 'b' to go back one menu level.\n"
        "Type 'q' or 'quit' to exit (with confirmation).\n"
        "You can also type commands directly at the prompt."
    ),
    "display": (
        "Layouts:\n"
        "  single          Focus on one capability or layer\n"
        "  side-by-side    Compare two\n"
        "  stacked         Show many\n"
        "Filter narrows the work area to a single capability.\n"
        "Use 'filter clear' to remove the filter."
    ),
    "layers": (
        "Layers are ACF processing stages (Monitoring, AIS, State, ...).\n"
        "Each layer runs its own engine process.\n"
        "You can enable, disable, restart, and display layers.\n"
        "Use 'layers' to see the current state."
    ),
}


# ----------------------------------------------------------------------
# Tokenizer
# ----------------------------------------------------------------------
def _tokenize(line: str) -> List[str]:
    if not isinstance(line, str):
        return []
    return line.strip().split()


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------
def _handle_display(args: List[str]) -> Dict[str, Any]:
    if not args:
        return _error("Usage: display reset | display layout <mode> | display show/hide <source>")

    sub = args[0].lower()

    if sub == "reset":
        ok, msg = _call_action(actions.reset_display)
        return _ok(msg) if ok else _error(msg)

    if sub == "layout":
        if len(args) < 2:
            return _error("Usage: display layout <mode>")
        mode = args[1].lower()
        ok, msg = _call_action(actions.set_layout, mode)
        return _ok(msg) if ok else _error(msg)

    if sub in ("show", "hide"):
        if len(args) < 2:
            return _error(f"Usage: display {sub} <source>")
        source = " ".join(args[1:])
        value = (sub == "show")
        ok, msg = _call_action(actions.set_layer_display, source, value)
        return _ok(msg) if ok else _error(msg)

    return _error(f"Unknown display subcommand: {sub}")


def _handle_filter(args: List[str]) -> Dict[str, Any]:
    if not args:
        return _error("Usage: filter <source> | filter clear")

    first = args[0].lower()

    if first == "clear":
        ok, msg = _call_action(actions.clear_filter)
        return _ok(msg) if ok else _error(msg)

    if first == "set":
        if len(args) < 2:
            return _error("Usage: filter set <source>")
        source = " ".join(args[1:])
    else:
        source = " ".join(args)

    ok, msg = _call_action(actions.set_filter, source)
    return _ok(msg) if ok else _error(msg)


# ----------------------------------------------------------------------
# Top-level dispatch
# ----------------------------------------------------------------------
def dispatch(line: str, current_menu: Optional[str] = None) -> Dict[str, Any]:
    if not _IMPORTS_OK:
        return _error("Console modules not available")

    if not isinstance(line, str):
        return _error("Invalid input")

    if len(line) > MAX_LINE_LENGTH:
        return _error("Input too long")

    stripped = line.strip()

    # ------------------------------------------------------------------
    # Menu shortcut
    # ------------------------------------------------------------------
    if current_menu and stripped and len(stripped) == 1:
        try:
            resolved = menus.resolve_item(current_menu, stripped)
        except Exception:
            resolved = None
        if resolved is not None:
            _, command = resolved
            if command is None:
                return _ok("")
            if not isinstance(command, str):
                return _error("Malformed menu command")
            if command == "__back__":
                return _back()
            if command == "__quit__":
                return _quit()
            return dispatch(command, current_menu=None)

    # ------------------------------------------------------------------
    # Tokenize
    # ------------------------------------------------------------------
    tokens = _tokenize(line)
    if not tokens:
        return _ok("")

    verb = tokens[0].lower()
    rest = tokens[1:]

    # ------------------------------------------------------------------
    # Aliases and reserved
    # ------------------------------------------------------------------
    if verb in ("q", "quit", "exit"):
        return _quit()
    if verb in ("h", "?"):
        return _view("help", "overview")

    if stripped == "__quit__":
        return _quit()
    if stripped == "__back__":
        return _back()

    # ------------------------------------------------------------------
    # Navigation
    # ------------------------------------------------------------------
    if verb == "menu":
        if not rest:
            return _menu("main")
        name = rest[0].lower()
        try:
            if menus.get_menu(name) is None:
                return _error(f"Unknown menu: {name}")
        except Exception as e:
            return _error(f"Menu lookup failed: {e}")
        return _menu(name)

    if verb == "back":
        return _back()

    if verb == "home":
        return _menu("main")

    # ------------------------------------------------------------------
    # Prompt command
    # ------------------------------------------------------------------
    if verb == "prompt":
        if not rest:
            return _error("Malformed prompt command")
        fields = get_prompt_fields(rest)
        if fields is None:
            return _error(f"Unknown prompt: {' '.join(rest)}")
        template = get_command_template(rest)
        return _prompt(rest, fields, template)

    # ------------------------------------------------------------------
    # Help
    # ------------------------------------------------------------------
    if verb == "help":
        topic = rest[0].lower() if rest else "overview"
        if topic not in HELP_TEXT:
            return _error(f"Unknown help topic: {topic}")
        return _view("help", topic)

    # ------------------------------------------------------------------
    # Views
    # ------------------------------------------------------------------
    if verb == "capabilities" and not rest:
        return _view("capabilities")

    if verb == "layers" and not rest:
        return _view("layers")

    if verb == "engines":
        if not rest:
            return _view("engines")
        sub = rest[0].lower()
        if sub == "heartbeat":
            return _view("engines_heartbeat")
        return _error(f"Unknown engines subcommand: {sub}")

    if verb == "system":
        if not rest:
            return _view("system")
        sub = rest[0].lower()
        if sub == "config":
            return _view("system_config")
        if sub == "blackboard":
            return _view("system_blackboard")
        if sub == "audit":
            return _view("system_audit")
        if sub == "resources":
            return _view("system_resources")
        if sub == "reload":
            if len(rest) >= 2 and rest[1].lower() == "all":
                ok, msg = _call_action(actions.reload_all)
                return _ok(msg) if ok else _error(msg)
            ok, msg = _call_action(actions.reload_config)
            return _ok(msg) if ok else _error(msg)
        return _error(f"Unknown system subcommand: {sub}")

    if verb == "reload":
        if rest and rest[0].lower() == "all":
            ok, msg = _call_action(actions.reload_all)
            return _ok(msg) if ok else _error(msg)
        ok, msg = _call_action(actions.reload_config)
        return _ok(msg) if ok else _error(msg)

    # ------------------------------------------------------------------
    # Diagnostics
    # ------------------------------------------------------------------
    if verb == "diag":
        if not rest:
            return _view("diagnostics")
        sub = rest[0].lower()

        if sub == "summary":
            return _view("diag_state")

        if sub == "failures":
            return _view("diag_failures")

        if sub == "ips":
            return _view("diag_ips")

        if sub == "events":
            if len(rest) >= 2 and rest[1].lower() == "all":
                return _view("diag_events", "all")
            return _view("diag_events")

        if sub == "health":
            return _view("diag_health")

        if sub in ("reader", "monitor", "ais", "state",
                   "response", "mtd"):
            return _view("diag_layer", sub)

        return _error(f"Unknown diag subcommand: {sub}")

    # ------------------------------------------------------------------
    # Capability actions
    # ------------------------------------------------------------------
    if verb == "enable":
        if not rest:
            return _error("Usage: enable <name>")
        if rest[0].lower() == "capability" and len(rest) >= 2:
            name = " ".join(rest[1:])
        else:
            name = rest[0]
        ok, msg = _call_action(actions.enable_capability, name)
        return _ok(msg) if ok else _error(msg)

    if verb == "disable":
        if not rest:
            return _error("Usage: disable <name>")
        if rest[0].lower() == "capability" and len(rest) >= 2:
            name = " ".join(rest[1:])
        else:
            name = rest[0]
        ok, msg = _call_action(actions.disable_capability, name)
        return _ok(msg) if ok else _error(msg)

    if verb == "capability":
        if not rest:
            return _error("Usage: capability <path|add|remove|telemetry> ...")
        sub = rest[0].lower()
        args = rest[1:]
        if sub == "path":
            if len(args) < 2:
                return _error("Usage: capability path <name> <path>")
            name = args[0]
            path = " ".join(args[1:])
            ok, msg = _call_action(actions.change_capability_path, name, path)
            return _ok(msg) if ok else _error(msg)
        if sub == "add":
            if len(args) < 2:
                return _error("Usage: capability add <name> <path>")
            name = args[0]
            path = " ".join(args[1:])
            ok, msg = _call_action(actions.add_custom_log, name, path)
            return _ok(msg) if ok else _error(msg)
        if sub == "remove":
            if not args:
                return _error("Usage: capability remove <name>")
            ok, msg = _call_action(actions.remove_custom_log, args[0])
            return _ok(msg) if ok else _error(msg)
        if sub == "telemetry":
            if not args:
                return _error("Usage: capability telemetry <name>")
            return _view("telemetry", args[0])
        return _error(f"Unknown capability subcommand: {sub}")

    if verb == "path":
        if len(rest) < 2:
            return _error("Usage: path <name> <path>")
        name = rest[0]
        path = " ".join(rest[1:])
        ok, msg = _call_action(actions.change_capability_path, name, path)
        return _ok(msg) if ok else _error(msg)

    if verb == "telemetry":
        if not rest:
            return _error("Usage: telemetry <name>")
        return _view("telemetry", rest[0])

    if verb == "add":
        if len(rest) < 2:
            return _error("Usage: add <name> <path>")
        name = rest[0]
        path = " ".join(rest[1:])
        ok, msg = _call_action(actions.add_custom_log, name, path)
        return _ok(msg) if ok else _error(msg)

    if verb == "remove":
        if not rest:
            return _error("Usage: remove <name>")
        ok, msg = _call_action(actions.remove_custom_log, rest[0])
        return _ok(msg) if ok else _error(msg)

    # ------------------------------------------------------------------
    # Layer actions
    # ------------------------------------------------------------------
    if verb == "layer":
        if len(rest) < 2:
            return _error("Usage: layer <enable|disable|restart|display|status> <id>")
        sub = rest[0].lower()
        layer_id = rest[1].lower()
        if sub == "enable":
            ok, msg = _call_action(actions.enable_layer, layer_id)
            return _ok(msg) if ok else _error(msg)
        if sub == "disable":
            ok, msg = _call_action(actions.disable_layer, layer_id)
            return _ok(msg) if ok else _error(msg)
        if sub == "restart":
            ok, msg = _call_action(actions.restart_layer, layer_id)
            return _ok(msg) if ok else _error(msg)
        if sub == "display":
            ok, msg = _call_action(actions.toggle_layer_display, layer_id)
            return _ok(msg) if ok else _error(msg)
        if sub == "status":
            return _view("layer_status", layer_id)
        return _error(f"Unknown layer subcommand: {sub}")

    # ------------------------------------------------------------------
    # Engine actions
    # ------------------------------------------------------------------
    if verb == "engine":
        if len(rest) < 2:
            return _error("Usage: engine <restart|logs> <name>")
        sub = rest[0].lower()
        name = rest[1].lower()
        if sub == "restart":
            if name == "all":
                ok, msg = _call_action(actions.restart_all_layers)
                return _ok(msg) if ok else _error(msg)
            ok, msg = _call_action(actions.restart_layer, name)
            return _ok(msg) if ok else _error(msg)
        if sub == "logs":
            return _view("engine_logs", name)
        return _error(f"Unknown engine subcommand: {sub}")

    # ------------------------------------------------------------------
    # Display
    # ------------------------------------------------------------------
    if verb == "display":
        return _handle_display(rest)

    # ------------------------------------------------------------------
    # Filter
    # ------------------------------------------------------------------
    if verb == "filter":
        return _handle_filter(rest)

    # ------------------------------------------------------------------
    # Layout
    # ------------------------------------------------------------------
    if verb == "layout":
        if not rest:
            return _error("Usage: layout single | side-by-side | stacked")
        mode = rest[0].lower()
        ok, msg = _call_action(actions.set_layout, mode)
        return _ok(msg) if ok else _error(msg)

    # ------------------------------------------------------------------
    # Refresh
    # ------------------------------------------------------------------
    if verb == "refresh":
        ok, msg = _call_action(actions.refresh_layer_state)
        return _ok(msg) if ok else _error(msg)

    # ------------------------------------------------------------------
    # Unknown
    # ------------------------------------------------------------------
    return _error(f"Unknown command: {line.strip()}")