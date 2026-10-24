# console/menus.py
# ============================================================================
# CONSOLE MENUS — Menu tree definitions
# ============================================================================
# Data-only. Describes the structure of every menu in the console.
#
# COMMAND GRAMMAR:
#   A menu item's "command" field is one of:
#     - "__back__"      Return to the parent menu.
#     - "__quit__"      Exit the console (with confirmation).
#     - "menu <name>"   Open the named menu.
#     - "prompt <cmd>"  Ask the user for parameters, then run <cmd>.
#     - "<action>"      Run the action directly.
#   None is reserved as a placeholder (currently unused).
#
# STRUCTURE:
#   Each menu is a read-only mapping with keys:
#     - "title":   displayed at the top
#     - "items":   immutable tuple of (key, label, command) tuples
#     - "prompt":  prompt shown to the user
#
# VALIDATION:
#   validate_menus() runs at import time and raises on developer error.
#   It checks key presence, item shape, item-key uniqueness, and command
#   format. Runtime never sees a malformed menu.
#
# DOES NOT RENDER. DOES NOT EXECUTE. The app and commands modules do that.
# ============================================================================

from types import MappingProxyType


# ----------------------------------------------------------------------
# Internal builder
# ----------------------------------------------------------------------
def _menu(title, items, prompt="Select option: "):
    """Build a frozen menu. Items must already be a tuple of 3-tuples."""
    return MappingProxyType({
        "title": title,
        "items": items,
        "prompt": prompt,
    })


# ----------------------------------------------------------------------
# Menu definitions
# ----------------------------------------------------------------------
MAIN_MENU = _menu(
    "Main Menu",
    (
        ("1", "Capabilities", "menu capabilities"),
        ("2", "Layers", "menu layers"),
        ("3", "Engines", "menu engines"),
        ("4", "System", "menu system"),
        ("5", "Display", "menu display"),
        ("6", "Diagnostics", "menu diagnostics"),
        ("7", "Help", "menu help"),
        ("q", "Quit", "__quit__"),
    ),
)

CAPABILITIES_MENU = _menu(
    "Capabilities",
    (
        ("1", "List capabilities", "capabilities"),
        ("2", "Enable a capability", "prompt enable capability"),
        ("3", "Disable a capability", "prompt disable capability"),
        ("4", "Change capability path", "prompt capability path"),
        ("5", "Show capability telemetry", "prompt capability telemetry"),
        ("6", "Add custom log", "prompt capability add"),
        ("7", "Remove custom log", "prompt capability remove"),
        ("b", "Back", "__back__"),
    ),
)

LAYERS_MENU = _menu(
    "Layers",
    (
        ("1", "List layers", "layers"),
        ("2", "Enable a layer", "prompt layer enable"),
        ("3", "Disable a layer", "prompt layer disable"),
        ("4", "Restart a layer", "prompt layer restart"),
        ("5", "Toggle layer display", "prompt layer display"),
        ("6", "Show engine status", "prompt layer status"),
        ("b", "Back", "__back__"),
    ),
)

ENGINES_MENU = _menu(
    "Engines",
    (
        ("1", "List engines", "engines"),
        ("2", "Restart an engine", "prompt engine restart"),
        ("3", "Restart all engines", "prompt engine restart all"),
        ("4", "Show heartbeats", "engines heartbeat"),
        ("5", "Show engine logs", "prompt engine logs"),
        ("b", "Back", "__back__"),
    ),
)

SYSTEM_MENU = _menu(
    "System",
    (
        ("1", "View configuration", "system config"),
        ("2", "View Blackboard", "system blackboard"),
        ("3", "View audit log", "system audit"),
        ("4", "Show resource usage", "system resources"),
        ("5", "Reload configuration", "prompt system reload"),
        ("6", "Reload all", "prompt system reload all"),
        ("b", "Back", "__back__"),
    ),
)

DISPLAY_MENU = _menu(
    "Display",
    (
        ("1", "Set layout", "prompt display layout"),
        ("2", "Show a capability or layer", "prompt display show"),
        ("3", "Hide a capability or layer", "prompt display hide"),
        ("4", "Filter by source", "prompt filter set"),
        ("5", "Clear filter", "filter clear"),
        ("6", "Reset display", "display reset"),
        ("b", "Back", "__back__"),
    ),
)

DIAGNOSTICS_MENU = _menu(
    "Diagnostics",
    (
        ("1", "Show state and risk", "diag state"),
        ("2", "Show failure counts", "diag failures"),
        ("3", "Show attacker IPs", "diag ips"),
        ("4", "Show recent events", "diag events"),
        ("5", "Show engine health", "diag health"),
        ("b", "Back", "__back__"),
    ),
)

HELP_MENU = _menu(
    "Help",
    (
        ("1", "Overview", "help overview"),
        ("2", "List all commands", "help commands"),
        ("3", "Navigation", "help navigation"),
        ("4", "Display", "help display"),
        ("5", "Layers and engines", "help layers"),
        ("b", "Back", "__back__"),
    ),
)


# ----------------------------------------------------------------------
# Registry
# ----------------------------------------------------------------------
MENUS = {
    "main": MAIN_MENU,
    "capabilities": CAPABILITIES_MENU,
    "layers": LAYERS_MENU,
    "engines": ENGINES_MENU,
    "system": SYSTEM_MENU,
    "display": DISPLAY_MENU,
    "diagnostics": DIAGNOSTICS_MENU,
    "help": HELP_MENU,
}


# ----------------------------------------------------------------------
# Validation (runs once at import)
# ----------------------------------------------------------------------
def validate_menus():
    """
    Validate the structure of every menu in MENUS.
    Raises ValueError on the first structural problem found.
    Called automatically at module import.
    """
    required_keys = ("title", "items", "prompt")

    for name, menu in MENUS.items():
        if not isinstance(name, str) or not name:
            raise ValueError("Menu name must be a non-empty string")

        for key in required_keys:
            if key not in menu:
                raise ValueError(f"Menu '{name}' missing required key '{key}'")

        if not isinstance(menu["title"], str) or not menu["title"]:
            raise ValueError(f"Menu '{name}': title must be a non-empty string")

        if not isinstance(menu["prompt"], str):
            raise ValueError(f"Menu '{name}': prompt must be a string")

        items = menu["items"]
        if not isinstance(items, tuple):
            raise ValueError(f"Menu '{name}': items must be a tuple")

        seen_keys = set()
        for item in items:
            if not isinstance(item, tuple) or len(item) != 3:
                raise ValueError(
                    f"Menu '{name}': each item must be a 3-tuple (key, label, command)"
                )
            item_key, label, command = item
            if not isinstance(item_key, str) or not item_key:
                raise ValueError(f"Menu '{name}': item key must be a non-empty string")
            if item_key.lower() in seen_keys:
                raise ValueError(
                    f"Menu '{name}': duplicate item key '{item_key}'"
                )
            seen_keys.add(item_key.lower())
            if not isinstance(label, str) or not label:
                raise ValueError(
                    f"Menu '{name}': item label must be a non-empty string"
                )
            if command is None:
                continue
            if not isinstance(command, str) or not command.strip():
                raise ValueError(
                    f"Menu '{name}': command must be a non-empty string or None"
                )


# Run validation once at import time
validate_menus()


# ----------------------------------------------------------------------
# Public helpers
# ----------------------------------------------------------------------
def get_menu(name: str):
    """
    Return the read-only menu mapping for a given name, or None if unknown.
    The returned object cannot be mutated; attempts raise TypeError.
    """
    if not isinstance(name, str):
        return None
    return MENUS.get(name.lower())


def get_main_menu():
    """Return the read-only main menu mapping."""
    return MAIN_MENU


def menu_names():
    """Return the list of valid menu names (a snapshot copy)."""
    return list(MENUS.keys())


def resolve_item(menu_name: str, key: str):
    """
    Return (label, command) for a given menu item key, or None if not found.
    Key comparison is case-insensitive and whitespace-trimmed.
    """
    menu = get_menu(menu_name)
    if menu is None:
        return None
    if not isinstance(key, str):
        return None
    key = key.strip().lower()
    for item_key, label, command in menu["items"]:
        if item_key.lower() == key:
            return (label, command)
    return None