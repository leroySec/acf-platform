#!/usr/bin/env python3
# ============================================================================
# CONFIG INTERACTIVE — Interactive Setup for ACF
# ============================================================================

import os
import sys
import json
import time
import subprocess
import re
import getpass
import shutil

from rich.console import Console, Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.box import ROUNDED

from config import Config
from platform_utils import get_temp_dir
from config import PreconditionChecks, BlackboardSchema
from sensor_config import SensorConfig, SensorPreconditionChecks
from os_primitive_config import OsPrimitiveConfig, OsPrimitivePreconditionChecks  # os_primitive_config
from setup_validator import (
    check_admin,
    check_ssh_event_log_windows,
    pre_flight_check,
    check_locking_available,
)
from layer_selection import (
    ALL_LAYERS_ORDER,
    LAYER_LABELS,
    run_layer_selection,
)

PYTHON_CMD = sys.executable

BLACKBOARD_FILE = Config.BLACKBOARD_FILE
SYSTEM_CONFIG_FILE = "system_config.json"
LOG_FILE = Config.LOG_FILE
PID_FILE = os.path.join(get_temp_dir(), "acf_layer_manager.pid")
STATE_FILE = os.path.join(get_temp_dir(), "acf_layer_manager_state.json")
LAYER_STATE_FILE = Config.LAYER_STATE_FILE

# Capabilities whose source metadata is derived from a hardcoded
# primitive in os_primitive_config.py. Their patterns (if any) are
# trustworthy and must survive config reloads. Everything else is a
# custom capability: user-supplied patterns written by the removed
# prompt are dropped on load so the reader's compiled default list is
# authoritative.
_PRIMITIVE_SOURCE_CAPS = {"firewall", "defender"}

console = Console()


# ----------------------------------------------------------------------
# Terminal clear
# ----------------------------------------------------------------------
def _clear():
    if os.name == "nt":
        subprocess.run("cls", shell=True)
    else:
        subprocess.run("clear", shell=True)


def _draw(renderable):
    _clear()
    console.print(renderable)


# ----------------------------------------------------------------------
# Layout primitives
# ----------------------------------------------------------------------
def _box_width():
    return min(max(console.width - 4, 60), 88)


def _title_panel(text):
    return Panel(
        Text(text, justify="center", style="bold white"),
        border_style="bright_black",
        box=ROUNDED,
        padding=(0, 1),
    )


def _capabilities_box(discovered, enabled_caps):
    body = Text()
    for name, info in discovered.items():
        available = info.get("available", False)
        if name in enabled_caps:
            body.append(f"  ✓ ", style="bold green")
            body.append(f"{name}\n", style="bold white")
        elif available:
            body.append(f"  ○ ", style="green")
            body.append(f"{name}\n", style="white")
        else:
            body.append(f"  ✕ ", style="red")
            body.append(f"{name}\n", style="grey42")
    if not discovered:
        body.append("  (none)\n", style="grey42")
    return Panel(
        body,
        title="[bold green]DISCOVERED CAPABILITIES[/bold green]",
        title_align="left",
        border_style="green",
        box=ROUNDED,
        padding=(1, 1),
    )


def _config_box(enabled_caps, capability_layers):
    current_layers = [L for L in ALL_LAYERS_ORDER
                      if any(L in caps for caps in capability_layers.values())]
    body = Text()
    body.append("  ENABLED:\n", style="bold blue")
    if enabled_caps:
        for cap in enabled_caps:
            body.append(f"    ✓ {cap}\n", style="white")
    else:
        body.append("    ○ None\n", style="grey42")
    body.append("\n  LAYERS IN USE:\n", style="bold blue")
    if current_layers:
        for L in current_layers:
            body.append(f"    ● {L}\n", style="white")
    else:
        body.append("    ○ None\n", style="grey42")
    return Panel(
        body,
        title="[bold blue]CURRENT CONFIGURATION[/bold blue]",
        title_align="left",
        border_style="blue",
        box=ROUNDED,
        padding=(1, 1),
    )


def _options_box(left_items, right_items):
    left = Text()
    for key, label in left_items:
        left.append(f"  [{key}]  ", style="bold purple")
        left.append(f"{label}\n", style="white")
    right = Text()
    for key, label in right_items:
        right.append(f"  [{key}]  ", style="bold purple")
        right.append(f"{label}\n", style="white")
    grid = Table.grid(expand=True, padding=(0, 2))
    grid.add_column(ratio=4)
    grid.add_column(ratio=3)
    grid.add_row(left, right)
    return Panel(
        grid,
        title="[bold purple]OPTIONS[/bold purple]",
        title_align="left",
        border_style="purple",
        box=ROUNDED,
        padding=(1, 1),
    )


def _input_box():
    return Panel(
        Text.from_markup("  [grey42]▌[/grey42]  [grey42]enter your choice[/grey42]"),
        border_style="cyan",
        box=ROUNDED,
        padding=(0, 1),
    )


def _wrap_outer(*children):
    return Panel(
        Group(*children),
        border_style="bright_black",
        box=ROUNDED,
        padding=(1, 1),
        width=_box_width(),
    )


def _main_screen(discovered, enabled_caps, capability_layers,
                 title="ACF INTERACTIVE CONFIGURATION SETUP"):
    top_row = Table.grid(expand=True, padding=(0, 1))
    top_row.add_column(ratio=1)
    top_row.add_column(ratio=1)
    top_row.add_row(
        _capabilities_box(discovered, enabled_caps),
        _config_box(enabled_caps, capability_layers),
    )
    return _wrap_outer(
        _title_panel(title),
        top_row,
        _options_box(
            [("a", "Add capability"),
             ("r", "Remove capability"),
             ("m", "Modify path"),
             ("l", "Select layers")],
            [("v", "View configuration"),
             ("s", "Save & launch"),
             ("q", "Quit without saving")],
        ),
        _input_box(),
    )


def _read(text="enter your choice"):
    console.print()
    console.print(f"[bold cyan]>[/bold cyan] {text}: ", end="")
    return console.input("").strip().lower()


def _pause(text="Press Enter to continue"):
    console.print()
    console.input(f"[cyan]{text}...[/cyan]")


# ----------------------------------------------------------------------
# LOG FILE VALIDATION
# ----------------------------------------------------------------------
def validate_log_file(filepath):
    if not os.path.isfile(filepath):
        return False, "Not a regular file"
    if os.path.getsize(filepath) == 0:
        return False, "File is empty"
    try:
        with open(filepath, 'rb') as f:
            data = f.read(4096)
        if len(data) == 0:
            return False, "File is empty"
        bom_markers = {
            b'\xef\xbb\xbf': 'utf-8',
            b'\xff\xfe': 'utf-16-le',
            b'\xfe\xff': 'utf-16-be',
        }
        for marker, enc in bom_markers.items():
            if data.startswith(marker):
                data = data[len(marker):]
                break
        text = None
        decoders = [
            ('utf-8', 'ignore'),
            ('utf-16-le', 'ignore'),
            ('utf-16-be', 'ignore'),
            ('utf-8', 'replace'),
        ]
        for enc, errors in decoders:
            try:
                text = data.decode(enc, errors=errors)
                break
            except UnicodeDecodeError:
                continue
        if text is None:
            return False, "Could not decode file as text"
        has_newline = '\n' in text or '\r\n' in text or '\r' in text
        if not has_newline and len(text) > 200:
            return False, "File does not contain line breaks (not a valid log file)"
        printable_count = sum(1 for c in text if c.isprintable() or c in '\n\r\t')
        printable_ratio = printable_count / len(text) if len(text) > 0 else 0
        if printable_ratio < 0.4:
            return False, "File contains mostly non-printable data (not a text log)"
        word_pattern = r'[a-zA-Z0-9_]{3,}'
        delimiter_pattern = r'[:/.\-_=]'
        has_word = bool(re.search(word_pattern, text))
        has_delimiter = bool(re.search(delimiter_pattern, text))
        if not has_word and not has_delimiter:
            return False, "File does not contain readable strings (not a text log)"
        return True, None
    except Exception as e:
        return False, f"Validation error: {e}"


# ----------------------------------------------------------------------
# DISCOVER CAPABILITIES
# ----------------------------------------------------------------------
def discover_capabilities():
    result = {}

    ssh_available = False
    ssh_path = None
    if os.name == 'nt':
        if check_ssh_event_log_windows():
            ssh_available = True
            ssh_path = "Windows Event Log (OpenSSH/Operational)"
    else:
        if os.path.exists("/var/log/auth.log"):
            ssh_available = True
            ssh_path = "/var/log/auth.log"
        else:
            try:
                check = subprocess.run(
                    ["journalctl", "-u", "ssh", "--no-pager", "-n", "1"],
                    capture_output=True, timeout=2
                )
                if check.returncode == 0:
                    ssh_available = True
                    ssh_path = "journalctl -u ssh"
            except Exception:
                pass
    result["ssh"] = {"available": ssh_available, "path": ssh_path, "type": "log"}

    sensor_check = SensorPreconditionChecks.check_sensor_capabilities()
    sensor_available = sensor_check.get("status") == "ready"
    sensor_method = sensor_check.get("method", "unknown")
    result["sensor"] = {
        "available": sensor_available,
        "path": sensor_method,
        "method": sensor_method,
        "type": "kernel",
    }

    # os_primitive_config — defender pre-check (before any operator input)
    defender_check = OsPrimitivePreconditionChecks.check_defender_capabilities()
    defender_details = defender_check.get("details", {}) or {}
    defender_channel = defender_details.get("channel", "")
    defender_path = (
        f"Windows Event Log ({defender_channel})" if defender_channel else None
    )
    result["defender"] = {
        "available": defender_check.get("status") == "ready",
        "path": defender_path,
        "method": defender_check.get("method", "unknown"),
        "type": "eventlog",
        "details": defender_details,
    }

    # os_primitive_config — firewall pre-check (before any operator input)
    firewall_check = OsPrimitivePreconditionChecks.check_firewall_capabilities()
    firewall_details = firewall_check.get("details", {}) or {}
    result["firewall"] = {
        "available": firewall_check.get("status") == "ready",
        "path": firewall_details.get("path"),
        "method": firewall_check.get("method", "unknown"),
        "type": "file",
        "details": firewall_details,
    }

    app_logs = {
        "app_http": {"paths": ["/var/log/nginx/error.log", "/var/log/apache2/error.log"]},
        "app_smtp": {"paths": ["/var/log/mail.log", "/var/log/mail/mail.log", "/var/log/maillog"]},
        "app_ftp": {"paths": ["/var/log/vsftpd.log"]},
        "app_mysql": {"paths": ["/var/log/mysql/error.log", "/var/log/mariadb/mariadb.log"]},
    }
    if hasattr(SensorConfig, "APP_LOG_SECTION_PATHS") and hasattr(SensorConfig, "APP_LOG_FILE_PATTERNS"):
        for base_path in SensorConfig.APP_LOG_SECTION_PATHS:
            if not os.path.exists(base_path):
                continue
            try:
                for root, dirs, files in os.walk(base_path):
                    for f in files:
                        full_path = os.path.join(root, f)
                        for pattern in SensorConfig.APP_LOG_FILE_PATTERNS:
                            if pattern in f:
                                cap_id = None
                                if "mail" in f or "mail" in root:
                                    cap_id = "app_smtp"
                                elif "vsftpd" in f:
                                    cap_id = "app_ftp"
                                elif "mysql" in f or "mysql" in root or "mariadb" in f or "mariadb" in root:
                                    cap_id = "app_mysql"
                                elif "nginx" in root or "apache" in root or "http" in f or "error.log" in f or "access.log" in f:
                                    cap_id = "app_http"
                                if cap_id and cap_id in app_logs:
                                    if not app_logs[cap_id].get("found"):
                                        app_logs[cap_id]["found"] = True
                                        app_logs[cap_id]["path"] = full_path
                                break
            except PermissionError:
                continue

    for app_id, info in app_logs.items():
        if info.get("found"):
            result[app_id] = {"available": True, "path": info["path"], "type": "log"}
        else:
            found = False
            for p in info["paths"]:
                if os.path.exists(p) and os.access(p, os.R_OK):
                    result[app_id] = {"available": True, "path": p, "type": "log"}
                    found = True
                    break
            if not found:
                result[app_id] = {"available": False, "path": None, "type": "log"}

    return result


# ----------------------------------------------------------------------
# CUSTOM LOG ADDER
# ----------------------------------------------------------------------
def sanitize_capability_name(name):
    return re.sub(r'[^a-zA-Z0-9_]', '_', name.lower())


def add_custom_log(discovered, items):
    """
    Prompt the operator for a custom log source.

    Accepts either:
      - a file path: C:\\path\\to\\log.log
      - a Windows event log string:
        Windows Event Log (Microsoft-Windows-Windows Defender/Operational)

    Returns (name, canonical_path, source_meta) where source_meta is
    a dict carrying type and, for eventlog sources, event_ids.

    No patterns are collected. The reader's compiled default pattern
    list applies to file sources that carry no per-capability
    override. Only firewall and defender carry pattern overrides, and
    those are delivered by os_primitive_config, not by this flow.
    """
    _draw(_wrap_outer(
        _title_panel("ADD CUSTOM LOG"),
        Panel("[grey62]Type 'c' at any prompt to cancel.[/grey62]\n"
              "[grey62]File path or 'Windows Event Log (<channel>)'[/grey62]",
              border_style="purple", box=ROUNDED, padding=(1, 1)),
        _input_box(),
    ))

    source_meta = {}

    while True:
        console.print()
        console.print("[cyan]Enter path to log file or event log:[/cyan] ", end="")
        path = console.input("").strip()
        if path.lower() == "c":
            console.print("[yellow]Cancelled.[/yellow]")
            return None, None, None

        if path.startswith("Windows Event Log ("):
            # Event log string. No file validation. Optionally ask
            # for event IDs.
            m = re.search(r"\(([^)]+)", path)
            if not m:
                console.print("[red]Invalid event log string.[/red]")
                continue
            channel = m.group(1).strip()
            if not channel:
                console.print("[red]Empty channel name.[/red]")
                continue
            canonical_path = path
            source_meta["type"] = "eventlog"

            console.print(
                f"\n[cyan]Event IDs to match (comma-separated, "
                f"or Enter to accept all):[/cyan] ", end="")
            eid_line = console.input("").strip()
            if eid_line:
                ids = []
                for tok in eid_line.split(","):
                    tok = tok.strip()
                    if tok.isdigit():
                        ids.append(int(tok))
                if ids:
                    source_meta["event_ids"] = ids
            break

        canonical_path = os.path.realpath(path)
        if not os.path.exists(canonical_path):
            console.print(f"[red]Path does not exist:[/red] {canonical_path}")
            continue
        if not os.access(canonical_path, os.R_OK):
            console.print(f"[red]Path is not readable:[/red] {canonical_path}")
            continue
        if not os.path.isfile(canonical_path):
            console.print(f"[red]Not a regular file:[/red] {canonical_path}")
            continue
        valid, msg = validate_log_file(canonical_path)
        if not valid:
            console.print(f"[red]Invalid log file:[/red] {msg}")
            continue
        source_meta["type"] = "file"
        break

    default_name = sanitize_capability_name(
        os.path.splitext(os.path.basename(canonical_path))[0]
    ) or "custom_log"

    console.print(f"\n[grey62]Default name:[/grey62] [bold white]{default_name}[/bold white]")

    while True:
        console.print("[cyan]Enter a name for this capability (or press Enter for default):[/cyan] ", end="")
        name = console.input("").strip()
        if not name:
            name = default_name
        name = sanitize_capability_name(name)
        if not name:
            console.print("[red]Invalid name. Use letters, numbers, underscores.[/red]")
            continue
        if name in discovered:
            console.print(f"[yellow]Name '{name}' already exists.[/yellow]")
            rename = console.input("[cyan]Use a different name? (y/n):[/cyan] ").strip().lower()
            if rename == "y":
                continue
            suffix = 1
            base = name
            while f"{base}_{suffix}" in discovered:
                suffix += 1
            name = f"{base}_{suffix}"
            console.print(f"[yellow]Auto-renamed to:[/yellow] [bold white]{name}[/bold white]")
        break

    return name, canonical_path, source_meta


# ----------------------------------------------------------------------
# LOAD EXISTING CONFIG
# ----------------------------------------------------------------------
def load_existing_config():
    """
    Returns (enabled_caps, custom_paths, capability_layers,
             sources_dict, capability_rules).

    capability_rules is returned unchanged from disk so the setup flow
    can preserve operator-authored sub-keys (fail2ban, shuffle, etc.)
    across saves. Only capability_rules.sensor is owned by this flow.
    """
    try:
        with open(SYSTEM_CONFIG_FILE, 'r') as f:
            config = json.load(f)
        enabled_dict = config.get("enabled_capabilities", {})
        paths_dict = config.get("capability_paths", {})
        sources_dict = config.get("capability_sources", {})
        if not isinstance(sources_dict, dict):
            sources_dict = {}

        # Strip user-supplied patterns from any capability that is not
        # backed by a hardcoded primitive in os_primitive_config.py.
        # The removed interactive prompt used to write operator-typed
        # strings into this key; those strings overrode the reader's
        # compiled default list and could not match real log content.
        # Preserve only the two capabilities whose pattern lists come
        # from a primitive.
        cleaned_sources = {}
        for cap, src in sources_dict.items():
            if not isinstance(src, dict):
                continue
            entry = dict(src)
            if cap not in _PRIMITIVE_SOURCE_CAPS:
                entry.pop("patterns", None)
            if entry:
                cleaned_sources[cap] = entry
        sources_dict = cleaned_sources

        capability_rules = config.get("capability_rules", {})
        if not isinstance(capability_rules, dict):
            capability_rules = {}

        enabled_caps = []
        custom_paths = {}
        for cap, val in enabled_dict.items():
            if cap == "custom":
                continue
            if val:
                enabled_caps.append(cap)
        for cap, val in paths_dict.items():
            if cap == "custom":
                continue
            custom_paths[cap] = val
        custom_enabled = enabled_dict.get("custom", {})
        if isinstance(custom_enabled, dict):
            for cap, val in custom_enabled.items():
                if val and cap not in enabled_caps:
                    enabled_caps.append(cap)
        custom_subpaths = paths_dict.get("custom", {})
        if isinstance(custom_subpaths, dict):
            for cap, val in custom_subpaths.items():
                custom_paths[cap] = val
        capability_layers = config.get("capability_layers", {})
        if not isinstance(capability_layers, dict):
            capability_layers = {}
        capability_layers = {
            cap: list(layers) for cap, layers in capability_layers.items()
            if cap in enabled_caps and isinstance(layers, list)
        }
        return (enabled_caps, custom_paths, capability_layers,
                sources_dict, capability_rules)
    except Exception:
        return [], {}, {}, {}, {}


def validate_layer_dependencies(enabled_caps, capability_layers):
    warnings = []
    layers = [L for L in ALL_LAYERS_ORDER
              if any(L in caps for caps in capability_layers.values())]
    if "layer4c" in layers and "ssh" not in enabled_caps:
        warnings.append("MTD layer (layer4c) requires SSH to be enabled.")
    if "layer4a" in layers:
        monitoring_caps = [cap for cap in enabled_caps if cap != "ssh"]
        if not monitoring_caps:
            warnings.append("Response layer (layer4a) requires at least one monitoring capability.")
    custom_caps = [cap for cap in enabled_caps
                   if cap not in ["ssh", "sensor",
                                  "app_http", "app_smtp", "app_ftp", "app_mysql"]]
    if custom_caps and "layer1" not in layers:
        warnings.append("Custom logs are enabled but Layer 1 is not selected.")
    return not warnings, warnings


# ----------------------------------------------------------------------
# SUB-FLOWS
# ----------------------------------------------------------------------
def _add_capability_flow(discovered, items, enabled_caps, custom_paths,
                          capability_sources):
    _draw(_wrap_outer(
        _title_panel("ADD CAPABILITY"),
        Panel(
            Text.from_markup(
                "  [bold cyan]1.[/bold cyan] Add custom log file (manual)\n"
                "  [bold cyan]2.[/bold cyan] Enable discovered capability"
            ),
            border_style="purple", box=ROUNDED, padding=(1, 1),
        ),
        _input_box(),
    ))
    console.print()
    sub = console.input("[bold cyan]>[/bold cyan] Enter 1 or 2: ").strip()

    if sub == '1':
        name, path, source_meta = add_custom_log(discovered, items)
        if name and path:
            if name not in discovered:
                discovered[name] = {
                    "available": True, "path": path,
                    "type": source_meta.get("type", "file"),
                }
                items.append(name)
            if name not in enabled_caps:
                enabled_caps.append(name)
            custom_paths[name] = path
            capability_sources[name] = source_meta or {"type": "file"}
            console.print(f"[green]Added custom log '{name}'.[/green]")

    elif sub == '2':
        available = [cap for cap in items if cap not in enabled_caps]
        if not available:
            _draw(_wrap_outer(
                _title_panel("ADD CAPABILITY"),
                Panel("[yellow]No additional discovered capabilities to enable.[/yellow]",
                      border_style="yellow", box=ROUNDED, padding=(1, 1)),
                _input_box(),
            ))
            _pause()
            return discovered, items, enabled_caps, custom_paths, capability_sources

        table = Table.grid(expand=True, padding=(0, 1))
        table.add_column(justify="right", width=3, style="bold cyan")
        table.add_column(width=14, style="bold white")
        table.add_column(width=4)
        table.add_column(style="grey62")
        for i, cap in enumerate(available, 1):
            info = discovered[cap]
            avail = info["available"]
            mark = Text("✓", style="green") if avail else Text("✕", style="red")
            table.add_row(f"{i}.", cap, mark, info.get("path", "unknown"))

        _draw(_wrap_outer(
            _title_panel("ADD CAPABILITY"),
            Panel(table, border_style="purple", box=ROUNDED, padding=(1, 1)),
            _input_box(),
        ))
        console.print()
        idx = console.input("[bold cyan]>[/bold cyan] Select a number "
                            "[grey62](Enter to cancel)[/grey62]: ").strip()
        if idx.isdigit():
            idx = int(idx) - 1
            if 0 <= idx < len(available):
                cap = available[idx]
                if cap not in enabled_caps:
                    enabled_caps.append(cap)
                    if cap not in custom_paths and discovered[cap].get("path"):
                        custom_paths[cap] = discovered[cap]["path"]
                    # os_primitive_config — carry pre-check details into
                    # capability_sources so the reader gets event_ids/patterns.
                    if cap not in capability_sources:
                        det = discovered[cap].get("details") or {}
                        if discovered[cap].get("type") and det:
                            src = {"type": discovered[cap]["type"]}
                            if "event_ids" in det:
                                src["event_ids"] = list(det["event_ids"])
                            if cap in _PRIMITIVE_SOURCE_CAPS and "patterns" in det:
                                src["patterns"] = list(det["patterns"])
                            capability_sources[cap] = src
                    console.print(f"[green]Enabled '{cap}'.[/green]")

    return discovered, items, enabled_caps, custom_paths, capability_sources


def _remove_capability_flow(enabled_caps, custom_paths, capability_layers,
                             capability_sources):
    if not enabled_caps:
        _draw(_wrap_outer(
            _title_panel("REMOVE CAPABILITY"),
            Panel("[yellow]No capabilities to remove.[/yellow]",
                  border_style="yellow", box=ROUNDED, padding=(1, 1)),
            _input_box(),
        ))
        _pause()
        return enabled_caps, custom_paths, capability_layers, capability_sources

    table = Table.grid(expand=True, padding=(0, 1))
    table.add_column(justify="right", width=3, style="bold cyan")
    table.add_column(style="white")
    for i, cap in enumerate(enabled_caps, 1):
        table.add_row(f"{i}.", cap)

    _draw(_wrap_outer(
        _title_panel("REMOVE CAPABILITY"),
        Panel(table, border_style="purple", box=ROUNDED, padding=(1, 1)),
        _input_box(),
    ))
    console.print()
    idx = console.input("[bold cyan]>[/bold cyan] Select a number "
                        "[grey62](Enter to cancel)[/grey62]: ").strip()
    if idx.isdigit():
        idx = int(idx) - 1
        if 0 <= idx < len(enabled_caps):
            cap = enabled_caps.pop(idx)
            custom_paths.pop(cap, None)
            capability_layers.pop(cap, None)
            capability_sources.pop(cap, None)
            console.print(f"[green]Removed '{cap}'.[/green]")
    return enabled_caps, custom_paths, capability_layers, capability_sources


def _modify_path_flow(enabled_caps, custom_paths, capability_sources):
    if not enabled_caps:
        _draw(_wrap_outer(
            _title_panel("MODIFY PATH"),
            Panel("[yellow]No capabilities to modify.[/yellow]",
                  border_style="yellow", box=ROUNDED, padding=(1, 1)),
            _input_box(),
        ))
        _pause()
        return custom_paths, capability_sources

    table = Table.grid(expand=True, padding=(0, 1))
    table.add_column(justify="right", width=3, style="bold cyan")
    table.add_column(width=14, style="white")
    table.add_column(style="grey62")
    for i, cap in enumerate(enabled_caps, 1):
        table.add_row(f"{i}.", cap, custom_paths.get(cap, "unknown"))

    _draw(_wrap_outer(
        _title_panel("MODIFY PATH"),
        Panel(table, border_style="purple", box=ROUNDED, padding=(1, 1)),
        _input_box(),
    ))
    console.print()
    idx = console.input("[bold cyan]>[/bold cyan] Select a number "
                        "[grey62](Enter to cancel)[/grey62]: ").strip()
    if idx.isdigit():
        idx = int(idx) - 1
        if 0 <= idx < len(enabled_caps):
            cap = enabled_caps[idx]

            # os_primitive_config — re-run the corresponding pre-check
            # when the operator selects defender or firewall.
            if cap == "defender":
                chk = OsPrimitivePreconditionChecks.check_defender_capabilities()
                if chk.get("status") == "ready":
                    det = chk.get("details") or {}
                    channel = det.get("channel", "")
                    if channel:
                        custom_paths[cap] = f"Windows Event Log ({channel})"
                    capability_sources[cap] = {
                        "type": "eventlog",
                        "event_ids": list(det.get("event_ids", [])),
                    }
                    console.print(f"[green]Defender check passed.[/green]")
                else:
                    err = (chk.get("details") or {}).get("error", "unknown")
                    console.print(f"[red]Defender check failed: {err}[/red]")
                return custom_paths, capability_sources

            if cap == "firewall":
                chk = OsPrimitivePreconditionChecks.check_firewall_capabilities()
                if chk.get("status") == "ready":
                    det = chk.get("details") or {}
                    custom_paths[cap] = det.get("path", custom_paths.get(cap))
                    capability_sources[cap] = {
                        "type": "file",
                        "patterns": list(det.get("patterns", [])),
                    }
                    console.print(f"[green]Firewall check passed.[/green]")
                else:
                    det = chk.get("details") or {}
                    err = det.get("error") or det.get("info", "unknown")
                    console.print(f"[red]Firewall check failed: {err}[/red]")
                return custom_paths, capability_sources

            console.print(f"[cyan]New path for {cap}:[/cyan] ", end="")
            new_path = console.input("").strip()
            if new_path:
                if new_path.startswith("Windows Event Log ("):
                    custom_paths[cap] = new_path
                    entry = capability_sources.get(cap) or {}
                    entry["type"] = "eventlog"
                    capability_sources[cap] = entry
                    console.print(f"[green]Path updated for {cap}.[/green]")
                else:
                    canonical = os.path.realpath(new_path)
                    if (os.path.exists(canonical) and os.access(canonical, os.R_OK)
                            and os.path.isfile(canonical)):
                        valid, msg = validate_log_file(canonical)
                        if valid:
                            custom_paths[cap] = canonical
                            entry = capability_sources.get(cap) or {}
                            entry["type"] = "file"
                            capability_sources[cap] = entry
                            console.print(f"[green]Path updated for {cap}.[/green]")
                        else:
                            console.print(f"[red]Invalid log file: {msg}[/red]")
                    else:
                        console.print("[red]Path does not exist, not readable, or not a file.[/red]")
    return custom_paths, capability_sources


def _review_flow(discovered, enabled_caps, custom_paths, capability_layers):
    body = Text()
    body.append("\n  ENABLED CAPABILITIES\n", style="bold blue")
    if not enabled_caps:
        body.append("     (none)\n", style="grey42")
    else:
        for cap in enabled_caps:
            path = custom_paths.get(cap, "")
            body.append(f"     ✓ {cap}", style="bold white")
            if path:
                body.append(f"   ({path})", style="grey62")
            body.append("\n")

    body.append("\n  LAYER ASSIGNMENTS\n", style="bold blue")
    for layer_id in ALL_LAYERS_ORDER:
        caps_here = [cap for cap in enabled_caps
                     if layer_id in capability_layers.get(cap, [])]
        caps_str = ", ".join(caps_here) if caps_here else "(none)"
        style = "green" if caps_here else "grey42"
        body.append(f"     {layer_id:8} ", style="grey62")
        body.append(f"{caps_str}\n", style=style)

    _draw(_wrap_outer(
        _title_panel("CONFIGURATION SUMMARY"),
        Panel(body, border_style="blue", box=ROUNDED, padding=(1, 1)),
        _input_box(),
    ))
    _pause()


# ----------------------------------------------------------------------
# PERSISTENCE & BLACKBOARD
# ----------------------------------------------------------------------
def audit_log(message):
    try:
        with open(LOG_FILE, "a") as f:
            user = getpass.getuser()
            f.write(f"[CONFIG] {time.ctime()} | User: {user} | {message}\n")
    except Exception:
        pass


def safe_write_config(config_data, target_file):
    tmp_file = target_file + ".tmp"
    try:
        with open(tmp_file, "w") as f:
            json.dump(config_data, f, indent=2)
        if os.path.exists(target_file):
            backup_file = target_file + ".backup"
            os.replace(target_file, backup_file)
        os.replace(tmp_file, target_file)
        return True, None
    except Exception as e:
        if os.path.exists(tmp_file):
            try:
                os.remove(tmp_file)
            except Exception:
                pass
        return False, str(e)


def _merge_capability_rules(existing, capability_layers=None):
    """
    Preserve everything the operator has written under
    capability_rules.<cap> in system_config.json. Overwrite only the
    sensor sub-key, which this setup flow owns.

    SSH: the response engine (layer4a) reads
    capability_rules.ssh.service_ports to know which ports to block,
    and the MTD traffic_shuffle action (layer4c) reads
    capability_rules.ssh.shuffle for its port pair and trigger
    thresholds. Both keys are hard-coded requirements of those
    layers. When absent, write framework defaults so a fresh
    config_interactive run produces a working pipeline without
    external editing. When present, preserve the operator's values.
    """
    rules = dict(existing) if isinstance(existing, dict) else {}
    rules["sensor"] = {
        "watch_paths": [
            "C:\\Windows\\System32\\drivers\\etc",
            "C:\\ProgramData\\ssh",
        ],
        "thresholds": {
            "cpu_spike": 70,
            "cpu_multiplier": 1.5,
            "memory_spike": 80,
            "memory_multiplier": 1.5,
        },
    }

    ssh_rules = rules.get("ssh")
    if not isinstance(ssh_rules, dict):
        ssh_rules = {}

    if "service_ports" not in ssh_rules:
        ssh_rules["service_ports"] = [22]

    if "shuffle" not in ssh_rules:
        layer4c_selected = (
            isinstance(capability_layers, dict)
            and "ssh" in capability_layers
            and isinstance(capability_layers["ssh"], list)
            and "layer4c" in capability_layers["ssh"]
        )
        ssh_rules["shuffle"] = {
            "enabled": layer4c_selected,
            "primary_port": 22,
            "alternate_port": 2222,
            "trigger_distinct_attackers": 3,
            "trigger_red_seconds": 300,
            "restore_after_seconds": 1800,
        }

    rules["ssh"] = ssh_rules
    return rules


def save_config(enabled_caps, capability_layers, custom_paths,
                 capability_sources, capability_rules):
    service_map = Config.SERVICE_MAP
    enabled_dict = {}
    for cap in service_map.keys():
        enabled_dict[cap] = cap in enabled_caps
    custom_enabled = {}
    for cap in enabled_caps:
        if cap not in service_map:
            custom_enabled[cap] = True
    enabled_dict["custom"] = custom_enabled

    paths_dict = {}
    custom_paths_sub = {}
    for cap, path in custom_paths.items():
        if cap in service_map:
            paths_dict[cap] = path
        else:
            custom_paths_sub[cap] = path
    paths_dict["custom"] = custom_paths_sub

    # capability_sources is flat: reader reads sources.get(name)
    # for every capability name, service-map or custom.
    sources_dict = {}
    for cap, src in capability_sources.items():
        if isinstance(src, dict) and src:
            sources_dict[cap] = src

    layers_summary = {
        L: any(L in caps for caps in capability_layers.values())
        for L in ALL_LAYERS_ORDER
    }

    log_caps = [c for c in enabled_caps if c != "sensor"]
    layers_summary["reader"] = bool(log_caps)

    config_data = {
        "version": "1.0",
        "enabled_capabilities": enabled_dict,
        "capability_paths": paths_dict,
        "capability_sources": sources_dict,
        "capability_layers": capability_layers,
        "layers": layers_summary,
        "risk_thresholds": {
            "GREEN_TO_YELLOW": 65, "YELLOW_TO_ORANGE": 80, "ORANGE_TO_RED": 90,
            "RED_TO_ORANGE": 80, "ORANGE_TO_YELLOW": 60, "YELLOW_TO_GREEN": 40,
        },
        "sensor_intervals": {"GREEN": 30, "YELLOW": 15, "ORANGE": 5, "RED": 2},
        "app_intervals": {"GREEN": 30, "YELLOW": 15, "ORANGE": 5, "RED": 3},
        # capability_rules preserves operator-authored sub-keys
        # (fail2ban, shuffle, ...) across saves. Only the sensor
        # sub-key is owned and rewritten by this flow.
        "capability_rules": _merge_capability_rules(capability_rules, capability_layers),
    }

    if os.path.exists(SYSTEM_CONFIG_FILE):
        _draw(_wrap_outer(
            _title_panel("SAVE CONFIGURATION"),
            Panel(f"[yellow]{SYSTEM_CONFIG_FILE} already exists. Overwrite?[/yellow]",
                  border_style="yellow", box=ROUNDED, padding=(1, 1)),
            _input_box(),
        ))
        console.print()
        confirm = console.input("[bold cyan]>[/bold cyan] (y/N): ").strip().lower()
        if confirm != 'y':
            console.print("[yellow]Configuration unchanged. Exiting.[/yellow]")
            sys.exit(0)

    success, error = safe_write_config(config_data, SYSTEM_CONFIG_FILE)
    if not success:
        console.print(f"[red]Failed to save configuration: {error}[/red]")
        sys.exit(1)
    console.print(f"[green]Configuration saved to {SYSTEM_CONFIG_FILE}[/green]")
    audit_log(f"Configuration updated. Enabled: {enabled_caps}. Layers: {layers_summary}")


def build_blackboard(enabled_caps):
    data = BlackboardSchema.get_initial_blackboard()
    all_caps = ["ssh", "sensor", "app_http", "app_smtp", "app_ftp", "app_mysql"]
    all_caps = list(set(all_caps + list(enabled_caps)))
    disabled = {cap: ["*"] for cap in all_caps if cap not in enabled_caps}
    data["disabled_capabilities"] = disabled
    data["timestamp"] = time.time()

    data.pop("layer_1_monitor", None)
    data.pop("layer_1_app_monitor", None)
    data.pop("layer_2_ais", None)
    data.pop("layer_3_state", None)
    data.pop("layer_4a_response", None)
    data.pop("layer_4c_mtd", None)

    for cap in all_caps:
        if cap == "sensor":
            if "layer_1_sensor_ext" not in data:
                data["layer_1_sensor_ext"] = {
                    "active_connections": 0,
                    "unknown_connection_count": 0,
                    "process_count": 0,
                    "new_process_count": 0,
                    "file_change_count": 0,
                    "cpu_percent": 0.0,
                    "memory_percent": 0.0,
                    "load_avg_1min": 0.0,
                    "cpu_spike_detected": False,
                    "memory_spike_detected": False,
                    "sensor_healthy": False,
                    "sensor_timestamp": 0.0,
                    "method": "pending",
                    "source": "service_sensor",
                    "version": Config.SCHEMA_VERSION,
                }
        else:
            data[f"layer_1_monitor_{cap}"] = {
                "last_failures": 0,
                "last_attacker_ip": "0.0.0.0",
                "monitoring_timestamp": 0.0,
                "monitor_healthy": False,
                "log_source": "unknown",
                "source": f"service_monitor_{cap}",
                "version": Config.SCHEMA_VERSION,
            }

        data[f"layer_2_ais_{cap}"] = {
            "source": cap,
            "ais_timestamp": 0.0,
            "ais_healthy": False,
            "risk": 0,
            "attacker_ip": "0.0.0.0",
            "baseline": 0.5,
            "known_threats": [],
            "detail": {},
            "version": Config.SCHEMA_VERSION,
        }
        data[f"layer_3_state_{cap}"] = {
            "source": cap,
            "state_timestamp": 0.0,
            "state_healthy": False,
            "state": "GREEN",
            "previous_state": "GREEN",
            "risk_input": 0,
            "detail": {},
            "version": Config.SCHEMA_VERSION,
        }
        data[f"layer_4a_response_{cap}"] = {
            "blocked_ips": [], "last_block": "", "block_timestamp": 0.0,
            "method": "unknown", "source": f"service_response_{cap}",
            "version": Config.SCHEMA_VERSION,
        }

    if "ssh" in all_caps:
        data["layer_4c_mtd_ssh"] = {
            "port": 22, "port_timestamp": 0.0, "config_level": "low",
            "source": "service_mtd", "version": Config.SCHEMA_VERSION,
        }

    try:
        os.makedirs(os.path.dirname(BLACKBOARD_FILE), exist_ok=True)
        with open(BLACKBOARD_FILE, "w") as f:
            json.dump(data, f, indent=2)
    except PermissionError:
        console.print(f"[red]Failed to write Blackboard: Permission denied to {BLACKBOARD_FILE}[/red]")
        sys.exit(1)
    except Exception as e:
        console.print(f"[red]Failed to write Blackboard: {e}[/red]")
        sys.exit(1)
    console.print(f"[green]Full Blackboard created at {BLACKBOARD_FILE}[/green]")


def run_pre_flight_validation(enabled_caps, custom_paths):
    config = {"capability_paths": custom_paths}
    failed = []
    console.print("\n[bold cyan][VALIDATOR][/bold cyan] Checking pre-flight conditions...")
    for cap in enabled_caps:
        ok, reason = pre_flight_check(cap, config)
        if not ok:
            failed.append((cap, reason))
            console.print(f"   [red]✕ {cap}: {reason}[/red]")
        else:
            console.print(f"   [green]✓ {cap}: {reason}[/green]")

    if not failed:
        return enabled_caps

    console.print("\n[yellow]The following enabled capabilities failed pre-flight:[/yellow]")
    for cap, reason in failed:
        console.print(f"   [red]- {cap}: {reason}[/red]")

    while True:
        console.print("\n[bold cyan]>[/bold cyan] Enter 'd' to disable them or 'a' to abort: ", end="")
        choice = console.input("").strip().lower()
        if choice == 'd':
            for cap, _ in failed:
                if cap in enabled_caps:
                    enabled_caps.remove(cap)
                    console.print(f"   [yellow]Disabled: {cap}[/yellow]")
            audit_log(f"Pre-flight failures: {[cap for cap, _ in failed]}. Disabled by user choice.")
            break
        elif choice == 'a':
            console.print("[red]Setup aborted by user.[/red]")
            audit_log("Setup aborted by user during pre-flight validation.")
            sys.exit(0)
    return enabled_caps


# ----------------------------------------------------------------------
# MAIN
# ----------------------------------------------------------------------
def interactive_setup():
    if not check_locking_available():
        console.print("[yellow]Warning: file locking is not available.[/yellow]")
    if os.name == 'nt' and not check_admin():
        console.print("[yellow]Warning: not running as Administrator. "
                      "Sensor may not work.[/yellow]")

    discovered = discover_capabilities()
    items = list(discovered.keys())

    existing_enabled, existing_paths, existing_layers, existing_sources, \
        existing_rules = load_existing_config()
    config_exists = (bool(existing_enabled) or bool(existing_paths)
                     or bool(existing_layers))
    enabled_caps = existing_enabled.copy() if config_exists else []
    custom_paths = existing_paths.copy() if config_exists else {}
    capability_layers = existing_layers.copy() if config_exists else {}
    capability_sources = existing_sources.copy() if config_exists else {}
    capability_rules = existing_rules.copy() if config_exists else {}

    while True:
        _draw(_main_screen(discovered, enabled_caps, capability_layers))
        choice = _read()

        if choice == 'a':
            discovered, items, enabled_caps, custom_paths, capability_sources = \
                _add_capability_flow(discovered, items, enabled_caps,
                                      custom_paths, capability_sources)

        elif choice == 'r':
            enabled_caps, custom_paths, capability_layers, capability_sources = \
                _remove_capability_flow(enabled_caps, custom_paths,
                                         capability_layers, capability_sources)

        elif choice == 'm':
            custom_paths, capability_sources = _modify_path_flow(
                enabled_caps, custom_paths, capability_sources)

        elif choice == 'v':
            _review_flow(discovered, enabled_caps, custom_paths, capability_layers)

        elif choice == 'l':
            before = {cap: list(caps) for cap, caps in capability_layers.items() if caps}
            capability_layers = run_layer_selection(console, enabled_caps, capability_layers)
            capability_layers = {cap: caps for cap, caps in capability_layers.items() if caps}
            if capability_layers != before:
                console.print("[green]layers updated[/green]")

        elif choice == 's':
            unassigned = [cap for cap in enabled_caps
                          if not capability_layers.get(cap)]
            if unassigned:
                _draw(_wrap_outer(
                    _title_panel("SAVE CONFIGURATION"),
                    Panel(
                        Text.from_markup(
                            "[yellow]The following capabilities have no layers assigned:[/yellow]\n"
                            + "\n".join(f"   - {cap}" for cap in unassigned)
                            + "\n\n[yellow]They will be configured but will not run.[/yellow]"
                        ),
                        border_style="yellow", box=ROUNDED, padding=(1, 1),
                    ),
                    _input_box(),
                ))
                console.print()
                ans = console.input("[bold cyan]>[/bold cyan] Continue? (y/n): ").strip().lower()
                if ans != 'y':
                    continue

            valid, warnings = validate_layer_dependencies(enabled_caps, capability_layers)
            if not valid:
                _draw(_wrap_outer(
                    _title_panel("SAVE CONFIGURATION"),
                    Panel(
                        Text.from_markup(
                            "[yellow]Layer dependency warnings:[/yellow]\n"
                            + "\n".join(f"   - {w}" for w in warnings)
                        ),
                        border_style="yellow", box=ROUNDED, padding=(1, 1),
                    ),
                    _input_box(),
                ))
                console.print()
                ans = console.input("[bold cyan]>[/bold cyan] Proceed anyway? (y/n): ").strip().lower()
                if ans != 'y':
                    continue

            _review_flow(discovered, enabled_caps, custom_paths, capability_layers)
            _draw(_wrap_outer(
                _title_panel("SAVE CONFIGURATION"),
                Panel("[yellow]Save this configuration and launch orchestrator?[/yellow]",
                      border_style="yellow", box=ROUNDED, padding=(1, 1)),
                _input_box(),
            ))
            console.print()
            ans = console.input("[bold cyan]>[/bold cyan] (y/n): ").strip().lower()
            if ans == 'y':
                break

        elif choice == 'q':
            _draw(_wrap_outer(
                _title_panel("QUIT"),
                Panel("[yellow]Quit without saving?[/yellow]",
                      border_style="yellow", box=ROUNDED, padding=(1, 1)),
                _input_box(),
            ))
            console.print()
            ans = console.input("[bold cyan]>[/bold cyan] (y/n): ").strip().lower()
            if ans == 'y':
                console.print("[yellow]Exiting without saving.[/yellow]")
                sys.exit(0)

    enabled_caps = run_pre_flight_validation(enabled_caps, custom_paths)
    capability_layers = {cap: layers for cap, layers in capability_layers.items()
                         if cap in enabled_caps}

    save_config(enabled_caps, capability_layers, custom_paths,
                 capability_sources, capability_rules)
    build_blackboard(enabled_caps)

    console.print("\n[green]Setup complete. Launching orchestrator...[/green]")
    try:
        proc = subprocess.Popen([PYTHON_CMD, "orchestrator.py"])
    except FileNotFoundError:
        console.print(f"[red]Error: '{PYTHON_CMD}' not found, or orchestrator.py is missing.[/red]")
        sys.exit(1)
    except OSError as e:
        console.print(f"[red]Error launching orchestrator: {e}[/red]")
        sys.exit(1)
    try:
        proc.wait()
    except KeyboardInterrupt:
        proc.wait()
    sys.exit(proc.returncode)


if __name__ == "__main__":
    interactive_setup()