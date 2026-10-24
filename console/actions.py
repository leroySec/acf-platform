# console/actions.py
# ============================================================================
# CONSOLE ACTIONS — Bridge between the console and the rest of the ACF
# ============================================================================
# The only file in the console that touches the outside world.
#
# Every public action returns (success: bool, message: str).
# Actions never raise; they return an error instead.
#
# FIXES APPLIED (round 1):
#   1. Backward-compat schema migration (flat -> nested custom)
#   2. Cross-process file lock around config read-modify-write
#   3. Same-process lock for the layer command channel
#   4. Path validation via the shared validate_log_file
#   5. Symlink resolution via os.path.realpath
#   6. Honest success reporting for toggle_layer_display
#   7. Audit logging for every capability and layer change
#   8. Configurable layer-command timeout via env var
#   9. Uses console_state.LAYER_IDS for display reset
#  10. Removed unused imports
#
# FIXES APPLIED (round 2):
#   A. Cross-process lock for the layer command channel
#   B. Remove our own command file on timeout
#   C. Audited user included in every audit line
#   D. ISO 8601 timestamps in audit entries
#   E. Removed the unused List import
#
# UPDATED (layer dimension):
#   - enable_capability / disable_capability write the dict shape of
#     disabled_capabilities: {capability: [layers]} with "*" meaning all.
#   - change_capability_path stops every layer's process for the capability
#     before allowing the reconciler to restart them.
#   - reload_all stops every pair via stop_all_services before reconciling.
# ============================================================================

import os
import json
import time
import uuid
import threading
import contextlib
import getpass
from typing import Tuple, Optional, Dict, Any

from config import Config
from platform_utils import acquire_lock, release_lock, get_temp_dir
from . import state as console_state


# ----------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------
SYSTEM_CONFIG_FILE = "system_config.json"
LAYER_COMMAND_FILE = Config.LAYER_COMMAND_FILE
LAYER_RESULT_FILE = Config.LAYER_RESULT_FILE
LAYER_STATE_FILE = Config.LAYER_STATE_FILE

LAYER_COMMAND_TIMEOUT = float(os.environ.get("ACF_LAYER_TIMEOUT", "8.0"))
LAYER_COMMAND_POLL = 0.2

# Intra-process lock for the layer command channel
_layer_command_lock = threading.Lock()

# Cross-process lock files
_CONFIG_LOCK_FILE = os.path.join(get_temp_dir(), "acf_system_config.lock")
_LAYER_COMMAND_LOCK_FILE = os.path.join(get_temp_dir(), "acf_layer_command.lock")


# ----------------------------------------------------------------------
# Lazy accessors
# ----------------------------------------------------------------------
def _get_orchestrator():
    try:
        import orchestrator
        return orchestrator
    except Exception:
        return None


def _get_validator():
    try:
        from config_interactive import validate_log_file
        return validate_log_file
    except Exception:
        return None


# ----------------------------------------------------------------------
# Path validation
# ----------------------------------------------------------------------
def _validate_path(path: str) -> Tuple[bool, str]:
    if not isinstance(path, str) or not path:
        return False, "Invalid path"
    if not os.path.exists(path):
        return False, f"Path does not exist: {path}"
    if not os.path.isfile(path):
        return False, f"Not a regular file: {path}"
    if not os.access(path, os.R_OK):
        return False, f"Path is not readable: {path}"

    validator = _get_validator()
    if validator is not None:
        try:
            ok, reason = validator(path)
            if not ok:
                return False, f"Invalid log file: {reason}"
        except Exception:
            pass

    return True, "OK"


# ----------------------------------------------------------------------
# Config helpers
# ----------------------------------------------------------------------
def _load_config() -> Dict[str, Any]:
    try:
        with open(SYSTEM_CONFIG_FILE, "r") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        return data
    except Exception:
        return {}


def _save_config(config: Dict[str, Any]) -> bool:
    try:
        tmp_file = SYSTEM_CONFIG_FILE + ".tmp"
        with open(tmp_file, "w") as f:
            json.dump(config, f, indent=2)
        os.replace(tmp_file, SYSTEM_CONFIG_FILE)
        return True
    except Exception:
        return False


def _normalize_config(config: Dict[str, Any]):
    if not isinstance(config, dict):
        return

    service_map = Config.SERVICE_MAP

    for section in ("enabled_capabilities", "capability_paths"):
        if section not in config or not isinstance(config[section], dict):
            config[section] = {}
        sub = config[section].get("custom")
        if not isinstance(sub, dict):
            sub = {}
            config[section]["custom"] = sub

        flat_keys = [k for k in list(config[section].keys())
                     if k != "custom" and k not in service_map]
        for k in flat_keys:
            sub[k] = config[section].pop(k)


@contextlib.contextmanager
def _config_locked():
    os.makedirs(os.path.dirname(_CONFIG_LOCK_FILE), exist_ok=True)
    lf = open(_CONFIG_LOCK_FILE, "a+")
    try:
        acquire_lock(lf.fileno(), exclusive=True)
        try:
            yield
        finally:
            try:
                release_lock(lf.fileno())
            except Exception:
                pass
    finally:
        lf.close()


@contextlib.contextmanager
def _layer_command_locked():
    """Cross-process lock for the layer command channel."""
    os.makedirs(os.path.dirname(_LAYER_COMMAND_LOCK_FILE), exist_ok=True)
    lf = open(_LAYER_COMMAND_LOCK_FILE, "a+")
    try:
        acquire_lock(lf.fileno(), exclusive=True)
        try:
            yield
        finally:
            try:
                release_lock(lf.fileno())
            except Exception:
                pass
    finally:
        lf.close()


# ----------------------------------------------------------------------
# Audit logging
# ----------------------------------------------------------------------
def _audit(message: str):
    """Write an audit line with the current user and ISO timestamp."""
    try:
        user = getpass.getuser()
    except Exception:
        user = "unknown"
    ts = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime())

    orch = _get_orchestrator()
    if orch is not None and hasattr(orch, "audit_log"):
        try:
            orch.audit_log(f"User: {user} | {message}")
            return
        except Exception:
            pass

    try:
        with open(Config.LOG_FILE, "a") as f:
            f.write(f"[CONSOLE] {ts} | User: {user} | {message}\n")
    except Exception:
        pass


# ----------------------------------------------------------------------
# Layer command helper
# ----------------------------------------------------------------------
def _remove_own_command_file(command_id: str):
    """Remove the command file only if it still contains our command."""
    try:
        if not os.path.exists(LAYER_COMMAND_FILE):
            return
        with open(LAYER_COMMAND_FILE, "r") as f:
            current = json.load(f)
        if isinstance(current, dict) and current.get("id") == command_id:
            os.remove(LAYER_COMMAND_FILE)
    except Exception:
        pass


def _send_layer_command(command: str, layer: str = "") -> Tuple[bool, str]:
    """
    Send a command to the layer manager and wait for its result.
    Serialized within the process and across processes.
    """
    with _layer_command_lock:
        with _layer_command_locked():
            command_id = f"cmd-{int(time.time())}-{uuid.uuid4().hex[:6]}"

            payload = {
                "id": command_id,
                "command": command,
                "layer": layer,
                "timestamp": time.time(),
            }

            try:
                if os.path.exists(LAYER_RESULT_FILE):
                    os.remove(LAYER_RESULT_FILE)
            except Exception:
                pass

            try:
                os.makedirs(os.path.dirname(LAYER_COMMAND_FILE), exist_ok=True)
                tmp_file = LAYER_COMMAND_FILE + ".tmp"
                with open(tmp_file, "w") as f:
                    json.dump(payload, f, indent=2)
                os.replace(tmp_file, LAYER_COMMAND_FILE)
            except Exception as e:
                return False, f"Failed to write command file: {e}"

            deadline = time.time() + LAYER_COMMAND_TIMEOUT
            while time.time() < deadline:
                try:
                    if os.path.exists(LAYER_RESULT_FILE):
                        with open(LAYER_RESULT_FILE, "r") as f:
                            result = json.load(f)
                        if isinstance(result, dict) and result.get("id") == command_id:
                            try:
                                os.remove(LAYER_RESULT_FILE)
                            except Exception:
                                pass
                            status = result.get("status", "")
                            message = result.get("message", "")
                            return (status == "ok"), message
                except Exception:
                    pass
                time.sleep(LAYER_COMMAND_POLL)

            # Timeout: remove our own command file if still present
            _remove_own_command_file(command_id)
            return False, "Layer manager did not respond in time"


# ----------------------------------------------------------------------
# Capability actions
# ----------------------------------------------------------------------
def enable_capability(name: str) -> Tuple[bool, str]:
    if not isinstance(name, str) or not name:
        return False, "Invalid capability name"
    if name not in Config.SERVICE_MAP:
        return False, f"'{name}' is not a hardcoded capability"

    try:
        with _config_locked():
            config = _load_config()
            _normalize_config(config)
            if config["enabled_capabilities"].get(name) is True:
                return True, f"{name} is already enabled"
            config["enabled_capabilities"][name] = True
            if not _save_config(config):
                return False, "Failed to save config"
    except Exception as e:
        return False, f"Config lock failed: {e}"

    orch = _get_orchestrator()
    if orch is not None:
        try:
            # Remove the capability's entry from the disabled dict entirely —
            # this re-enables every layer of the capability.
            disabled = orch.get_disabled_caps()
            if name in disabled:
                del disabled[name]
                orch.write_blackboard_disabled(disabled)
            orch.sync_services()
        except Exception as e:
            return False, f"Config saved, but orchestrator call failed: {e}"

    _audit(f"Enabled capability: {name}")
    return True, f"{name} enabled"


def disable_capability(name: str) -> Tuple[bool, str]:
    if not isinstance(name, str) or not name:
        return False, "Invalid capability name"
    if name not in Config.SERVICE_MAP:
        return False, f"'{name}' is not a hardcoded capability"

    try:
        with _config_locked():
            config = _load_config()
            _normalize_config(config)
            if config["enabled_capabilities"].get(name) is False:
                return True, f"{name} is already disabled"
            config["enabled_capabilities"][name] = False
            if not _save_config(config):
                return False, "Failed to save config"
    except Exception as e:
        return False, f"Config lock failed: {e}"

    orch = _get_orchestrator()
    if orch is not None:
        try:
            # Write the capability as disabled for all its layers ("*").
            # The orchestrator's reconciler stops every pair of this capability.
            disabled = orch.get_disabled_caps()
            disabled[name] = ["*"]
            orch.write_blackboard_disabled(disabled)
            orch.sync_services()
        except Exception as e:
            return False, f"Config saved, but orchestrator call failed: {e}"

    _audit(f"Disabled capability: {name}")
    return True, f"{name} disabled"


def change_capability_path(name: str, new_path: str) -> Tuple[bool, str]:
    if not isinstance(name, str) or not name:
        return False, "Invalid capability name"
    if not isinstance(new_path, str) or not new_path:
        return False, "Invalid path"

    canonical = os.path.realpath(new_path)
    ok, reason = _validate_path(canonical)
    if not ok:
        return False, reason

    is_custom = name not in Config.SERVICE_MAP

    try:
        with _config_locked():
            config = _load_config()
            _normalize_config(config)
            if is_custom:
                config["capability_paths"]["custom"][name] = canonical
            else:
                config["capability_paths"][name] = canonical
            if not _save_config(config):
                return False, "Failed to save config"
    except Exception as e:
        return False, f"Config lock failed: {e}"

    if is_custom:
        ok, msg = _send_layer_command("restart", "layer1")
        if not ok:
            return False, f"Path saved, but monitor engine restart failed: {msg}"
    else:
        orch = _get_orchestrator()
        if orch is not None:
            try:
                # Stop every layer's process for this capability so the
                # reconciler restarts them with the new path.
                layer_map = orch.SERVICE_MAP.get(name, {})
                if isinstance(layer_map, dict):
                    for layer in list(layer_map.keys()):
                        try:
                            orch.stop_service(name, layer)
                        except Exception:
                            pass
                orch.sync_services()
            except Exception as e:
                return False, f"Path saved, but service restart failed: {e}"

    _audit(f"Changed path for {name}: {canonical}")
    return True, f"Path updated for {name}"


# ----------------------------------------------------------------------
# Custom log actions
# ----------------------------------------------------------------------
def add_custom_log(name: str, path: str) -> Tuple[bool, str]:
    if not isinstance(name, str) or not name:
        return False, "Invalid name"
    if not isinstance(path, str) or not path:
        return False, "Invalid path"
    if name in Config.SERVICE_MAP:
        return False, f"'{name}' conflicts with a hardcoded capability"

    canonical = os.path.realpath(path)
    ok, reason = _validate_path(canonical)
    if not ok:
        return False, reason

    try:
        with _config_locked():
            config = _load_config()
            _normalize_config(config)
            if name in config["enabled_capabilities"]["custom"]:
                return False, f"Custom log '{name}' already exists"

            # Warn if this path is already registered under another name
            for existing_name, existing_path in config["capability_paths"]["custom"].items():
                if existing_name != name and existing_path == canonical:
                    return False, f"Path already registered as '{existing_name}'"

            config["enabled_capabilities"]["custom"][name] = True
            config["capability_paths"]["custom"][name] = canonical
            if not _save_config(config):
                return False, "Failed to save config"
    except Exception as e:
        return False, f"Config lock failed: {e}"

    _audit(f"Added custom log: {name} -> {canonical}")
    return True, f"Custom log '{name}' added. Restart Layer 1 to begin monitoring."


def remove_custom_log(name: str) -> Tuple[bool, str]:
    if not isinstance(name, str) or not name:
        return False, "Invalid name"
    if name in Config.SERVICE_MAP:
        return False, f"'{name}' is a hardcoded capability, not a custom log"

    removed = False
    try:
        with _config_locked():
            config = _load_config()
            _normalize_config(config)
            if name in config["enabled_capabilities"]["custom"]:
                del config["enabled_capabilities"]["custom"][name]
                removed = True
            if name in config["capability_paths"]["custom"]:
                del config["capability_paths"]["custom"][name]
                removed = True
            if not removed:
                return False, f"Custom log '{name}' not found"
            if not _save_config(config):
                return False, "Failed to save config"
    except Exception as e:
        return False, f"Config lock failed: {e}"

    _audit(f"Removed custom log: {name}")
    return True, f"Custom log '{name}' removed. Restart Layer 1 to apply."


# ----------------------------------------------------------------------
# Layer actions
# ----------------------------------------------------------------------
def enable_layer(layer_id: str) -> Tuple[bool, str]:
    if not isinstance(layer_id, str) or not layer_id:
        return False, "Invalid layer id"
    ok, msg = _send_layer_command("enable", layer_id)
    if ok:
        _audit(f"Enabled layer: {layer_id}")
    return ok, msg


def disable_layer(layer_id: str) -> Tuple[bool, str]:
    if not isinstance(layer_id, str) or not layer_id:
        return False, "Invalid layer id"
    ok, msg = _send_layer_command("disable", layer_id)
    if ok:
        _audit(f"Disabled layer: {layer_id}")
    return ok, msg


def restart_layer(layer_id: str) -> Tuple[bool, str]:
    if not isinstance(layer_id, str) or not layer_id:
        return False, "Invalid layer id"
    ok, msg = _send_layer_command("restart", layer_id)
    if ok:
        _audit(f"Restarted layer: {layer_id}")
    return ok, msg


def restart_all_layers() -> Tuple[bool, str]:
    ok, msg = _send_layer_command("restart_all", "")
    if ok:
        _audit("Restarted all layers")
    return ok, msg


def refresh_layer_state() -> Tuple[bool, str]:
    return _send_layer_command("status", "")


# ----------------------------------------------------------------------
# Display actions
# ----------------------------------------------------------------------
def toggle_layer_display(layer_id: str) -> Tuple[bool, str]:
    if not isinstance(layer_id, str) or not layer_id:
        return False, "Invalid layer id"
    if layer_id not in console_state.LAYER_IDS:
        return False, f"Unknown layer: {layer_id}"
    new_value = console_state.toggle_display(layer_id)
    return True, f"Layer {layer_id} display {'ON' if new_value else 'OFF'}"


def set_layer_display(layer_id: str, value: bool) -> Tuple[bool, str]:
    if not isinstance(layer_id, str) or not layer_id:
        return False, "Invalid layer id"
    if layer_id not in console_state.LAYER_IDS:
        return False, f"Unknown layer: {layer_id}"
    console_state.set_displayed(layer_id, value)
    return True, f"Layer {layer_id} display {'ON' if value else 'OFF'}"


def set_filter(source: Optional[str]) -> Tuple[bool, str]:
    if source is None or source == "":
        console_state.clear_filter()
        return True, "Filter cleared"
    console_state.set_filter(source)
    return True, f"Filter set to '{source}'"


def clear_filter() -> Tuple[bool, str]:
    console_state.clear_filter()
    return True, "Filter cleared"


def set_layout(mode: str) -> Tuple[bool, str]:
    if mode not in ("single", "side-by-side", "stacked"):
        return False, f"Invalid layout: {mode}"
    console_state.set_layout(mode)
    return True, f"Layout set to '{mode}'"


def reset_display() -> Tuple[bool, str]:
    console_state.set_layout("single")
    console_state.clear_filter()
    for layer in console_state.LAYER_IDS:
        console_state.set_displayed(layer, True)
    return True, "Display reset to defaults"


# ----------------------------------------------------------------------
# System actions
# ----------------------------------------------------------------------
def reload_config() -> Tuple[bool, str]:
    config = _load_config()
    if not config:
        return False, "Config file is missing or empty"

    orch = _get_orchestrator()
    if orch is not None:
        try:
            orch.sync_services()
        except Exception as e:
            return False, f"Config reloaded but sync failed: {e}"

    _audit("Reloaded configuration")
    return True, "Configuration reloaded"


def reload_all() -> Tuple[bool, str]:
    messages = []

    ok, msg = _send_layer_command("restart_all", "")
    messages.append(f"layers: {msg}")

    orch = _get_orchestrator()
    if orch is not None:
        try:
            # Stop every (capability, layer) pair, then let the reconciler
            # restart everything that should be running.
            orch.stop_all_services()
            orch.sync_services()
            messages.append("capabilities: restarted")
        except Exception as e:
            messages.append(f"capabilities: failed ({e})")

    _audit("Reloaded all layers and capabilities")
    return True, "; ".join(messages)


# ----------------------------------------------------------------------
# Read-only helpers
# ----------------------------------------------------------------------
def get_layer_snapshot() -> Dict[str, Any]:
    try:
        with open(LAYER_STATE_FILE, "r") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        return data
    except Exception:
        return {}


def get_blackboard() -> Dict[str, Any]:
    try:
        with open(Config.BLACKBOARD_FILE, "r") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            return {}
        return data
    except Exception:
        return {}


def get_capabilities() -> Dict[str, Any]:
    config = _load_config()
    caps = config.get("enabled_capabilities", {})
    if not isinstance(caps, dict):
        return {}
    return caps


def get_capability_paths() -> Dict[str, Any]:
    config = _load_config()
    paths = config.get("capability_paths", {})
    if not isinstance(paths, dict):
        return {}
    return paths


def get_capabilities_flat() -> Dict[str, bool]:
    caps = get_capabilities()
    flat: Dict[str, bool] = {}
    for k, v in caps.items():
        if k == "custom" and isinstance(v, dict):
            for kk, vv in v.items():
                flat[kk] = bool(vv)
        else:
            flat[k] = bool(v)
    return flat


def get_capability_paths_flat() -> Dict[str, str]:
    paths = get_capability_paths()
    flat: Dict[str, str] = {}
    for k, v in paths.items():
        if k == "custom" and isinstance(v, dict):
            for kk, vv in v.items():
                flat[kk] = vv
        else:
            flat[k] = v
    return flat