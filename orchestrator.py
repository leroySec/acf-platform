#!/usr/bin/env python3
# ============================================================================
# ORCHESTRATOR — Management and Monitoring Service
# ============================================================================
# - Starts enabled capabilities as subprocesses
# - Shows services' output via the event router
# - Uses a lock to prevent race conditions
# - Hosts the terminal console
#
# UPDATED:
#   - SERVICE_MAP is per-capability with layers inside each capability
#   - start_service / stop_service take a layer argument
#   - processes is keyed by (capability, layer) tuples
#   - sync_services reconciles per pair
#   - monitor_loop watches disabled_capabilities, enabled_capabilities, and layers
#   - disabled_capabilities is a dict {capability: [layers]} with "*" for all
#   - LAYER_SCRIPT_OVERRIDES maps specific (capability, layer) pairs to a
#     dedicated script when the layer's default engine is not appropriate
#   - Kill-on-close job object: every child spawned by this process is
#     assigned to a Windows job with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE.
#     When the orchestrator exits for any reason, the kernel kills every
#     child in the job. No signal has to be delivered. No cooperation
#     from the child is required.
#
# TRACE (temporary diagnostic):
#   _trace() routes through emit() at debug level. The console hides
#   debug by default. Use 'diag events all' to see the traces. Remove
#   the _trace calls once the diagnosis is complete.
# ============================================================================

import os
import sys
import json
import time
import subprocess
import signal
import atexit
import threading
from typing import Dict, List

from platform_utils import acquire_lock, release_lock
from config import Config
import process_tree

# ----------------------------------------------------------------------
# Phase 3: event system (with fallback if not installed)
# ----------------------------------------------------------------------
try:
    from event_router import start_router, stop_router
    from event_reader import start_reader, stop_reader
    from event_emit import emit as _emit_impl
    _EVENTS_AVAILABLE = True
except ImportError:
    _EVENTS_AVAILABLE = False

    def start_router():
        return None
    def stop_router():
        pass
    def start_reader(handler):
        pass
    def stop_reader():
        pass

    def _emit_impl(src, layer, level, msg):
        ts = time.strftime("%H:%M:%S")
        print(f"[{ts}][{src}][{layer}][{level.upper()}] {msg}")


# Shared lock for any raw console output.
_output_lock = threading.Lock()


def emit(src, layer, level, msg):
    """Emit an event. Falls back to tagged print if the router is unavailable."""
    with _output_lock:
        _emit_impl(src, layer, level, msg)


def _trace(msg):
    """
    Diagnostic trace. Routes through the event router at debug level
    so it never writes to the terminal directly. The console hides
    debug by default; use 'diag events all' to see these.
    """
    emit("orchestrator", "-", "debug", msg)


# ----------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------
SYSTEM_CONFIG_FILE = "system_config.json"
BLACKBOARD_FILE = Config.BLACKBOARD_FILE

SERVICE_MAP = Config.SERVICE_MAP
ENGINE_MAP = Config.ENGINE_MAP

# Capability-and-layer pairs that have their own dedicated script,
# overriding the default engine for that layer.
# sensor at layer1 reads system metrics; the monitor engine reads logs.
# They are different jobs, different files.
LAYER_SCRIPT_OVERRIDES = {
}

ALL_CAPS = list(SERVICE_MAP.keys())
processes = {}          # (capability_id, layer_id) -> subprocess.Popen
stop_monitor = False
sync_lock = threading.Lock()


# ----------------------------------------------------------------------
# Event print handler (used only if the console is unavailable)
# ----------------------------------------------------------------------
def _print_event(event: dict):
    with _output_lock:
        try:
            ts = time.strftime("%H:%M:%S",
                               time.localtime(event.get("ts", time.time())))
            src = event.get("src", "unknown")
            layer = event.get("layer", "-")
            level = event.get("level", "info").upper()
            msg = event.get("msg", "")
            print(f"[{ts}][{src}][{layer}][{level}] {msg}")
        except Exception:
            pass


# ----------------------------------------------------------------------
# Safe call helper
# ----------------------------------------------------------------------
def _safe_call(fn, *args, default=None, label=""):
    """Call fn(*args) and return its value, or default on failure."""
    try:
        return fn(*args)
    except Exception as e:
        emit("orchestrator", "-", "error",
             f"{label or 'step'} failed: {e}")
        return default


# ----------------------------------------------------------------------
# Signal handler
# ----------------------------------------------------------------------
def _shutdown_signal(sig, frame):
    """Stop services, stop layer-manager engines, stop the monitor."""
    global stop_monitor
    try:
       stop_all_services()
    except Exception:
       pass
    try:
      import layer_manager
      layer_manager.handle_shutdown()
      layer_manager.stop_all_engines()
    except Exception:
       pass 
    try:
       from console import state as _console_state
       _console_state.request_shutdown()
    except Exception:
       pass 


# ----------------------------------------------------------------------
# Config & Blackboard helpers
# ----------------------------------------------------------------------
def load_system_config():
    try:
        with open(SYSTEM_CONFIG_FILE, "r") as f:
            return json.load(f)
    except:
        return {}


def save_system_config(config):
    try:
        with open(SYSTEM_CONFIG_FILE, "w") as f:
            json.dump(config, f, indent=2)
        return True
    except:
        return False


def load_blackboard():
    try:
        with open(BLACKBOARD_FILE, "r") as f:
            return json.load(f)
    except:
        return {}


def write_blackboard_disabled(disabled_dict):
    """Write the disabled_capabilities dict {capability: [layers]}."""
    try:
        with open(BLACKBOARD_FILE, 'r+') as f:
            acquire_lock(f.fileno(), exclusive=True)
            data = json.load(f)
            data["disabled_capabilities"] = disabled_dict
            f.seek(0)
            json.dump(data, f, indent=2)
            f.truncate()
            release_lock(f.fileno())
        return True
    except:
        return False


def get_enabled_caps():
    """Return only discovered capabilities (flat keys)."""
    config = load_system_config()
    enabled_dict = config.get("enabled_capabilities", {})
    caps = []
    for cap, val in enabled_dict.items():
        if cap == "custom":
            continue
        if val:
            caps.append(cap)
    return caps


def get_disabled_caps():
    """
    Return the disabled_capabilities as a dict {capability: [layers]}.
    Backward-compatible with the old list-of-names format: a list entry
    is converted to {name: ["*"]}.
    """
    bb = load_blackboard()
    disabled = bb.get("disabled_capabilities", {})
    if isinstance(disabled, list):
        return {cap: ["*"] for cap in disabled}
    if not isinstance(disabled, dict):
        return {}
    return disabled


def get_enabled_layers():
    """Return the list of layer IDs enabled in system_config.json."""
    config = load_system_config()
    layers = config.get("layers", {})
    if not isinstance(layers, dict):
        return []
    return [lid for lid, on in layers.items() if on]


def _pair_disabled(disabled_dict, cap, layer):
    """
    Return True if the (capability, layer) pair is disabled.
    A pair is disabled if the capability is present and either "*" is in
    its list or the specific layer is in its list.
    """
    entry = disabled_dict.get(cap)
    if not entry:
        return False
    if not isinstance(entry, list):
        return False
    if "*" in entry:
        return True
    return layer in entry


# ----------------------------------------------------------------------
# Service management
# ----------------------------------------------------------------------
def start_service(cap_id, layer):
    _trace(f"[TRACE start] called for {cap_id}@{layer}")

    # Prune any dead processes first.
    for pair, p in list(processes.items()):
        if p.poll() is not None:
            del processes[pair]

    pair = (cap_id, layer)
    if pair in processes and processes[pair].poll() is None:
        _trace(f"[TRACE start] {cap_id}@{layer}: already alive")
        return

    # A specific override wins. Otherwise, the layer's default engine.
    override = LAYER_SCRIPT_OVERRIDES.get((cap_id, layer))
    if override:
        script = override
        argv = [sys.executable, script]
    else:
        script = ENGINE_MAP.get(layer)
        argv = [sys.executable, script, cap_id]

    _trace(f"[TRACE start] {cap_id}@{layer}: script={script!r}")
    _trace(f"[TRACE start] {cap_id}@{layer}: argv={argv}")
    script_exists = (os.path.exists(script) if script else False)
    _trace(f"[TRACE start] {cap_id}@{layer}: "
           f"script_exists={script_exists}")

    if not script or not os.path.exists(script):
        _trace(f"[TRACE start] {cap_id}@{layer}: SCRIPT NOT FOUND")
        emit("orchestrator", "-", "error",
             f"Script for {cap_id} at {layer} not found: {script}")
        return

    emit("orchestrator", "-", "info", f"Starting {cap_id} at {layer}...")
    try:
        proc = subprocess.Popen(argv)
        process_tree.assign_process(proc)
        processes[pair] = proc
        _trace(f"[TRACE start] {cap_id}@{layer}: "
               f"POPEN OK pid={proc.pid}")
        emit("orchestrator", "-", "info",
             f"{cap_id} at {layer} started (PID: {proc.pid})")
    except Exception as e:
        _trace(f"[TRACE start] {cap_id}@{layer}: "
               f"POPEN FAILED {type(e).__name__}: {e}")
        emit("orchestrator", "-", "error",
             f"Failed to start {cap_id} at {layer}: {e}")


def stop_service(cap_id, layer):
    pair = (cap_id, layer)
    if pair not in processes:
        return
    proc = processes[pair]
    if proc.poll() is None:
        emit("orchestrator", "-", "info",
             f"Stopping {cap_id} at {layer} (PID: {proc.pid})...")
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.kill()
        emit("orchestrator", "-", "info", f"{cap_id} at {layer} stopped.")
    else:
        emit("orchestrator", "-", "info",
             f"{cap_id} at {layer} already terminated.")
    del processes[pair]


def stop_all_services():
    for pair in list(processes.keys()):
        cap_id, layer = pair
        stop_service(cap_id, layer)


def sync_services():
    _trace("[TRACE sync] entered")
    with sync_lock:
        enabled = get_enabled_caps()
        disabled = get_disabled_caps()
        layers_enabled = get_enabled_layers()

        _trace(f"[TRACE sync] enabled={enabled}")
        _trace(f"[TRACE sync] layers_enabled={layers_enabled}")
        _trace(f"[TRACE sync] disabled={disabled}")

        # Stop any running pair that should not be running.
        for pair in list(processes.keys()):
            cap_id, layer = pair
            if (cap_id not in enabled
                    or layer not in layers_enabled
                    or _pair_disabled(disabled, cap_id, layer)):
                stop_service(cap_id, layer)

        # Start every enabled pair that is not already running.
        for cap in enabled:
            if cap not in SERVICE_MAP:
                _trace(f"[TRACE sync] {cap}: not in SERVICE_MAP")
                continue
            layers_for_cap = SERVICE_MAP[cap]
            if not isinstance(layers_for_cap, list):
                _trace(f"[TRACE sync] {cap}: SERVICE_MAP entry "
                       f"not a list")
                continue
            _trace(f"[TRACE sync] {cap}: SERVICE_MAP={layers_for_cap}")
            for layer in layers_for_cap:
                _trace(f"[TRACE sync] checking {cap}@{layer}")
                if layer not in layers_enabled:
                    _trace(f"[TRACE sync] {cap}@{layer}: "
                           f"layer not in layers_enabled")
                    continue
                if _pair_disabled(disabled, cap, layer):
                    _trace(f"[TRACE sync] {cap}@{layer}: "
                           f"pair disabled")
                    continue
                pair = (cap, layer)
                if pair in processes \
                        and processes[pair].poll() is None:
                    _trace(f"[TRACE sync] {cap}@{layer}: "
                           f"already running")
                    continue
                _trace(f"[TRACE sync] {cap}@{layer}: WILL SPAWN")
                start_service(cap, layer)


# ----------------------------------------------------------------------
# Monitor thread
# ----------------------------------------------------------------------
def monitor_loop():
    last_disabled = None
    last_enabled = None
    last_layers = None
    while not stop_monitor:
        try:
            disabled = get_disabled_caps()
            enabled = get_enabled_caps()
            layers = get_enabled_layers()
            if (disabled != last_disabled
                    or enabled != last_enabled
                    or layers != last_layers):
                emit("orchestrator", "-", "info",
                     "Configuration changed; reconciling services.")
                sync_services()
                last_disabled = disabled
                last_enabled = enabled
                last_layers = layers
        except Exception as e:
            emit("orchestrator", "-", "error", f"Monitor error: {e}")
        time.sleep(5)


# ----------------------------------------------------------------------
# Interactive commands (legacy fallback)
# ----------------------------------------------------------------------
def print_status():
    enabled = get_enabled_caps()
    disabled = get_disabled_caps()
    layers_enabled = get_enabled_layers()
    print("\n=== Capability Status ===")
    for cap in ALL_CAPS:
        if cap not in SERVICE_MAP:
            continue
        layer_map = SERVICE_MAP[cap]
        if not isinstance(layer_map, list):
            continue
        for layer in layer_map:
            pair = (cap, layer)
            state = "ENABLED" if cap in enabled else "DISABLED (inactive)"
            if _pair_disabled(disabled, cap, layer):
                state = "DISABLED (by user)"
            if layer not in layers_enabled:
                state = "LAYER DISABLED"
            running = ("RUNNING" if pair in processes
                       and processes[pair].poll() is None else "STOPPED")
            pid = (processes[pair].pid if pair in processes
                   and processes[pair].poll() is None else "N/A")
            print(f"  {cap}@{layer:8} : {state:25} | "
                  f"{running:7} | PID: {pid}")


def interactive_prompt():
    print("\nInteractive management commands:")
    print("  enable <cap>       - enable a capability (e.g., enable ssh)")
    print("  disable <cap>      - disable a capability")
    print("  status             - show current status")
    print("  quit               - exit orchestrator (stops all services)")
    while True:
        try:
            cmd = input("\n> ").strip().lower()
            if not cmd:
                continue
            parts = cmd.split()
            if parts[0] == "quit":
                print("Shutting down...")
                stop_all_services()
                break
            elif parts[0] == "status":
                print_status()
            elif parts[0] == "enable" and len(parts) == 2:
                cap = parts[1]
                if cap not in ALL_CAPS:
                    print(f"Unknown capability: {cap}")
                    continue
                config = load_system_config()
                if not config.get("enabled_capabilities", {}).get(cap, False):
                    config["enabled_capabilities"][cap] = True
                    if save_system_config(config):
                        print(f"Enabled {cap}")
                        disabled = get_disabled_caps()
                        disabled.pop(cap, None)
                        write_blackboard_disabled(disabled)
                    else:
                        print("Failed to update config.")
                else:
                    print(f"{cap} is already enabled.")
            elif parts[0] == "disable" and len(parts) == 2:
                cap = parts[1]
                if cap not in ALL_CAPS:
                    print(f"Unknown capability: {cap}")
                    continue
                config = load_system_config()
                if config.get("enabled_capabilities", {}).get(cap, False):
                    config["enabled_capabilities"][cap] = False
                    if save_system_config(config):
                        print(f"Disabled {cap}")
                        disabled = get_disabled_caps()
                        disabled[cap] = ["*"]
                        write_blackboard_disabled(disabled)
                    else:
                        print("Failed to update config.")
                else:
                    print(f"{cap} is already disabled.")
            else:
                print("Invalid command. Available: enable, disable, status, quit")
        except KeyboardInterrupt:
            print("\nExiting interactive mode.")
            break
        except EOFError:
            print("\nInput closed. Exiting interactive mode.")
            break
        except Exception as e:
            print(f"Error: {e}")


# ----------------------------------------------------------------------
# Main
# ----------------------------------------------------------------------
def main():
    global stop_monitor

    # atexit order (LIFO): services stop first, then router.
    atexit.register(stop_router)
    atexit.register(stop_all_services)

    signal.signal(signal.SIGINT, _shutdown_signal)
    signal.signal(signal.SIGTERM, _shutdown_signal)

    print("\n" + "="*60)
    print("🛡️ ACF Orchestrator")
    print("="*60)

    job = process_tree.create_job()
    if job is not None:
        print("[ORCH] Kill-on-close job created; "
              "children will die with this process")
    else:
        print("[ORCH] Kill-on-close job not available; "
              "children may survive a forced kill")

    if not os.path.exists(SYSTEM_CONFIG_FILE):
        print("No configuration found. Please run "
              "'python config_interactive.py' first.")
        sys.exit(1)

    # Event router
    router_port = _safe_call(start_router, default=None,
                             label="Event router")
    if router_port is not None:
        print(f"[ORCH] Event router listening on port {router_port}")
    else:
        print("[ORCH] Event router not available; events will use direct print")

    _safe_call(emit, "orchestrator", "-", "info",
               "Orchestrator starting", label="Initial emit")

    # Monitor thread and services
    print("Starting monitor thread...")
    monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
    monitor_thread.start()

    time.sleep(1)
    _safe_call(sync_services, label="sync_services")

    # ------------------------------------------------------------------
    # Layer manager: run in a daemon thread using the original signature.
    # The daemon thread calls initialize(), which starts its own monitor
    # thread and then blocks. The orchestrator's main thread continues.
    # When the process exits, the daemon thread (and the monitor sub-thread
    # it started) die with the process.
    # ------------------------------------------------------------------
    config = load_system_config()
    enabled_dict = (config.get("enabled_capabilities", {})
                    if isinstance(config, dict) else {})
    custom_dict = (enabled_dict.get("custom", {})
                   if isinstance(enabled_dict, dict) else {})
    if not isinstance(custom_dict, dict):
        custom_dict = {}
    has_custom_logs = any(custom_dict.values())

    layers_dict = (config.get("layers", {})
                   if isinstance(config, dict) else {})
    if isinstance(layers_dict, dict):
        has_layers = any(layers_dict.values())
    elif isinstance(layers_dict, list):
        has_layers = bool(layers_dict)
    else:
        has_layers = False

    if has_custom_logs or has_layers:
        try:
            import layer_manager
            threading.Thread(
                target=layer_manager.initialize,
                daemon=True,
                name="layer_manager",
            ).start()
            print("[ORCH] Layer Manager started (thread).")
        except ImportError:
            print("[ORCH] Layer Manager not found. Continuing without it.")
        except Exception as e:
            print(f"[ORCH] Layer Manager failed to start: {e}")
    else:
        print("[ORCH] No custom logs or layers enabled. "
              "Layer Manager not started.")

    # ------------------------------------------------------------------
    # Console (fallback to legacy prompt if unavailable).
    # The try/finally guarantees the monitor thread is signalled to stop
    # regardless of how the console exits.
    # ------------------------------------------------------------------
    try:
        try:
            from gui import run_gui
            run_gui()
        except ImportError:
            try:
               from console import run_console
               run_console()
            except ImportError:
               print("[ORCh] no GUI or console available; " "using legacy prompt.")
               if router_port is not None:
                   try:
                      start_reader(_print_event)
                   except Exception as e:
                      print(f"[ORCH] Reader failed to start: {e}")
            try:
                   interactive_prompt()
            except Exception as e:
                  print(f"[ORCH] Legacy prompt failed: {e}")
        except Exception as e:
            print(f"[ORCh] Presentation error: {e}")
    finally: 
         try:
           import layer_manager
           layer_manager.handle_shutdown()
           layer_manager.stop_all_engines()
         except Exception:
             pass
         stop_monitor = True
         try:
            moitor_thread.join(timeout=2)
         except Exception:
             pass

    print("Orchestrator terminated.")


if __name__ == "__main__":
    main()