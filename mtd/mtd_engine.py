#!/usr/bin/env python3
"""
mtd/mtd_engine.py - Layer 4c Moving Target Defence engine.

The only process the orchestrator launches for layer4c.

Dispatch modes:

  MTD mode (primary)
    Imports mtd.action_* classes. Builds a per-capability action
    list from the classes whose supports(capability, context)
    returns True. Refreshes preflight() every cycle. Dispatches:
    should_activate(state) -> activate() or deactivate().

  STANDALONE mode (fallback)
    Used only when the action modules cannot be imported. Runs a
    port shuffle inline for the ssh capability.

Worker rebuild rule:

    A worker is rebuilt when either:
      - the set of layer4c capabilities changes, or
      - the log_path the worker was constructed with no longer
        matches the current capability_paths.<cap> in config.

State source (per capability):

    layer_3_state_<cap>.state    (preferred)
    layer_3_state.state          (flat, fallback)
    "GREEN"                      (final fallback)

Section written:

    layer_4c_mtd_<cap>

Section keys written:

    port, previous_port, target_port, base_port, alternate_port,
    aggressive_port, backend, config_path, service_name, decoy,
    actions, mtd_timestamp, mtd_healthy, state_input, source,
    version, action_registry, action_summary, action_log,
    mtd_cycle_count, mtd_last_cycle_at,
    state_observed, state_entered_at, state_duration_seconds.

    The state_* keys record what the worker observed this cycle.
    mtd_cycle_count and mtd_last_cycle_at record liveness.
    action_summary carries one line per action:
        {name: {preflight: status, reason: gate_reason}}.

Windows shutdown note:

    signal.SIGINT fires on Ctrl+C. signal.SIGTERM is registered but
    is not delivered by Windows TerminateProcess. atexit removes
    the heartbeat on normal exit or SIGINT.
"""

import atexit
import importlib
import inspect
import json
import os
import re
import shutil
import signal
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from config import Config
from platform_utils import acquire_lock, release_lock, get_temp_dir

try:
    from event_emit import emit
except ImportError:
    def emit(src, layer, level, msg, capability=None, cycle=None):
        ts = time.strftime("%H:%M:%S")
        print(f"[{ts}][{src}][{layer}][{level.upper()}] {msg}")


# ----------------------------------------------------------------------
# Action imports
# ----------------------------------------------------------------------
_ACTION_CLASSES: List[type] = []
_ACTION_IMPORT_ERRORS: Dict[str, str] = {}


def _try_import_class(module_name, class_name):
    try:
        mod = importlib.import_module(module_name)
        cls = getattr(mod, class_name, None)
        if cls is None:
            _ACTION_IMPORT_ERRORS[module_name] = (
                f"module imported but {class_name} not found")
            return None
        if not inspect.isclass(cls):
            _ACTION_IMPORT_ERRORS[module_name] = (
                f"{class_name} is not a class "
                f"(got {type(cls).__name__})")
            return None
        return cls
    except Exception as e:
        _ACTION_IMPORT_ERRORS[module_name] = f"{type(e).__name__}: {e}"
        return None


TrafficShuffleAction = _try_import_class(
    "mtd.action_traffic_shuffle", "TrafficShuffleAction")
DecoyAction = _try_import_class("mtd.action_decoy", "DecoyAction")
PathRotationAction = _try_import_class(
    "mtd.action_path_rotation", "PathRotationAction")
HoneytokenAction = _try_import_class(
    "mtd.action_honeytoken", "HoneytokenAction")

for _c in (TrafficShuffleAction, DecoyAction,
           PathRotationAction, HoneytokenAction):
    if _c is not None:
        _ACTION_CLASSES.append(_c)

_ACTIONS_AVAILABLE = len(_ACTION_CLASSES) > 0


# ----------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------
SRC = "mtd_engine"
LAYER = "layer4c"

SYSTEM_CONFIG_FILE = os.path.join(_ROOT, "system_config.json")
BLACKBOARD_FILE = Config.BLACKBOARD_FILE
HEARTBEAT_FILE = os.path.join(get_temp_dir(), "acf_mtd_engine.heartbeat")

BASE_CYCLE_SECONDS = 10
MIN_CYCLE_SECONDS = 3
MAX_CYCLE_SECONDS = 30

WATCHDOG_MULTIPLIER = 6
HARD_WATCHDOG_MULTIPLIER = 30

STATE_RANK = {"GREEN": 0, "YELLOW": 1, "ORANGE": 2, "RED": 3}

WINDIR = os.environ.get("WINDIR", r"C:\Windows")
SSHD_BINARY = os.path.join(WINDIR, "System32", "OpenSSH", "sshd.exe")
SSHD_CONFIG = r"C:\ProgramData\ssh\sshd_config"
SSHD_SERVICE = "sshd"

BASE_PORT = 22
ALTERNATE_PORT = 2222
AGGRESSIVE_PORT = 3333

SERVICE_RESTART_TIMEOUT = 45.0
SERVICE_STATE_POLL_INTERVAL = 0.4

PORT_VERIFY_RETRIES = 6
PORT_VERIFY_BASE_DELAY = 0.8
PORT_VERIFY_MAX_DELAY = 6.0

FILE_LOCK_RETRIES = 5
FILE_LOCK_DELAYS = (0.2, 0.5, 1.0, 2.0)

MAX_ACTION_HISTORY = 50

_SC_ERR_SERVICE_ALREADY_RUNNING = "1056"
_SC_ERR_SERVICE_DISABLED = "1058"
_SC_ERR_SERVICE_CANNOT_ACCEPT_CTRL = "1061"
_SC_ERR_SERVICE_NOT_ACTIVE = "1062"

_SC_TRANSIENT_FROM_START = ("startpending", "continuepending")
_SC_TRANSIENT_FROM_STOP = ("stoppending",)

_running = True
_last_cycle_time = time.time()
_last_successful_cycle_time = time.time()
_cycle_in_progress = False


def _write_heartbeat_file():
    try:
        os.makedirs(os.path.dirname(HEARTBEAT_FILE), exist_ok=True)
        with open(HEARTBEAT_FILE, "w", encoding="utf-8") as f:
            f.write(str(time.time()))
    except Exception:
        pass


def _remove_heartbeat_file():
    try:
        if os.path.exists(HEARTBEAT_FILE):
            os.remove(HEARTBEAT_FILE)
    except Exception:
        pass


atexit.register(_remove_heartbeat_file)


def _bb_read():
    for attempt in range(3):
        try:
            with open(BLACKBOARD_FILE, "r", encoding="utf-8") as f:
                return json.load(f)
        except json.JSONDecodeError:
            time.sleep(0.05 * (attempt + 1))
        except Exception:
            return {}
    return {}


def _bb_read_section(section):
    data = _bb_read()
    s = data.get(section, {})
    return s if isinstance(s, dict) else {}


def _bb_update(section, updates):
    try:
        with open(BLACKBOARD_FILE, "r+", encoding="utf-8") as f:
            acquire_lock(f.fileno(), exclusive=True)
            try:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    data = {}
                if not isinstance(data, dict):
                    data = {}
                if section not in data or \
                        not isinstance(data[section], dict):
                    data[section] = {}
                data[section].update(updates)
                f.seek(0)
                json.dump(data, f, indent=2)
                f.truncate()
                return True
            finally:
                release_lock(f.fileno())
    except Exception as e:
        emit(SRC, LAYER, "error",
             f"Blackboard update for {section}: {e}")
        return False


def load_config():
    try:
        with open(SYSTEM_CONFIG_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception as e:
        emit(SRC, LAYER, "error", f"config load failed: {e}")
        return {}


def _read_disabled_map():
    data = _bb_read()
    disabled = data.get("disabled_capabilities", {})
    if isinstance(disabled, list):
        return {cap: ["*"] for cap in disabled}
    if isinstance(disabled, dict):
        out = {}
        for cap, layers in disabled.items():
            if isinstance(layers, list):
                out[cap] = layers
            elif layers is True:
                out[cap] = ["*"]
        return out
    return {}


def _pair_disabled(disabled_map, capability, layer):
    entry = disabled_map.get(capability)
    if not entry:
        return False
    if "*" in entry:
        return True
    return layer in entry


def _capabilities_for_layer(config, layer):
    capability_layers = config.get("capability_layers", {})
    if not isinstance(capability_layers, dict):
        return []
    return [name for name, layers in capability_layers.items()
            if isinstance(layers, list) and layer in layers]


def _read_states_from_blackboard(capabilities):
    """
    One blackboard read for every capability.
    Per-capability key first, flat key second, GREEN last.
    """
    data = _bb_read()
    out = {}
    for c in capabilities:
        sec = data.get(f"layer_3_state_{c}", {})
        s = sec.get("state") if isinstance(sec, dict) else None
        if isinstance(s, str) and s.strip().upper() in STATE_RANK:
            out[c] = s.strip().upper()
            continue
        flat = data.get("layer_3_state", {})
        s = flat.get("state") if isinstance(flat, dict) else None
        if isinstance(s, str) and s.strip().upper() in STATE_RANK:
            out[c] = s.strip().upper()
            continue
        out[c] = "GREEN"
    return out


# ----------------------------------------------------------------------
# Config I/O
# ----------------------------------------------------------------------
def _decode_raw(raw):
    checks = (
        (b"\xff\xfe\x00\x00", "utf-32-le"),
        (b"\x00\x00\xfe\xff", "utf-32-be"),
        (b"\xef\xbb\xbf", "utf-8"),
        (b"\xff\xfe", "utf-16-le"),
        (b"\xfe\xff", "utf-16-be"),
    )
    for bom, enc in checks:
        if raw.startswith(bom):
            body = raw[len(bom):]
            try:
                if enc in ("utf-16-le", "utf-16-be",
                           "utf-32-le", "utf-32-be"):
                    return (body.decode(enc, errors="surrogatepass"),
                            bom, enc + "+surrogatepass")
                return (body.decode(enc), bom, enc)
            except (LookupError, UnicodeDecodeError):
                continue
    try:
        return (raw.decode("utf-8"), b"", "utf-8")
    except UnicodeDecodeError:
        pass
    return (raw.decode("cp1252", errors="surrogateescape"),
            b"", "cp1252+surrogateescape")


def _read_text(path):
    with open(path, "rb") as f:
        raw = f.read()
    return _decode_raw(raw)


def _write_text(path, text, bom, encoding):
    if encoding.endswith("+surrogateescape"):
        enc = encoding[: -len("+surrogateescape")]
        data = bom + text.encode(enc, errors="surrogateescape")
    elif encoding.endswith("+surrogatepass"):
        enc = encoding[: -len("+surrogatepass")]
        data = bom + text.encode(enc, errors="surrogatepass")
    else:
        data = bom + text.encode(encoding)
    with open(path, "wb") as f:
        f.write(data)


def _split_head_tail(content):
    m = re.search(r"^\s*Match\b", content,
                  re.MULTILINE | re.IGNORECASE)
    if m:
        return (content[:m.start()], content[m.start():])
    return (content, "")


def _read_port_from_config(path):
    try:
        content, _bom, _enc = _read_text(path)
    except Exception:
        return None
    head, _tail = _split_head_tail(content)
    for line in head.splitlines():
        m = re.match(r"^\s*Port\s+(\d+)", line, re.IGNORECASE)
        if m:
            try:
                return int(m.group(1))
            except ValueError:
                continue
    return BASE_PORT


def _rewrite_port_in_config(path, new_port):
    try:
        original, bom, encoding = _read_text(path)
    except Exception as e:
        return False, f"read failed: {e}"
    head, tail = _split_head_tail(original)
    pattern = re.compile(r"^(\s*)Port\s+\d+([^\r\n]*)$",
                         re.IGNORECASE | re.MULTILINE)

    def repl(m):
        return f"{m.group(1)}Port {new_port}{m.group(2)}"

    new_head, count = pattern.subn(repl, head, count=1)
    if count == 0:
        if new_head and not new_head.endswith("\n"):
            new_head += "\n"
        new_head += f"Port {new_port}\n"
    tmp = path + ".tmp"
    try:
        _write_text(tmp, new_head + tail, bom, encoding)
        os.replace(tmp, path)
        return True, ""
    except Exception as e:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass
        return False, f"write failed: {e}"


def _copy_acl_windows(src, dst):
    ps = _resolve_powershell()
    if not ps:
        return False
    se = src.replace("'", "''")
    de = dst.replace("'", "''")
    cmd = (f"try {{ "
           f"  $acl = Get-Acl -LiteralPath '{se}'; "
           f"  Set-Acl -LiteralPath '{de}' -AclObject $acl; "
           f"  'ok' "
           f"}} catch {{ 'fail' }}")
    rc, out, _err = _run_ps(cmd, timeout=10.0)
    return rc == 0 and "ok" in (out or "")


_CACHED_POWERSHELL = None


def _resolve_powershell():
    global _CACHED_POWERSHELL
    if _CACHED_POWERSHELL is not None:
        return _CACHED_POWERSHELL or None
    for c in ("powershell.exe", "powershell", "pwsh.exe", "pwsh"):
        found = shutil.which(c)
        if found:
            _CACHED_POWERSHELL = found
            return found
    _CACHED_POWERSHELL = ""
    return None


_PS_PREAMBLE = (
    "$ErrorActionPreference = 'Continue'; "
    "try { [Console]::OutputEncoding = "
    "[System.Text.Encoding]::UTF8 } catch {}; "
)


def _run_ps(cmd, timeout=10.0):
    ps = _resolve_powershell()
    if not ps:
        return -1, "", "no PowerShell binary found"
    try:
        r = subprocess.run(
            [ps, "-NoProfile", "-NonInteractive", "-Command",
             _PS_PREAMBLE + cmd],
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace")
        return r.returncode, r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)


def _sc(args, timeout=10.0):
    try:
        r = subprocess.run(["sc.exe"] + args, capture_output=True,
                           text=True, timeout=timeout,
                           encoding="utf-8", errors="replace")
        return r.returncode, r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)


def _service_status(name, timeout=8.0):
    esc = name.replace("'", "''")
    cmd = (f"try {{ "
           f"  $svc = Get-Service -Name '{esc}' -ErrorAction Stop; "
           f"  $svc.Status.ToString() "
           f"}} catch {{ 'unknown' }}")
    rc, out, _err = _run_ps(cmd, timeout=timeout)
    if rc != 0:
        return "unknown"
    return (out or "").strip().lower() or "unknown"


def _wait_for_service(name, want, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _service_status(name) == want:
            return True
        time.sleep(SERVICE_STATE_POLL_INTERVAL)
    return False


def _resolve_transition_before_verb(name):
    st = _service_status(name)
    if st in _SC_TRANSIENT_FROM_START:
        _wait_for_service(name, "running", SERVICE_RESTART_TIMEOUT)
    elif st in _SC_TRANSIENT_FROM_STOP:
        _wait_for_service(name, "stopped", SERVICE_RESTART_TIMEOUT)


def _service_stop(name):
    _resolve_transition_before_verb(name)
    rc, out, err = _sc(["stop", name])
    blob = (out or "") + (err or "")
    if rc != 0 and _SC_ERR_SERVICE_NOT_ACTIVE not in blob:
        return False, (err or out or "sc stop failed").strip()[:200]
    if not _wait_for_service(name, "stopped", SERVICE_RESTART_TIMEOUT):
        return False, "service did not reach stopped"
    return True, ""


def _service_start(name):
    _resolve_transition_before_verb(name)
    rc, out, err = _sc(["start", name])
    blob = (out or "") + (err or "")
    if rc != 0 and _SC_ERR_SERVICE_ALREADY_RUNNING not in blob:
        if _SC_ERR_SERVICE_DISABLED in blob:
            return False, "service is disabled"
        return False, (err or out or "sc start failed").strip()[:200]
    if not _wait_for_service(name, "running", SERVICE_RESTART_TIMEOUT):
        return False, "service did not reach running"
    return True, ""


def _listening_on_port(port):
    cmd = (f"try {{ "
           f"  $c = Get-NetTCPConnection -LocalPort {port} "
           f"        -State Listen -ErrorAction Stop; "
           f"  if ($c) {{ 'yes' }} else {{ 'no' }} "
           f"}} catch {{ 'no' }}")
    rc, out, _err = _run_ps(cmd, timeout=6.0)
    if rc != 0:
        return False
    return "yes" in (out or "")


def _verify_port(port):
    delay = PORT_VERIFY_BASE_DELAY
    for _ in range(PORT_VERIFY_RETRIES):
        if _listening_on_port(port):
            return True
        time.sleep(delay)
        delay = min(delay * 1.6, PORT_VERIFY_MAX_DELAY)
    return False


class _StandalonePortShuffle:
    def __init__(self, capability="ssh"):
        self.capability = capability
        self.config_path = SSHD_CONFIG
        self.service_name = SSHD_SERVICE
        self.backup_path = self.config_path + ".acf.bak"
        self.current_port = _read_port_from_config(self.config_path) \
            or BASE_PORT
        self.previous_port = self.current_port
        self.target_port = self.current_port
        self.actions = []

    def change_port(self, new_port):
        old = _read_port_from_config(self.config_path) or BASE_PORT
        self.previous_port = old
        self.target_port = new_port
        if old == new_port:
            return True, ""
        try:
            shutil.copy2(self.config_path, self.backup_path)
            _copy_acl_windows(self.config_path, self.backup_path)
        except Exception as e:
            return False, f"backup failed: {e}"
        ok, err = _rewrite_port_in_config(self.config_path, new_port)
        if not ok:
            self._restore()
            return False, err
        try:
            r = subprocess.run(
                [SSHD_BINARY, "-t", "-f", self.config_path],
                capture_output=True, text=True, timeout=10,
                encoding="utf-8", errors="replace")
            if r.returncode != 0:
                self._restore()
                return False, (r.stderr or r.stdout or "").strip()[:200]
        except Exception as e:
            self._restore()
            return False, f"sshd -t failed: {e}"
        ok, err = _service_stop(self.service_name)
        if not ok:
            self._restore()
            return False, f"service stop failed: {err}"
        ok, err = _service_start(self.service_name)
        if not ok:
            self._restore()
            return False, f"service start failed: {err}"
        if not _verify_port(new_port):
            self._restore()
            return False, f"port {new_port} not listening"
        self.current_port = new_port
        self._record("port_switch", True, "",
                     old_port=old, new_port=new_port)
        try:
            if os.path.isfile(self.backup_path):
                os.remove(self.backup_path)
        except Exception:
            pass
        return True, ""

    def _restore(self):
        try:
            if os.path.isfile(self.backup_path):
                tmp = self.config_path + ".tmp"
                shutil.copy2(self.backup_path, tmp)
                _copy_acl_windows(self.backup_path, tmp)
                os.replace(tmp, self.config_path)
                _service_stop(self.service_name)
                _service_start(self.service_name)
        except Exception:
            pass
        self._record("rollback", True, "")

    def _record(self, action, ok, err="", **fields):
        entry = {"ts": time.time(), "action": action, "ok": ok}
        for k, v in fields.items():
            entry[k] = v
        if err:
            entry["error"] = err[:200]
        self.actions.append(entry)
        if len(self.actions) > MAX_ACTION_HISTORY:
            self.actions = self.actions[-MAX_ACTION_HISTORY:]


class MTDWorker:
    def __init__(self, capability, disabled_map):
        self.capability = capability
        self.disabled_map = disabled_map
        self.state_section = f"layer_3_state_{capability}"
        self.mtd_section = f"layer_4c_mtd_{capability}"
        self.actions = []
        self.standalone = None
        self._cycle_count: int = 0

        self._cached_log_path = self._read_log_path_from_config()

        self._build()

    def _read_log_path_from_config(self) -> Optional[str]:
        cfg = load_config()
        cap_paths = cfg.get("capability_paths", {})
        if not isinstance(cap_paths, dict):
            return None
        if self.capability in cap_paths:
            v = cap_paths[self.capability]
            return v if isinstance(v, str) else None
        custom = cap_paths.get("custom", {})
        if isinstance(custom, dict) and self.capability in custom:
            v = custom[self.capability]
            return v if isinstance(v, str) else None
        return None

    def log_path_changed(self) -> bool:
        return self._read_log_path_from_config() != self._cached_log_path

    def _base_context(self):
        cfg = load_config()
        cap_paths = cfg.get("capability_paths", {})
        log_path = None
        if isinstance(cap_paths, dict):
            if self.capability in cap_paths:
                log_path = cap_paths[self.capability]
            else:
                custom = cap_paths.get("custom", {})
                if isinstance(custom, dict) and \
                        self.capability in custom:
                    log_path = custom[self.capability]
        return {
            "capability": self.capability,
            "log_path": log_path,
            "config_path": SYSTEM_CONFIG_FILE,
            "sshd_config_path": SSHD_CONFIG,
            "system_config_path": SYSTEM_CONFIG_FILE,
            "base_dir": None,
        }

    def _context_for(self, action_class):
        ctx = self._base_context()
        name = getattr(action_class, "name", "")
        if name == "path_rotation":
            ctx["config_path"] = SYSTEM_CONFIG_FILE
        elif name == "address_rotation":
            ctx["config_path"] = SSHD_CONFIG
        return ctx

    def _build(self):
        if _ACTIONS_AVAILABLE:
            for cls in _ACTION_CLASSES:
                try:
                    action_ctx = self._context_for(cls)
                    if not cls.supports(self.capability, action_ctx):
                        continue
                    inst = cls(self.capability, action_ctx)
                    status, mode, reason = inst.preflight()
                    self.actions.append({
                        "name": cls.name,
                        "class": cls.__name__,
                        "instance": inst,
                        "preflight_status": status,
                        "preflight_mode": mode,
                        "preflight_reason": reason,
                    })
                except Exception as e:
                    emit(SRC, LAYER, "warn",
                         f"action {getattr(cls, 'name', cls)} "
                         f"construction failed: {e}",
                         capability=self.capability)
        else:
            if self.capability == "ssh":
                self.standalone = _StandalonePortShuffle(self.capability)

    def shutdown(self):
        for entry in self.actions:
            try:
                inst = entry["instance"]
                if inst.is_active():
                    ok, err = inst.deactivate()
                    if not ok:
                        emit(SRC, LAYER, "warn",
                             f"deactivate {entry['name']} on drop "
                             f"failed: {err}",
                             capability=self.capability)
            except Exception as e:
                emit(SRC, LAYER, "warn",
                     f"deactivate {entry['name']} on drop raised: {e}",
                     capability=self.capability)
        if self.standalone is not None:
            try:
                self.standalone.change_port(BASE_PORT)
            except Exception as e:
                emit(SRC, LAYER, "warn",
                     f"standalone restore on drop failed: {e}",
                     capability=self.capability)

    # ------------------------------------------------------------------
    # Observability: read what the state section says this cycle
    # ------------------------------------------------------------------
    def _read_state_info(self, state: str) -> Dict[str, Any]:
        """
        Read the state section for this capability and return what
        the worker observed this cycle. Used in the section write
        so an operator can see, without log hunting, exactly what
        state was seen and how long it has been held.
        """
        sec = _bb_read_section(self.state_section)
        entered = 0.0
        if isinstance(sec, dict):
            try:
                entered = float(sec.get("state_entered_at", 0.0))
            except (TypeError, ValueError):
                entered = 0.0
        now = time.time()
        if entered > 0 and entered <= now:
            duration = now - entered
        else:
            entered = 0.0
            duration = 0.0
        return {
            "state_observed": state,
            "state_entered_at": entered,
            "state_duration_seconds": round(duration, 3),
        }

    def run_cycle(self, state):
        self._cycle_count += 1
        state_info = self._read_state_info(state)

        disabled = _pair_disabled(self.disabled_map,
                                  self.capability, LAYER)
        if disabled:
            self._write_section(state, disabled=True,
                                state_info=state_info)
            return
        self._refresh_preflight()
        if self.standalone is not None:
            self._run_standalone(state)
        else:
            self._run_actions(state)
        self._write_section(state, state_info=state_info)

    def _refresh_preflight(self):
        for entry in self.actions:
            inst = entry["instance"]
            try:
                status, mode, reason = inst.preflight()
                entry["preflight_status"] = status
                entry["preflight_mode"] = mode
                entry["preflight_reason"] = reason
            except Exception as e:
                entry["preflight_status"] = "BLOCKED"
                entry["preflight_mode"] = ""
                entry["preflight_reason"] = f"preflight exception: {e}"

    def _run_actions(self, state):
        for entry in self.actions:
            inst = entry["instance"]
            if entry["preflight_status"] != "READY":
                continue
            try:
                should = inst.should_activate(state)
                if should:
                    ok, err = inst.activate()
                    if not ok:
                        emit(SRC, LAYER, "warn",
                             f"{entry['name']}: activate failed: {err}",
                             capability=self.capability)
                else:
                    if inst.is_active():
                        ok, err = inst.deactivate()
                        if not ok:
                            emit(SRC, LAYER, "warn",
                                 f"{entry['name']}: deactivate "
                                 f"failed: {err}",
                                 capability=self.capability)
            except Exception as e:
                emit(SRC, LAYER, "error",
                     f"{entry['name']}: {e}",
                     capability=self.capability)

    def _run_standalone(self, state):
        if state == "RED":
            target = AGGRESSIVE_PORT
        elif state == "ORANGE":
            target = ALTERNATE_PORT
        else:
            target = BASE_PORT
        self.standalone.change_port(target)

    def any_action_ready(self) -> bool:
        for entry in self.actions:
            if entry["preflight_status"] == "READY":
                return True
        if self.standalone is not None:
            return True
        return False

    def _write_section(self, state, disabled=False, state_info=None):
        statuses = {}
        for entry in self.actions:
            try:
                statuses[entry["name"]] = entry["instance"].status()
            except Exception as e:
                statuses[entry["name"]] = {"error": str(e)}

        # One-line-per-action rollup: preflight status plus the
        # gate reason each action exposed. Lets an operator see at
        # a glance which action is blocked and why, without
        # drilling into action_registry.
        action_summary: Dict[str, Dict[str, str]] = {}
        for entry in self.actions:
            st = statuses.get(entry["name"], {})
            reason = ""
            if entry["preflight_status"] != "READY":
                reason = entry["preflight_reason"] or ""
            elif isinstance(st, dict):
                reason = (st.get("gate_reson") or st.get("flip_reason") or "")

        action_log = []
        for name, st in statuses.items():
            if not isinstance(st, dict):
                continue
            acts = st.get("actions")
            if isinstance(acts, list):
                for a in acts[-MAX_ACTION_HISTORY:]:
                    if isinstance(a, dict):
                        action_log.append(a)
        if self.standalone is not None:
            action_log.extend(
                self.standalone.actions[-MAX_ACTION_HISTORY:])

        port = BASE_PORT
        prev_port = BASE_PORT
        target_port = BASE_PORT
        if "traffic_shuffle" in statuses:
            ts = statuses["traffic_shuffle"]
            port = ts.get("active_port", BASE_PORT)
            prev_port = ts.get("primary_port", BASE_PORT)
            target_port = ts.get("alternate_port", BASE_PORT)
        elif "port_shuffle" in statuses:
            ps = statuses["port_shuffle"]
            port = ps.get("port", BASE_PORT)
            prev_port = ps.get("previous_port", BASE_PORT)
            target_port = ps.get("target_port", BASE_PORT)
        elif self.standalone is not None:
            port = self.standalone.current_port
            prev_port = self.standalone.previous_port
            target_port = self.standalone.target_port

        decoy_active = False
        if "decoy" in statuses:
            decoy_active = bool(statuses["decoy"].get("active"))

        registry = {
            entry["name"]: {
                "preflight_status": entry["preflight_status"],
                "preflight_mode": entry["preflight_mode"],
                "preflight_reason": entry["preflight_reason"],
                "status": statuses.get(entry["name"], {}),
            }
            for entry in self.actions
        }
        if self.standalone is not None:
            registry["traffic_shuffle"] = {
                "mode": "standalone",
                "status": {
                    "port": self.standalone.current_port,
                    "previous_port": self.standalone.previous_port,
                    "target_port": self.standalone.target_port,
                },
            }

        updates = {
            "port": port,
            "previous_port": prev_port,
            "target_port": target_port,
            "base_port": BASE_PORT,
            "alternate_port": ALTERNATE_PORT,
            "aggressive_port": AGGRESSIVE_PORT,
            "backend": "sshd_config",
            "config_path": SSHD_CONFIG,
            "service_name": SSHD_SERVICE,
            "decoy": decoy_active,
            "actions": [entry["name"] for entry in self.actions]
                       or (["traffic_shuffle"]
                           if self.standalone is not None else []),
            "mtd_timestamp": time.time(),
            "mtd_healthy": not disabled,
            "state_input": state,
            "source": SRC,
            "version": getattr(Config, "SCHEMA_VERSION", ""),
            "action_registry": registry,
            "action_summary": action_summary,
            "action_log": action_log[-MAX_ACTION_HISTORY:],
            "mtd_cycle_count": self._cycle_count,
            "mtd_last_cycle_at": time.time(),
        }
        if isinstance(state_info, dict):
            updates.update(state_info)
        _bb_update(self.mtd_section, updates)


class MTDEngine:
    def __init__(self):
        self.workers = {}
        self.cycle_count = 0
        self._no_workers_warned_at = 0.0
        self._no_ready_warned_at = 0.0

    def _collect_states(self):
        caps = list(self.workers.keys())
        if not caps:
            return {}
        return _read_states_from_blackboard(caps)

    def _rebuild_workers(self, disabled_map):
        global _last_cycle_time
        config = load_config()
        if not config:
            emit(SRC, LAYER, "error", "config empty; no workers")
            return
        names = _capabilities_for_layer(config, LAYER)
        if not names:
            return

        for name in list(self.workers.keys()):
            if name in names:
                continue
            emit(SRC, LAYER, "info",
                 f"{name} no longer assigned to layer4c; dropping",
                 capability=name)
            _last_cycle_time = time.time()
            self.workers[name].shutdown()
            del self.workers[name]

        for name in names:
            existing = self.workers.get(name)
            if existing is not None:
                if existing.log_path_changed():
                    emit(SRC, LAYER, "info",
                         f"{name} log_path changed in config; "
                         f"rebuilding worker",
                         capability=name)
                    _last_cycle_time = time.time()
                    existing.shutdown()
                    self.workers[name] = MTDWorker(name, disabled_map)
                else:
                    existing.disabled_map = disabled_map
                continue
            self.workers[name] = MTDWorker(name, disabled_map)
            emit(SRC, LAYER, "info",
                 f"worker attached "
                 f"({len(self.workers[name].actions)} action(s)"
                 + (", standalone"
                    if self.workers[name].standalone else "")
                 + ")",
                 capability=name)

    def _run_all(self, states):
        for name, worker in self.workers.items():
            try:
                worker.run_cycle(states.get(name, "GREEN"))
            except Exception as e:
                emit(SRC, LAYER, "error", f"worker error: {e}",
                     capability=name)

    def _warn_no_workers(self):
        now = time.time()
        if now - self._no_workers_warned_at < 60.0:
            return
        self._no_workers_warned_at = now
        emit(SRC, LAYER, "warn",
             "no capabilities assigned to layer4c")

    def _warn_all_blocked(self):
        if not self.workers:
            return
        for worker in self.workers.values():
            if worker.any_action_ready():
                return
        now = time.time()
        if now - self._no_ready_warned_at < 60.0:
            return
        self._no_ready_warned_at = now
        emit(SRC, LAYER, "warn",
             "every worker action preflight is BLOCKED; the engine "
             "is cycling but no action is running")

    def run(self):
        global _running, _last_cycle_time
        global _last_successful_cycle_time, _cycle_in_progress

        _install_signal_handlers()

        mode = "MTD" if _ACTIONS_AVAILABLE else "STANDALONE"
        emit(SRC, LAYER, "info",
             f"MTD engine starting (mode={mode}, "
             f"{len(_ACTION_CLASSES)} action class(es))")
        for mod, err in _ACTION_IMPORT_ERRORS.items():
            emit(SRC, LAYER, "warn", f"action import {mod}: {err}")
        if not _ACTIONS_AVAILABLE:
            emit(SRC, LAYER, "warn",
                 "no action modules importable; using standalone "
                 "port shuffle only")

        _last_successful_cycle_time = time.time()

        try:
            while _running:
                _cycle_in_progress = True
                _last_cycle_time = time.time()
                cycle_clean = True
                sleep_total = min(MAX_CYCLE_SECONDS, BASE_CYCLE_SECONDS)
                try:
                    self.cycle_count += 1
                    disabled_map = _read_disabled_map()
                    try:
                        self._rebuild_workers(disabled_map)
                        states = self._collect_states()
                        self._run_all(states)
                    except Exception as e:
                        emit(SRC, LAYER, "error",
                             f"engine cycle error: {e}")
                        cycle_clean = False
                        states = {}
                    if not self.workers:
                        self._warn_no_workers()
                    else:
                        self._warn_all_blocked()
                    _write_heartbeat_file()
                    if cycle_clean:
                        _last_successful_cycle_time = time.time()
                    sleep_total = self._cycle_sleep(states)
                finally:
                    _cycle_in_progress = False

                slept = 0.0
                while _running and slept < sleep_total:
                    time.sleep(0.5)
                    slept += 0.5
        finally:
            _remove_heartbeat_file()
            emit(SRC, LAYER, "info", "MTD engine stopped")

    def _cycle_sleep(self, states):
        if not states:
            return min(MAX_CYCLE_SECONDS, BASE_CYCLE_SECONDS)
        agg = max(states.values(),
                  key=lambda s: STATE_RANK.get(s, 0))
        if agg == "RED":
            return MIN_CYCLE_SECONDS
        if agg == "ORANGE":
            return max(MIN_CYCLE_SECONDS, BASE_CYCLE_SECONDS // 2)
        if agg == "YELLOW":
            return max(MIN_CYCLE_SECONDS,
                       int(BASE_CYCLE_SECONDS * 0.75))
        return min(MAX_CYCLE_SECONDS, BASE_CYCLE_SECONDS)


def _install_signal_handlers():
    for sig_name in ("SIGINT", "SIGTERM", "SIGBREAK"):
        sig = getattr(signal, sig_name, None)
        if sig is None:
            continue
        try:
            signal.signal(sig, _shutdown)
        except (ValueError, OSError):
            pass


def watchdog():
    global _running
    soft_threshold = BASE_CYCLE_SECONDS * WATCHDOG_MULTIPLIER
    hard_threshold = BASE_CYCLE_SECONDS * HARD_WATCHDOG_MULTIPLIER
    while _running:
        time.sleep(soft_threshold / 2)
        if not _running:
            return
        now = time.time()
        if _cycle_in_progress and \
                (now - _last_cycle_time) > hard_threshold:
            emit(SRC, LAYER, "error",
                 f"watchdog: cycle running for "
                 f"{now - _last_cycle_time:.0f}s "
                 f"(hard threshold {hard_threshold}s), "
                 f"requesting shutdown")
            _running = False
            return
        if not _cycle_in_progress and \
                (now - _last_successful_cycle_time) > soft_threshold:
            emit(SRC, LAYER, "error",
                 f"watchdog: no clean cycle in "
                 f"{now - _last_successful_cycle_time:.0f}s "
                 f"(soft threshold {soft_threshold}s), "
                 f"requesting shutdown")
            _running = False
            return


def _shutdown(sig, frame):
    global _running
    emit(SRC, LAYER, "info", f"shutdown signal {sig}")
    _running = False


def main():
    if not os.path.exists(SYSTEM_CONFIG_FILE):
        emit(SRC, LAYER, "error",
             f"config not found at {SYSTEM_CONFIG_FILE}")
        sys.exit(1)
    if not os.path.exists(BLACKBOARD_FILE):
        emit(SRC, LAYER, "error",
             f"blackboard not found at {BLACKBOARD_FILE}")
        sys.exit(1)
    emit(SRC, LAYER, "info",
         f"config loaded from {SYSTEM_CONFIG_FILE}")
    engine = MTDEngine()
    threading.Thread(target=watchdog, daemon=True,
                     name="mtd_watchdog").start()
    engine.run()


if __name__ == "__main__":
    main()