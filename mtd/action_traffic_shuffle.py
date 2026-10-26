#!/usr/bin/env python3
"""
mtd/action_traffic_shuffle.py — Traffic shuffle MTD action.

The service is preconfigured at setup to listen on both the primary
and the alternate port. This action flips the firewall: the primary
port is blocked for the outside world, traffic reaches the service
on the alternate port instead. The service is never stopped.

LADDER GATE:
  Both trigger axes now require state == RED.
    - distinct attackers >= threshold AND state RED
    - RED sustained >= trigger_red_seconds (via mtd/enabling.py)

  A cooldown after every restore (min_seconds_between_flips)
  prevents immediate re-fire once the restore window elapses.

  Duration is read through mtd/enabling.py. The action does not
  compute elapsed time itself.

Config keys:
  capability_rules.<cap>.shuffle.trigger_distinct_attackers (default 3)
  capability_rules.<cap>.shuffle.trigger_red_seconds       (default 300)
  capability_rules.<cap>.shuffle.restore_after_seconds     (default 1800)
  capability_rules.<cap>.shuffle.min_seconds_between_flips (default 60)

Port numbers come from mtd/port_registry.py.

Requires Administrator.
"""

import json
import os
import shutil
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Set, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from mtd.base import (
    MTDAction,
    STATUS_READY,
    STATUS_BLOCKED,
    MODE_PRIMARY,
)
from mtd import port_registry
from mtd import enabling

try:
    from config import Config
    _CONFIG_AVAILABLE = True
except ImportError:
    Config = None
    _CONFIG_AVAILABLE = False

try:
    from platform_utils import acquire_lock, release_lock
    _LOCK_AVAILABLE = True
except ImportError:
    _LOCK_AVAILABLE = False

    def acquire_lock(fd, exclusive=True):
        pass

    def release_lock(fd):
        pass

try:
    from event_emit import emit as _emit_impl
    _EMIT_AVAILABLE = True
except ImportError:
    _EMIT_AVAILABLE = False

    def _emit_impl(src, layer, level, msg):
        ts = time.strftime("%H:%M:%S")
        print(f"[{ts}][{src}][{layer}][{level.upper()}] {msg}")


def _safe_emit(src: str, layer: str, level: str, msg: str) -> None:
    try:
        _emit_impl(src, layer, level, msg)
    except Exception:
        pass


_LAYER = "layer4c"

BLACKBOARD_FILE = (
    getattr(Config, "BLACKBOARD_FILE", None)
    if _CONFIG_AVAILABLE else None
) or os.path.join(
    os.environ.get("TEMP", "/tmp"),
    "acf_state.json"
)

DEFAULT_TRIGGER_DISTINCT_ATTACKERS = 3
DEFAULT_TRIGGER_RED_SECONDS = 300
DEFAULT_RESTORE_AFTER_SECONDS = 1800
DEFAULT_MIN_SECONDS_BETWEEN_FLIPS = 60

NETSH_TIMEOUT = 15.0
PS_TIMEOUT = 10.0

_RULE_ALLOW_TEMPLATE = "ACF_capability_{cap}_ALLOW_{port}"
_RULE_BLOCK_TEMPLATE = "ACF_capability_{cap}_SHUFFLE_BLOCK_{port}"

MAX_ACTION_HISTORY = 50

_FIREWALL_SERVICE_NAMES = ("mpssvc", "MpsSvc")

_FW_AVAILABLE = "available"
_FW_POWERSHELL_UNAVAILABLE = "powershell_unavailable"
_FW_SERVICE_STOPPED = "service_stopped"
_FW_UNKNOWN = "unknown"

_CACHED_POWERSHELL: Optional[str] = None
_CACHED_FW_STATUS: Dict[str, Any] = {"value": _FW_UNKNOWN, "at": 0.0}
_FW_STATUS_LOCK = threading.Lock()
_FW_STATUS_TTL = 5.0


_MUTATION_LOCKS: Dict[str, threading.Lock] = {}
_SNAPSHOT_LOCKS: Dict[str, threading.Lock] = {}
_LOCKS_MUTEX = threading.Lock()


def _get_mutation_lock(lock_key: str) -> threading.Lock:
    with _LOCKS_MUTEX:
        if lock_key not in _MUTATION_LOCKS:
            _MUTATION_LOCKS[lock_key] = threading.Lock()
        return _MUTATION_LOCKS[lock_key]


def _get_snapshot_lock(lock_key: str) -> threading.Lock:
    with _LOCKS_MUTEX:
        if lock_key not in _SNAPSHOT_LOCKS:
            _SNAPSHOT_LOCKS[lock_key] = threading.Lock()
        return _SNAPSHOT_LOCKS[lock_key]


_SETUP_DONE: Set[Tuple[str, int, int]] = set()
_SETUP_DONE_LOCK = threading.Lock()


def _setup_done(fp: Tuple[str, int, int]) -> bool:
    with _SETUP_DONE_LOCK:
        return fp in _SETUP_DONE


def _mark_setup_done(fp: Tuple[str, int, int]) -> None:
    with _SETUP_DONE_LOCK:
        _SETUP_DONE.add(fp)


_CONFIG_CACHE: Dict[str, Any] = {"mtime": 0.0, "data": {}}
_CONFIG_CACHE_LOCK = threading.Lock()


def _system_config_path() -> str:
    return os.path.join(_ROOT, "system_config.json")


def _load_system_config_cached() -> Dict:
    try:
        path = _system_config_path()
        mtime = os.path.getmtime(path)
    except Exception:
        return {}
    with _CONFIG_CACHE_LOCK:
        if (mtime == _CONFIG_CACHE.get("mtime")
                and isinstance(_CONFIG_CACHE.get("data"), dict)):
            return _CONFIG_CACHE["data"]
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if not isinstance(data, dict):
            data = {}
    except Exception:
        data = {}
    with _CONFIG_CACHE_LOCK:
        _CONFIG_CACHE["mtime"] = mtime
        _CONFIG_CACHE["data"] = data
    return data


def _coerce_int(value: Any, default: int,
                minimum: int, maximum: int) -> int:
    if isinstance(value, bool):
        return default
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    if n < minimum or n > maximum:
        return default
    return n


def _coerce_bool(value: Any, default: bool) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("1", "true", "yes", "on"):
            return True
        if v in ("0", "false", "no", "off"):
            return False
    return default


def _resolve_service_ports(capability: str) -> List[int]:
    """
    Cost: file stat (cached). No subprocesses.

    Falls back to port_registry when the config field is missing,
    mirroring response_engine._resolve_service_ports' fallback to
    _DEFAULT_SERVICE_PORTS. Without this fallback, MTD traffic_shuffle
    silently fails to construct (supports() returns False) when a
    fresh config_interactive run or any config gap omits
    capability_rules.<cap>.service_ports.
    """
    cfg = _load_system_config_cached()
    rules = cfg.get("capability_rules", {})
    if isinstance(rules, dict):
        entry = rules.get(capability)
        if isinstance(entry, dict):
            raw = entry.get("service_ports")
            if isinstance(raw, list):
                out: List[int] = []
                for p in raw:
                    try:
                        n = int(p)
                    except (TypeError, ValueError):
                        continue
                    if 1 <= n <= 65535 and n not in out:
                        out.append(n)
                if out:
                    return out
    fallback = port_registry.primary_port(capability)
    return [fallback] if fallback > 0 else []


def _resolve_shuffle_config(capability: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "enabled": _coerce_bool(
            getattr(Config, "SHUFFLE_ENABLED_DEFAULT", False)
            if _CONFIG_AVAILABLE else False,
            False),
        "primary_port": port_registry.primary_port(capability),
        "alternate_port": port_registry.alternate_port(capability),
        "trigger_distinct_attackers": _coerce_int(
            getattr(Config, "SHUFFLE_TRIGGER_DISTINCT_ATTACKERS", 3)
            if _CONFIG_AVAILABLE else 3,
            DEFAULT_TRIGGER_DISTINCT_ATTACKERS, 1, 1000),
        "trigger_red_seconds": _coerce_int(
            getattr(Config, "SHUFFLE_TRIGGER_RED_SECONDS", 300)
            if _CONFIG_AVAILABLE else 300,
            DEFAULT_TRIGGER_RED_SECONDS, 5, 86400),
        "restore_after_seconds": _coerce_int(
            getattr(Config, "SHUFFLE_RESTORE_AFTER_SECONDS", 1800)
            if _CONFIG_AVAILABLE else 1800,
            DEFAULT_RESTORE_AFTER_SECONDS, 30, 604800),
        "min_seconds_between_flips": _coerce_int(
            getattr(Config, "SHUFFLE_MIN_SECONDS_BETWEEN_FLIPS", 60)
            if _CONFIG_AVAILABLE else 60,
            DEFAULT_MIN_SECONDS_BETWEEN_FLIPS, 0, 3600),
    }

    cfg = _load_system_config_cached()
    rules = cfg.get("capability_rules", {})
    if not isinstance(rules, dict):
        return out
    entry = rules.get(capability)
    if not isinstance(entry, dict):
        return out
    shuffle = entry.get("shuffle")
    if not isinstance(shuffle, dict):
        cap_layers = cfg.get("capability_layers", {}).get(capability, [])
        if isinstance(cap_layers, list) and "layer4c" in cap_layers:
            out["enabled"] = True
            return out

    if "enabled" in shuffle:
        out["enabled"] = _coerce_bool(shuffle["enabled"], out["enabled"])
    if "primary_port" in shuffle:
        out["primary_port"] = _coerce_int(
            shuffle["primary_port"], out["primary_port"], 1, 65535)
    if "alternate_port" in shuffle:
        out["alternate_port"] = _coerce_int(
            shuffle["alternate_port"], out["alternate_port"], 1, 65535)
    if "trigger_distinct_attackers" in shuffle:
        out["trigger_distinct_attackers"] = _coerce_int(
            shuffle["trigger_distinct_attackers"],
            out["trigger_distinct_attackers"], 1, 1000)
    if "trigger_red_seconds" in shuffle:
        out["trigger_red_seconds"] = _coerce_int(
            shuffle["trigger_red_seconds"],
            out["trigger_red_seconds"], 5, 86400)
    if "restore_after_seconds" in shuffle:
        out["restore_after_seconds"] = _coerce_int(
            shuffle["restore_after_seconds"],
            out["restore_after_seconds"], 30, 604800)
    if "min_seconds_between_flips" in shuffle:
        out["min_seconds_between_flips"] = _coerce_int(
            shuffle["min_seconds_between_flips"],
            out["min_seconds_between_flips"], 0, 3600)

    return out


def _is_admin() -> bool:
    if os.name != "nt":
        return True
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _run_netsh(args: List[str],
               timeout: float = NETSH_TIMEOUT) -> Tuple[bool, str, str]:
    try:
        r = subprocess.run(
            ["netsh"] + args,
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
        return (r.returncode == 0), r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired:
        return False, "", "timeout"
    except Exception as e:
        return False, "", str(e)


def _resolve_powershell() -> Optional[str]:
    global _CACHED_POWERSHELL
    if _CACHED_POWERSHELL is not None:
        return _CACHED_POWERSHELL or None
    for candidate in ("powershell.exe", "powershell", "pwsh.exe", "pwsh"):
        found = shutil.which(candidate)
        if found:
            _CACHED_POWERSHELL = found
            return found
    _CACHED_POWERSHELL = ""
    return None


def _run_ps(cmd: str, timeout: float = PS_TIMEOUT) -> Tuple[bool, str, str]:
    ps = _resolve_powershell()
    if not ps:
        return False, "", "no PowerShell binary found"
    try:
        r = subprocess.run(
            [ps, "-NoProfile", "-NonInteractive", "-Command",
             "$ErrorActionPreference = 'Continue'; " + cmd],
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
        return (r.returncode == 0), r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired:
        return False, "", "timeout"
    except Exception as e:
        return False, "", str(e)


def _firewall_status(use_cache: bool = True) -> str:
    """
    Return one of:
      _FW_AVAILABLE               — reachable and running
      _FW_POWERSHELL_UNAVAILABLE  — no PowerShell binary on PATH
      _FW_SERVICE_STOPPED         — service reports not running
      _FW_UNKNOWN                 — could not determine

    Cost: 0 process spawns when cache hit; up to 2 PowerShell
    spawns on cache miss; plus 1 netsh spawn if the PowerShell
    probes fail to determine status.
    """
    global _CACHED_FW_STATUS
    now = time.time()

    if use_cache:
        with _FW_STATUS_LOCK:
            if (now - _CACHED_FW_STATUS["at"]) < _FW_STATUS_TTL:
                return _CACHED_FW_STATUS["value"]

    if _resolve_powershell() is None:
        result = _FW_POWERSHELL_UNAVAILABLE
        with _FW_STATUS_LOCK:
            _CACHED_FW_STATUS = {"value": result, "at": now}
        return result

    for svc in _FIREWALL_SERVICE_NAMES:
        ok, out, _err = _run_ps(
            f"try {{ "
            f"  (Get-Service -Name '{svc}' -ErrorAction Stop)"
            f"    .Status.ToString() "
            f"}} catch {{ 'unknown' }}"
        )
        if not ok:
            continue
        st = (out or "").strip().lower()
        if st == "running":
            result = _FW_AVAILABLE
            with _FW_STATUS_LOCK:
                _CACHED_FW_STATUS = {"value": result, "at": now}
            return result
        if st and st != "unknown":
            result = _FW_SERVICE_STOPPED
            with _FW_STATUS_LOCK:
                _CACHED_FW_STATUS = {"value": result, "at": now}
            return result

    # G6-1 fallback: PowerShell service enumeration failed on both
    # service names. On some Windows configurations Get-Service
    # returns "unknown" for mpssvc/MpsSvc even though the firewall
    # is functional and netsh can manipulate rules. Ask netsh
    # directly. If netsh can respond to a firewall query, the
    # firewall subsystem is operational and rule operations will
    # succeed regardless of what Get-Service reported.
    ok, out, _err = _run_netsh(
        ["advfirewall", "show", "allprofiles", "state"])
    if ok and (out or "").strip():
        result = _FW_AVAILABLE
        with _FW_STATUS_LOCK:
            _CACHED_FW_STATUS = {"value": result, "at": now}
        return result

    result = _FW_UNKNOWN
    with _FW_STATUS_LOCK:
        _CACHED_FW_STATUS = {"value": result, "at": now}
    return result


def _firewall_status_message(status: str) -> str:
    if status == _FW_AVAILABLE:
        return "Windows Firewall reachable"
    if status == _FW_POWERSHELL_UNAVAILABLE:
        return ("cannot query Windows Firewall: no PowerShell "
                "binary on PATH")
    if status == _FW_SERVICE_STOPPED:
        return "Windows Firewall service is not running"
    return "cannot determine Windows Firewall state"


def _firewall_rule_exists(name: str) -> Optional[bool]:
    status = _firewall_status()
    if status != _FW_AVAILABLE:
        return None
    ok, _out, _err = _run_netsh(
        ["advfirewall", "firewall", "show", "rule", f"name={name}"])
    return ok


def _firewall_add_allow(name: str, port: int) -> Tuple[bool, str]:
    exists = _firewall_rule_exists(name)
    if exists is None:
        return False, _firewall_status_message(_firewall_status())
    if exists:
        return True, ""
    ok, _out, err = _run_netsh([
        "advfirewall", "firewall", "add", "rule",
        f"name={name}",
        "dir=in", "action=allow", "protocol=TCP",
        f"localport={port}", "profile=any",
    ])
    if ok:
        return True, ""
    exists_after = _firewall_rule_exists(name)
    if exists_after is None:
        return False, _firewall_status_message(_firewall_status())
    if exists_after:
        return True, ""
    return False, (err or "add rule failed").strip()[:200]


def _firewall_add_block(name: str, port: int) -> Tuple[bool, str]:
    exists = _firewall_rule_exists(name)
    if exists is None:
        return False, _firewall_status_message(_firewall_status())
    if exists:
        return True, ""
    ok, _out, err = _run_netsh([
        "advfirewall", "firewall", "add", "rule",
        f"name={name}",
        "dir=in", "action=block", "protocol=TCP",
        f"localport={port}", "profile=any",
    ])
    if ok:
        return True, ""
    exists_after = _firewall_rule_exists(name)
    if exists_after is None:
        return False, _firewall_status_message(_firewall_status())
    if exists_after:
        return True, ""
    return False, (err or "add rule failed").strip()[:200]


def _firewall_delete_rule(name: str) -> Tuple[bool, str]:
    exists = _firewall_rule_exists(name)
    if exists is None:
        return False, _firewall_status_message(_firewall_status())
    if not exists:
        return True, ""
    ok, _out, err = _run_netsh([
        "advfirewall", "firewall", "delete", "rule",
        f"name={name}",
    ])
    if ok:
        return True, ""
    exists_after = _firewall_rule_exists(name)
    if exists_after is None:
        return False, _firewall_status_message(_firewall_status())
    if not exists_after:
        return True, ""
    return False, (err or "delete rule failed").strip()[:200]


def _enumerate_allow_rules_for_capability(capability: str) -> List[str]:
    prefix = f"ACF_capability_{capability}_ALLOW_"
    prefix_esc = prefix.replace("'", "''")
    ps = (
        f"Get-NetFirewallRule -DisplayName '{prefix_esc}*' "
        f"-ErrorAction SilentlyContinue | "
        f"ForEach-Object {{ $_.DisplayName }}"
    )
    ok, out, _err = _run_ps(ps)
    if not ok or not out:
        return []
    names: List[str] = []
    for line in out.splitlines():
        ln = line.strip()
        if ln and ln.startswith(prefix):
            names.append(ln)
    return names


_BLACKBOARD_READ_WARN_AT: float = 0.0


def _read_blackboard() -> Dict:
    global _BLACKBOARD_READ_WARN_AT
    try:
        with open(BLACKBOARD_FILE, "r", encoding="utf-8") as f:
            if _LOCK_AVAILABLE:
                acquire_lock(f.fileno(), exclusive=False)
                try:
                    data = json.load(f)
                finally:
                    release_lock(f.fileno())
            else:
                data = json.load(f)
        return data if isinstance(data, dict) else {}
    except Exception as e:
        now = time.time()
        if now - _BLACKBOARD_READ_WARN_AT > 60.0:
            _BLACKBOARD_READ_WARN_AT = now
            _safe_emit("traffic_shuffle", _LAYER, "warn",
                       f"blackboard read failed: "
                       f"{type(e).__name__}: {e}")
        return {}


def _section(bb: Dict, name: str) -> Dict:
    s = bb.get(name, {})
    return s if isinstance(s, dict) else {}


def _allow_rule_name(capability: str, port: int) -> str:
    return _RULE_ALLOW_TEMPLATE.format(cap=capability, port=port)


def _block_rule_name(capability: str, port: int) -> str:
    return _RULE_BLOCK_TEMPLATE.format(cap=capability, port=port)


def _count_distinct_blocked_ips(blocked: Any) -> int:
    if not isinstance(blocked, list):
        return 0
    ips: Set[str] = set()
    for e in blocked:
        if isinstance(e, dict):
            ip = e.get("ip")
            if isinstance(ip, str) and ip:
                ips.add(ip)
        elif isinstance(e, str) and e:
            ips.add(e)
    return len(ips)


class TrafficShuffleAction(MTDAction):
    name = "traffic_shuffle"
    one_shot = False
    requires_admin = True

    @classmethod
    def supports(cls, capability: str, context: Dict[str, Any]) -> bool:
        if not isinstance(capability, str) or not capability:
            return False
        if capability not in port_registry.ALLOCATIONS:
            return False
        ports = _resolve_service_ports(capability)
        return bool(ports)

    def __init__(self, capability: str, context: Dict[str, Any]):
        super().__init__(capability, context)

        self._lock_key: str = f"traffic_shuffle::{capability}"
        self.capability = capability

        service_ports = _resolve_service_ports(capability)
        shuffle = _resolve_shuffle_config(capability)

        self.shuffle_config = shuffle
        self.enabled: bool = bool(shuffle.get("enabled"))
        self.primary_port: int = int(shuffle.get("primary_port") or 0)
        self.alternate_port: int = int(shuffle.get("alternate_port") or 0)
        self.trigger_distinct_attackers: int = int(
            shuffle.get("trigger_distinct_attackers") or 3)
        self.trigger_red_seconds: int = int(
            shuffle.get("trigger_red_seconds") or 300)
        self.restore_after_seconds: int = int(
            shuffle.get("restore_after_seconds") or 1800)
        self.min_seconds_between_flips: int = int(
            shuffle.get("min_seconds_between_flips") or 60)

        if self.primary_port <= 0 and service_ports:
            self.primary_port = service_ports[0]

        self._is_active = False
        self._flipped_at: float = 0.0
        self._flip_time_uncertain: bool = False
        self._flip_reason: str = ""
        self._block_rule_name: str = ""
        self._allow_rules_created: List[str] = []
        self._actions: List[Dict[str, Any]] = []
        self._last_error: str = ""

        self._last_restore_at: float = 0.0

    def _reconcile_from_firewall(self) -> None:
        if self.primary_port <= 0:
            return
        name = _block_rule_name(self.capability, self.primary_port)
        exists = _firewall_rule_exists(name)

        if exists is None:
            msg = _firewall_status_message(_firewall_status())
            with _get_snapshot_lock(self._lock_key):
                self._last_error = msg
            return

        with _get_snapshot_lock(self._lock_key):
            was = self._is_active
            had_time = self._flipped_at > 0

        if not exists:
            with _get_snapshot_lock(self._lock_key):
                self._is_active = False
                self._block_rule_name = ""
                self._flipped_at = 0.0
                self._flip_time_uncertain = False
                self._flip_reason = ""
                self._last_error = ""
            if was:
                _safe_emit(self.capability, _LAYER, "info",
                           "traffic shuffle state reconciled from "
                           "firewall: block rule is gone")
            return

        with _get_snapshot_lock(self._lock_key):
            self._is_active = True
            self._block_rule_name = name
            self._last_error = ""

        if not had_time:
            with _get_snapshot_lock(self._lock_key):
                self._flipped_at = time.time()
                self._flip_time_uncertain = True
            _safe_emit(
                self.capability, _LAYER, "info",
                "traffic shuffle recovered from previous instance; "
                "flip time anchored to process start (Windows "
                "firewall rules do not expose CreationTime)")

    def _cleanup_stale_allow_rules(self) -> None:
        keep = {
            _allow_rule_name(self.capability, self.primary_port),
            _allow_rule_name(self.capability, self.alternate_port),
        }
        for name in _enumerate_allow_rules_for_capability(self.capability):
            if name in keep:
                continue
            ok, err = _firewall_delete_rule(name)
            if not ok:
                _safe_emit(self.capability, _LAYER, "warn",
                           f"could not remove stale allow rule "
                           f"{name}: {err}")
            else:
                _safe_emit(self.capability, _LAYER, "info",
                           f"removed stale allow rule {name}")

    def _do_setup(self) -> Tuple[bool, str]:
        self._cleanup_stale_allow_rules()
        for port in (self.primary_port, self.alternate_port):
            name = _allow_rule_name(self.capability, port)
            ok, err = _firewall_add_allow(name, port)
            if not ok:
                return False, f"allow rule for port {port}: {err}"
            with _get_snapshot_lock(self._lock_key):
                if name not in self._allow_rules_created:
                    self._allow_rules_created.append(name)
        return True, ""

    def preflight(self) -> Tuple[str, str, str]:
        try:
            if not _CONFIG_AVAILABLE:
                return (STATUS_BLOCKED, "",
                        "config module not importable")
            if not _is_admin():
                return (STATUS_BLOCKED, "",
                        "requires elevation (Administrator)")
            if not self.enabled:
                return (STATUS_BLOCKED, "",
                        f"shuffle not enabled for {self.capability}")
            if self.primary_port <= 0:
                return (STATUS_BLOCKED, "",
                        "primary_port not resolvable")
            if self.alternate_port <= 0:
                return (STATUS_BLOCKED, "",
                        "alternate_port not configured")
            if self.primary_port == self.alternate_port:
                return (STATUS_BLOCKED, "",
                        f"primary and alternate port are the same "
                        f"({self.primary_port})")

            effective = port_registry.effective_port_map(
                _load_system_config_cached())
            collision = port_registry.find_collision(effective)
            if collision:
                with _get_snapshot_lock(self._lock_key):
                    self._last_error = (
                        f"port allocation collision: {collision}")
                return (STATUS_BLOCKED, "",
                        f"port allocation collision: {collision}")

            fp = (self.capability, self.primary_port, self.alternate_port)
            if not _setup_done(fp):
                ok, err = self._do_setup()
                if not ok:
                    with _get_snapshot_lock(self._lock_key):
                        self._last_error = f"setup failed: {err}"
                    return (STATUS_BLOCKED, "",
                            f"setup failed: {err}")
                _mark_setup_done(fp)

            self._reconcile_from_firewall()

            return (STATUS_READY, MODE_PRIMARY, "")
        except Exception as e:
            with _get_snapshot_lock(self._lock_key):
                self._last_error = f"preflight error: {e}"
            return (STATUS_BLOCKED, "", f"preflight error: {e}")

    def should_activate(self, state: str) -> bool:
        """
        Two trigger axes, both under RED. Duration check via
        mtd/enabling.py.

        Active branch:  stays active while RED and restore window
                        has not elapsed.
        Not active:     cooldown after last restore, then the
                        enabling time gate, then the attacker-count
                        axis.
        """
        if not self.enabled:
            with _get_snapshot_lock(self._lock_key):
                self._flip_reason = ""
            return False

        now = time.time()

        with _get_snapshot_lock(self._lock_key):
            active = self._is_active
            flipped_at = self._flipped_at
            last_restore = self._last_restore_at

        if active:
            if (state or "").strip().upper() != "RED":
                with _get_snapshot_lock(self._lock_key):
                    self._flip_reason = "state_below_red"
                return False
            if (self.restore_after_seconds > 0
                    and flipped_at > 0
                    and (now - flipped_at) >= self.restore_after_seconds):
                with _get_snapshot_lock(self._lock_key):
                    self._flip_reason = "restore_window_elapsed"
                return False
            with _get_snapshot_lock(self._lock_key):
                self._flip_reason = "active"
            return True

        if (self.min_seconds_between_flips > 0
                and last_restore > 0
                and (now - last_restore) < self.min_seconds_between_flips):
            with _get_snapshot_lock(self._lock_key):
                self._flip_reason = "cooldown_after_restore"
            return False

        enabled, reason = enabling.is_enabled(
            self.capability,
            state_minimums={"RED": self.trigger_red_seconds},
            now=now,
        )
        if not enabled:
            with _get_snapshot_lock(self._lock_key):
                self._flip_reason = reason
            return False

        bb = _read_blackboard()
        response_section = _section(
            bb, f"layer_4a_response_{self.capability}")
        blocked = response_section.get("blocked_ips")
        distinct = _count_distinct_blocked_ips(blocked)
        axis_distinct = distinct >= self.trigger_distinct_attackers

        reasons: List[str] = []
        if axis_distinct:
            reasons.append(f"distinct_attackers={distinct}")
        reasons.append(reason)

        with _get_snapshot_lock(self._lock_key):
            self._flip_reason = ";".join(reasons)
        return True

    def is_active(self) -> bool:
        with _get_snapshot_lock(self._lock_key):
            return self._is_active

    def activate(self) -> Tuple[bool, str]:
        if not _is_admin():
            return False, "requires elevation (Administrator)"

        with _get_mutation_lock(self._lock_key):
            self._reconcile_from_firewall()

            with _get_snapshot_lock(self._lock_key):
                already_active = self._is_active
                reason = self._flip_reason

            if already_active:
                return True, ""

            block_name = _block_rule_name(
                self.capability, self.primary_port)

            ok, err = _firewall_add_block(block_name, self.primary_port)
            if not ok:
                with _get_snapshot_lock(self._lock_key):
                    self._last_error = err
                self._record("activate", False, err,
                             primary_port=self.primary_port,
                             rule=block_name)
                return False, err

            flip_time = time.time()
            uncertain = True

            with _get_snapshot_lock(self._lock_key):
                self._is_active = True
                self._flipped_at = flip_time
                self._flip_time_uncertain = uncertain
                self._block_rule_name = block_name
                self._last_error = ""

            self._record("activate", True, "",
                         primary_port=self.primary_port,
                         alternate_port=self.alternate_port,
                         rule=block_name,
                         reason=reason,
                         flip_time_uncertain=uncertain)
            _safe_emit(self.capability, _LAYER, "info",
                       f"traffic shuffle active: primary "
                       f"{self.primary_port} blocked, alternate "
                       f"{self.alternate_port} reachable ({reason})")
            return True, ""

    def deactivate(self) -> Tuple[bool, str]:
        if not _is_admin():
            return False, "requires elevation (Administrator)"

        with _get_mutation_lock(self._lock_key):
            with _get_snapshot_lock(self._lock_key):
                block_name = self._block_rule_name
            if not block_name and self.primary_port > 0:
                block_name = _block_rule_name(
                    self.capability, self.primary_port)

            ok = True
            err = ""
            if block_name:
                ok, err = _firewall_delete_rule(block_name)

            now = time.time()
            with _get_snapshot_lock(self._lock_key):
                if ok:
                    self._is_active = False
                    self._flipped_at = 0.0
                    self._flip_time_uncertain = False
                    self._flip_reason = ""
                    self._block_rule_name = ""
                    self._last_error = ""
                    self._last_restore_at = now
                else:
                    self._last_error = err

            self._record("deactivate", ok, err,
                         primary_port=self.primary_port,
                         alternate_port=self.alternate_port,
                         rule=block_name or "(none)",
                         deleted=bool(block_name))
            if ok:
                _safe_emit(self.capability, _LAYER, "info",
                           f"traffic shuffle released: primary "
                           f"{self.primary_port} reachable again")
            return ok, err

    def _record(self, action: str, ok: bool, err: str = "",
                **fields) -> None:
        entry = {"ts": time.time(), "action": action, "ok": ok}
        for k, v in fields.items():
            if isinstance(v, str) and len(v) > 200:
                v = v[:200]
            entry[k] = v
        if err:
            entry["error"] = err[:200]
        with _get_snapshot_lock(self._lock_key):
            self._actions.append(entry)
            if len(self._actions) > MAX_ACTION_HISTORY:
                self._actions = self._actions[-MAX_ACTION_HISTORY:]

    def status(self) -> Dict[str, Any]:
        with _get_snapshot_lock(self._lock_key):
            return {
                "backend": "traffic_shuffle",
                "enabled": self.enabled,
                "primary_port": self.primary_port,
                "alternate_port": self.alternate_port,
                "active_port": (
                    self.alternate_port if self._is_active
                    else self.primary_port),
                "active": self._is_active,
                "flipped_at": self._flipped_at,
                "last_restore_at": self._last_restore_at,
                "flip_time_uncertain": self._flip_time_uncertain,
                "flip_reason": self._flip_reason,
                "block_rule_name": self._block_rule_name,
                "allow_rules_created": list(self._allow_rules_created),
                "trigger_distinct_attackers": self.trigger_distinct_attackers,
                "trigger_red_seconds": self.trigger_red_seconds,
                "restore_after_seconds": self.restore_after_seconds,
                "min_seconds_between_flips": self.min_seconds_between_flips,
                "last_error": self._last_error,
                "actions": list(self._actions),
            }