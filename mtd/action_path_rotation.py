#!/usr/bin/env python3
"""
mtd/action_path_rotation.py — Path rotation MTD action.

Moves the log file to a new directory under a stable base directory
and updates system_config.json so the reader follows. Active at RED
only, subject to a sustained-state gate.

LADDER GATE:
  RED must be sustained for trigger_red_seconds before the action
  fires. Duration is read through mtd/enabling.py. The action does
  not compute elapsed time itself.

Config key:
  capability_rules.<cap>.path_rotation.trigger_red_seconds (default 900)

Base-directory stability:
  The base directory must be the same on every rotation, so that
  successive rotations produce sibling directories rather than
  nested ones. Resolution order:
    1. base_dir from context
    2. capability_rules.<cap>.path_rotation.base_dir (persisted)
    3. parent of the current log_path (inferred, persisted on first
       successful rotation)

Requires Administrator, Windows only.
"""

import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import uuid
from typing import Any, Dict, List, Optional, Tuple

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
from mtd import enabling

try:
    from config import Config
    _CONFIG_AVAILABLE = True
except ImportError:
    Config = None
    _CONFIG_AVAILABLE = False

try:
    from platform_utils import (
        acquire_lock, release_lock, get_temp_dir,
    )
    _LOCK_AVAILABLE = True
except ImportError:
    _LOCK_AVAILABLE = False

    def get_temp_dir():
        return "/tmp" if os.name != "nt" else os.environ.get(
            "TEMP", "C:\\Temp")

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

DEFAULT_PATH_PATTERN = "%Y%m%d-%H%M%S"
DEFAULT_MIN_SECONDS_BETWEEN = 60.0
DEFAULT_RENAME_RETRIES = 4
DEFAULT_RENAME_RETRY_DELAY = 0.25
DEFAULT_REMOVE_EMPTY_OLD_DIR = False
DEFAULT_REQUIRE_ACL = False
DEFAULT_CONFIG_LOCK_TIMEOUT = 5.0
DEFAULT_TRIGGER_RED_SECONDS = 900
CONFIG_LOCK_CANCEL_GRACE = 1.0

MAX_PATH_ATTEMPTS = 16
_MAX_PATH_LEN = 240

_PATH_SAFE_RE = re.compile(r"^[A-Za-z0-9._-]+$")

_STRFTIME_RE = {
    "%Y": r"\d{4}",
    "%y": r"\d{2}",
    "%m": r"\d{2}",
    "%d": r"\d{2}",
    "%H": r"\d{2}",
    "%M": r"\d{2}",
    "%S": r"\d{2}",
    "%j": r"\d{3}",
    "%U": r"\d{2}",
    "%W": r"\d{2}",
    "%%": re.escape("%"),
}

_WSA_SHARING_VIOLATION = 32
_WSA_ACCESS_DENIED = 5
_WSA_LOCK_VIOLATION = 33
_WSA_NOT_SAME_DEVICE = 17

_STATE_RED = "RED"

_CONFIG_LOCK_BASENAME = "acf_system_config.lock"


_MUTATION_LOCKS: Dict[str, threading.Lock] = {}
_SNAPSHOT_LOCKS: Dict[str, threading.Lock] = {}
_LOCKS_MUTEX = threading.Lock()

_THREAD_COUNTER_MUTEX = threading.Lock()
_THREAD_COUNTER = [0]


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


def _next_thread_id() -> int:
    with _THREAD_COUNTER_MUTEX:
        _THREAD_COUNTER[0] += 1
        return _THREAD_COUNTER[0]


def _coerce_int(value: Any, default: int,
                minimum: int, maximum: int) -> int:
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    if n < minimum or n > maximum:
        return default
    return n


def _coerce_float(value: Any, default: float,
                  minimum: float, maximum: float) -> float:
    try:
        f = float(value)
    except (TypeError, ValueError):
        return default
    if f < minimum or f > maximum:
        return default
    return f


def _coerce_str(value: Any, default: str) -> str:
    if isinstance(value, str) and value.strip():
        return value.strip()
    return default


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


_CONFIG_CACHE: Dict[str, Any] = {"mtime": 0.0, "data": {}}
_CONFIG_CACHE_LOCK = threading.Lock()


def _load_system_config_cached() -> Dict:
    path = os.path.join(_ROOT, "system_config.json")
    try:
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


def _read_persisted_base_dir(capability: str) -> Optional[str]:
    cfg = _load_system_config_cached()
    if not isinstance(cfg, dict):
        return None
    rules = cfg.get("capability_rules", {})
    if not isinstance(rules, dict):
        return None
    entry = rules.get(capability)
    if not isinstance(entry, dict):
        return None
    pr = entry.get("path_rotation")
    if not isinstance(pr, dict):
        return None
    raw = pr.get("base_dir")
    if not isinstance(raw, str) or not raw.strip():
        return None
    try:
        return os.path.abspath(os.path.realpath(raw.strip()))
    except Exception:
        return os.path.abspath(raw.strip())


def _read_trigger_red_seconds(capability: str) -> int:
    cfg = _load_system_config_cached()
    rules = cfg.get("capability_rules", {})
    if isinstance(rules, dict):
        entry = rules.get(capability)
        if isinstance(entry, dict):
            pr = entry.get("path_rotation")
            if isinstance(pr, dict):
                v = pr.get("trigger_red_seconds")
                try:
                    n = int(v)
                    if n >= 0:
                        return n
                except (TypeError, ValueError):
                    pass
    return DEFAULT_TRIGGER_RED_SECONDS


def _is_unc_like(path: str) -> bool:
    p = (path or "").lstrip()
    return p.startswith("\\\\") or p.startswith("//")


def _is_drive_letter(path: str) -> bool:
    drive, _tail = os.path.splitdrive(path or "")
    return bool(drive) and not _is_unc_like(path)


def _same_volume(path_a: str, path_b: str) -> bool:
    if os.name == "nt":
        drive_a = os.path.splitdrive(os.path.abspath(path_a))[0].lower()
        drive_b = os.path.splitdrive(os.path.abspath(path_b))[0].lower()
        return drive_a == drive_b
    try:
        return os.stat(path_a).st_dev == os.stat(path_b).st_dev
    except OSError:
        return False


def _path_equal(path_a: str, path_b: str) -> bool:
    return (os.path.normcase(os.path.abspath(path_a))
            == os.path.normcase(os.path.abspath(path_b)))


def _is_ancestor_or_equal(ancestor: str, child: str) -> bool:
    a = os.path.normcase(os.path.abspath(ancestor))
    c = os.path.normcase(os.path.abspath(child))
    if a == c:
        return True
    try:
        return os.path.commonpath([a, c]) == a
    except ValueError:
        return False


def _errno_codes(e: BaseException) -> Tuple[int, ...]:
    codes: List[int] = []
    if isinstance(e, OSError):
        we = getattr(e, "winerror", None)
        if isinstance(we, int):
            codes.append(we)
        er = getattr(e, "errno", None)
        if isinstance(er, int):
            codes.append(er)
    return tuple(codes)


def _is_sharing_violation(codes: Tuple[int, ...]) -> bool:
    if os.name == "nt":
        for c in codes:
            if c in (_WSA_SHARING_VIOLATION, _WSA_ACCESS_DENIED,
                     _WSA_LOCK_VIOLATION):
                return True
    else:
        import errno as _e
        for c in codes:
            if c in (_e.EACCES, _e.EBUSY, _e.EAGAIN, _e.EPERM):
                return True
    return False


def _is_cross_device(codes: Tuple[int, ...]) -> bool:
    if os.name == "nt":
        return _WSA_NOT_SAME_DEVICE in codes
    import errno as _e
    return _e.EXDEV in codes


_CACHED_POWERSHELL: Optional[str] = None


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


def _run_ps(cmd: str, timeout: float = 10.0) -> Tuple[int, str, str]:
    ps = _resolve_powershell()
    if not ps:
        return -1, "", "no PowerShell binary found"
    try:
        r = subprocess.run(
            [ps, "-NoProfile", "-NonInteractive", "-Command",
             "$ErrorActionPreference = 'Continue'; " + cmd],
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
        return r.returncode, r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)


def _copy_acl_windows(src: str, dst: str) -> bool:
    src_esc = src.replace("'", "''")
    dst_esc = dst.replace("'", "''")
    cmd = (
        f"try {{ "
        f"  $acl = Get-Acl -LiteralPath '{src_esc}'; "
        f"  Set-Acl -LiteralPath '{dst_esc}' -AclObject $acl; "
        f"  'ok' "
        f"}} catch {{ 'fail: ' + $_.Exception.Message }}"
    )
    rc, out, _err = _run_ps(cmd, timeout=10.0)
    return rc == 0 and "ok" in (out or "")


def _copy_acl_posix(src: str, dst: str) -> bool:
    try:
        st = os.stat(src)
        os.chmod(dst, st.st_mode & 0o7777)
        try:
            os.chown(dst, st.st_uid, st.st_gid)
        except (PermissionError, OSError, AttributeError):
            pass
        return True
    except Exception:
        return False


def _copy_acl(src: str, dst: str) -> bool:
    if os.name == "nt":
        return _copy_acl_windows(src, dst)
    return _copy_acl_posix(src, dst)


def _sanitize_path_component(raw: str) -> str:
    if not isinstance(raw, str) or not raw:
        return ""
    cleaned = "".join(
        ch for ch in raw
        if (ch.isascii() and ch.isalnum()) or ch in "._-"
    )
    if not cleaned or not _PATH_SAFE_RE.match(cleaned):
        return ""
    return cleaned


def _strftime_to_regex(fmt: str) -> Tuple[Optional[str], str]:
    if not isinstance(fmt, str) or not fmt:
        return None, ""
    parts: List[str] = []
    i = 0
    while i < len(fmt):
        ch = fmt[i]
        if ch == "%" and i + 1 < len(fmt):
            token = fmt[i:i + 2]
            if token in _STRFTIME_RE:
                parts.append(_STRFTIME_RE[token])
            else:
                return None, token
            i += 2
        else:
            parts.append(re.escape(ch))
            i += 1
    return "".join(parts), ""


class PathRotationAction(MTDAction):
    name = "path_rotation"
    one_shot = True
    requires_admin = False

    @classmethod
    def supports(cls, capability: str, context: Dict[str, Any]) -> bool:
        ctx = context if isinstance(context, dict) else {}
        path = ctx.get("log_path")
        return isinstance(path, str) and bool(path.strip())

    def __init__(self, capability: str, context: Dict[str, Any]):
        super().__init__(capability, context)

        ctx: Dict[str, Any] = context if isinstance(context, dict) else {}

        raw_log_path = _coerce_str(ctx.get("log_path"), "")
        if raw_log_path:
            try:
                self.log_path: str = os.path.abspath(
                    os.path.realpath(raw_log_path))
            except Exception:
                self.log_path = os.path.abspath(raw_log_path)
        else:
            self.log_path = ""

        if self.log_path:
            self._lock_key: str = f"path_rotation::{self.log_path}"
        else:
            self._lock_key = f"path_rotation::{capability}"

        raw_base = ctx.get("base_dir")
        self.base_dir: Optional[str] = None
        base_source = "none"
        if isinstance(raw_base, str) and raw_base.strip():
            try:
                self.base_dir = os.path.abspath(
                    os.path.realpath(raw_base.strip()))
            except Exception:
                self.base_dir = os.path.abspath(raw_base.strip())
            base_source = "context"
        else:
            persisted = _read_persisted_base_dir(capability)
            if persisted:
                self.base_dir = persisted
                base_source = "config"
        self._base_dir_source: str = base_source

        self.path_pattern: str = _coerce_str(
            ctx.get("path_pattern"), DEFAULT_PATH_PATTERN,
        )

        raw_cfg = _coerce_str(ctx.get("config_path"),
                              "system_config.json")
        try:
            self.config_path: str = os.path.abspath(
                os.path.realpath(raw_cfg))
        except Exception:
            self.config_path = os.path.abspath(raw_cfg)

        self.remove_empty_old_dir: bool = _coerce_bool(
            ctx.get("remove_empty_old_dir"),
            DEFAULT_REMOVE_EMPTY_OLD_DIR,
        )
        self.require_acl_preservation: bool = _coerce_bool(
            ctx.get("require_acl_preservation"), DEFAULT_REQUIRE_ACL,
        )
        self.min_seconds_between_rotations: float = _coerce_float(
            ctx.get("min_seconds_between_rotations"),
            DEFAULT_MIN_SECONDS_BETWEEN, 0.0, 3600.0,
        )
        self.rename_retries: int = _coerce_int(
            ctx.get("rename_retries"),
            DEFAULT_RENAME_RETRIES, 0, 20,
        )
        self.rename_retry_delay: float = _coerce_float(
            ctx.get("rename_retry_delay"),
            DEFAULT_RENAME_RETRY_DELAY, 0.0, 10.0,
        )
        self.config_lock_timeout: float = _coerce_float(
            ctx.get("config_lock_timeout"),
            DEFAULT_CONFIG_LOCK_TIMEOUT, 0.5, 60.0,
        )

        fmt_re, unsupported = _strftime_to_regex(self.path_pattern)
        self._path_pattern_regex: Optional[str] = fmt_re
        self._unsupported_directive: str = unsupported

        # Ladder gate.
        self.trigger_red_seconds: int = _read_trigger_red_seconds(
            capability)
        self._gate_reason: str = ""

        self._init_warnings: List[str] = []
        self._check_warnings: List[str] = []

        self._last_state: str = ""
        self._last_rotation_ts: float = 0.0
        self._rotations_total: int = 0
        self._last_rotation_info: Dict[str, Any] = {}
        self._actions: List[Dict[str, Any]] = []
        self._preflight_reason: str = ""
        self._reader_restart_required: bool = False
        self._reader_restart_reason: str = ""
        self._reader_restart_at: float = 0.0
        self._config_state_uncertain: bool = False
        self._config_state_uncertain_reason: str = ""
        self._config_state_uncertain_at: float = 0.0

        self._config_lock_file: str = os.path.join(
            get_temp_dir(), _CONFIG_LOCK_BASENAME)

        self._check_environment()

    def _check_environment(self) -> None:
        self._preflight_reason = ""
        self._check_warnings = []

        if not self.log_path:
            self._preflight_reason = "no log_path provided"
            return

        if not _CONFIG_AVAILABLE:
            self._preflight_reason = (
                "config module is not importable; cannot determine "
                "whether capability is hardcoded or custom"
            )
            return

        if self._path_pattern_regex is None:
            self._preflight_reason = (
                f"path_pattern {self.path_pattern!r} uses an "
                f"unsupported directive "
                f"{self._unsupported_directive or '<unknown>'}; "
                f"choose a format from "
                f"{', '.join(sorted(_STRFTIME_RE.keys()))}"
            )
            return

        try:
            sample = time.strftime(self.path_pattern)
        except (ValueError, TypeError) as e:
            self._preflight_reason = f"invalid path_pattern: {e}"
            return
        if not sample:
            self._preflight_reason = (
                "path_pattern produced an empty string"
            )
            return
        if _sanitize_path_component(sample) != sample:
            self._preflight_reason = (
                f"path_pattern produces characters that cannot be "
                f"used in a directory name: {sample!r}"
            )
            return

        if not os.path.exists(self.log_path):
            self._preflight_reason = (
                f"log path does not exist: {self.log_path}"
            )
            return
        if os.path.isdir(self.log_path):
            self._preflight_reason = (
                f"log path is a directory: {self.log_path}"
            )
            return
        if not os.path.isfile(self.log_path):
            self._preflight_reason = (
                f"log path is not a regular file: {self.log_path}"
            )
            return

        old_dir = os.path.dirname(self.log_path)
        if not os.access(old_dir, os.W_OK):
            self._preflight_reason = (
                f"log directory not writable: {old_dir}"
            )
            return

        effective_base = self.base_dir or old_dir
        if not os.path.isdir(effective_base):
            self._preflight_reason = (
                f"base_dir does not exist: {effective_base}"
            )
            return
        if not os.access(effective_base, os.W_OK):
            self._preflight_reason = (
                f"base_dir not writable: {effective_base}"
            )
            return

        if os.name == "nt":
            mixed = ((_is_drive_letter(self.log_path)
                      and _is_unc_like(effective_base))
                     or (_is_unc_like(self.log_path)
                         and _is_drive_letter(effective_base)))
            if mixed:
                self._check_warnings.append(
                    "log_path and base_dir mix a drive letter and a "
                    "UNC path; on Windows these are treated as "
                    "different volumes even when they resolve to the "
                    "same share. Use consistent path forms."
                )

        try:
            if not _same_volume(self.log_path, effective_base):
                self._preflight_reason = (
                    f"log path and base_dir are on different "
                    f"volumes: {self.log_path} vs {effective_base}"
                )
                return
        except OSError:
            pass

        if not os.path.isfile(self.config_path):
            self._preflight_reason = (
                f"config_path does not exist: {self.config_path}"
            )
            return
        config_dir = os.path.dirname(self.config_path)
        if config_dir and not os.access(config_dir, os.W_OK):
            self._preflight_reason = (
                f"config directory not writable: {config_dir}"
            )
            return

        if not _LOCK_AVAILABLE:
            self._check_warnings.append(
                "platform_utils not available; config writes will "
                "not be serialized against the console"
            )

        if os.name == "nt" and not _resolve_powershell():
            self._check_warnings.append(
                "no PowerShell binary found; new directory and "
                "config file will inherit the parent default ACL"
            )

    def preflight(self) -> Tuple[str, str, str]:
        self._check_environment()
        if self._preflight_reason:
            return (STATUS_BLOCKED, "", self._preflight_reason)
        return (STATUS_READY, MODE_PRIMARY, "")

    def should_activate(self, state: str) -> bool:
        """
        RED must be sustained for trigger_red_seconds before the
        action fires. Duration is evaluated by mtd/enabling.py.

        The state value is remembered for the activate() call,
        which reads it to decide whether to proceed or no-op.
        """
        if not isinstance(state, str):
            state = ""
        normalized = state.strip().upper()
        with _get_snapshot_lock(self._lock_key):
            self._last_state = normalized

        enabled, reason = enabling.is_enabled(
            self.capability,
            state_minimums={"RED": self.trigger_red_seconds},
        )
        with _get_snapshot_lock(self._lock_key):
            self._gate_reason = reason
        return enabled

    def is_active(self) -> bool:
        return False

    def acknowledge_reader_restart(self) -> Tuple[bool, str]:
        with _get_snapshot_lock(self._lock_key):
            was = self._reader_restart_required
            self._reader_restart_required = False
            self._reader_restart_reason = ""
        return True, "cleared" if was else "was not set"

    def acknowledge_config_reconciled(self) -> Tuple[bool, str]:
        with _get_snapshot_lock(self._lock_key):
            was = self._config_state_uncertain
            self._config_state_uncertain = False
            self._config_state_uncertain_reason = ""
        return True, "cleared" if was else "was not set"

    def activate(self) -> Tuple[bool, str]:
        with _get_mutation_lock(self._lock_key):
            if self._path_pattern_regex is None:
                return False, (
                    f"path_pattern {self.path_pattern!r} uses an "
                    f"unsupported directive "
                    f"{self._unsupported_directive or '<unknown>'}"
                )

            with _get_snapshot_lock(self._lock_key):
                state = self._last_state

            if not state:
                return False, (
                    "should_activate() must be called before "
                    "activate()")
            if state != _STATE_RED:
                self._record_locked("path_rotation", True, "",
                                    state=state,
                                    noop_reason="state_not_red")
                return True, ""

            now = time.time()
            with _get_snapshot_lock(self._lock_key):
                last_ts = self._last_rotation_ts
            if (self.min_seconds_between_rotations > 0
                    and (now - last_ts)
                    < self.min_seconds_between_rotations):
                self._record_locked(
                    "path_rotation", True, "", state=state,
                    noop_reason="rate_limited",
                    seconds_since_last=round(now - last_ts, 3),
                )
                return True, ""

            if not self.log_path:
                return False, "no log_path provided"
            if not os.path.exists(self.log_path):
                return False, (
                    f"log path does not exist: {self.log_path}"
                )
            if os.path.isdir(self.log_path):
                return False, (
                    f"log path is a directory: {self.log_path}"
                )
            if not os.path.isfile(self.log_path):
                return False, (
                    f"log path is not a regular file: {self.log_path}"
                )

            was_base_inferred = self.base_dir is None
            effective_base = (self.base_dir
                              or os.path.dirname(self.log_path))
            try:
                if not _same_volume(self.log_path, effective_base):
                    return False, (
                        "log path and base_dir are on different "
                        "volumes"
                    )
            except OSError:
                pass

            ok, err, info = self._perform_rotation(
                effective_base,
                persist_base_dir=was_base_inferred)

            with _get_snapshot_lock(self._lock_key):
                self._record_locked(
                    "path_rotation", ok, err, state=state, **info,
                )
                if ok:
                    self._last_rotation_ts = time.time()
                    self._rotations_total += 1
                    self._last_rotation_info = dict(info)
                    self._reader_restart_required = True
                    self._reader_restart_at = time.time()
                    self._reader_restart_reason = (
                        "log path changed in system_config.json; "
                        "reader must restart to pick up the new path"
                    )
                    self._config_state_uncertain = False
                    self._config_state_uncertain_reason = ""
                    if was_base_inferred:
                        self.base_dir = effective_base

            if ok:
                _safe_emit(self.capability, _LAYER, "info",
                           f"path rotated: {info.get('old_path')} -> "
                           f"{info.get('new_path')}")
            else:
                _safe_emit(self.capability, _LAYER, "error",
                           f"path rotation failed: {err}")
            return ok, err

    def deactivate(self) -> Tuple[bool, str]:
        return True, ""

    def _perform_rotation(self,
                          base_dir: str,
                          persist_base_dir: bool = False
                          ) -> Tuple[bool, str, Dict[str, Any]]:
        info: Dict[str, Any] = {}

        old_path = self.log_path
        old_dir = os.path.dirname(old_path)
        basename = os.path.basename(old_path)

        new_path, reason = self._compute_new_path(base_dir, basename,
                                                  old_path)
        if new_path is None:
            return False, reason or "no new path", info
        new_dir = os.path.dirname(new_path)
        info["old_path"] = old_path
        info["new_path"] = new_path
        info["effective_base_dir"] = base_dir

        try:
            os.makedirs(new_dir, exist_ok=False)
        except FileExistsError:
            return False, f"new directory already exists: {new_dir}", info
        except OSError as e:
            return False, f"mkdir failed: {e}", info

        acl_ok = _copy_acl(old_dir, new_dir)
        if not acl_ok:
            _safe_emit(self.capability, _LAYER, "warn",
                       f"could not copy directory ACL from {old_dir} "
                       f"to {new_dir}")
        info["acl_preserved"] = acl_ok

        if not acl_ok and self.require_acl_preservation:
            removed, rm_reason = self._try_rmdir_empty(new_dir)
            info["new_dir_cleanup_ok"] = removed
            if not removed:
                info["new_dir_cleanup_error"] = rm_reason
            msg = (
                "ACL preservation required but could not be applied"
            )
            if not removed:
                msg += f"; leftover directory: {new_dir} ({rm_reason})"
            return False, msg, info

        ok, err, cross_device = self._rename_with_retry(old_path, new_path)
        if not ok:
            self._try_rmdir_empty(new_dir)
            if cross_device:
                return False, (
                    "move crossed a filesystem boundary "
                    "(deploy base_dir on the same volume)"
                ), info
            return False, f"move failed: {err}", info

        info["moved"] = True

        base_to_persist: Optional[str] = (
            base_dir if persist_base_dir else None)
        info["base_dir_persisted"] = bool(base_to_persist)
        if base_to_persist:
            info["base_dir_written"] = base_to_persist

        cfg_ok, cfg_err, cfg_old, cfg_outcome = self._update_config(
            new_path, base_to_persist)
        info["config_write_outcome"] = cfg_outcome

        if not cfg_ok:
            if cfg_outcome == "uncertain":
                info["config_state_uncertain"] = True
                with _get_snapshot_lock(self._lock_key):
                    self._config_state_uncertain = True
                    self._config_state_uncertain_reason = cfg_err
                    self._config_state_uncertain_at = time.time()
                return False, (
                    f"config write outcome uncertain: {cfg_err}; "
                    f"file left at {new_path}; engine must "
                    f"reconcile"
                ), info

            rb_ok, rb_err, _rb_cross = self._rename_with_retry(
                new_path, old_path)
            info["file_rollback_ok"] = rb_ok
            if rb_ok:
                self._try_rmdir_empty(new_dir)
                return False, (
                    f"config update failed: {cfg_err} (moved back)"
                ), info
            info["file_rollback_error"] = rb_err[:200]
            return False, (
                f"config update failed: {cfg_err}; file rollback "
                f"also failed: {rb_err}; file stranded at {new_path}"
            ), info

        info["config_updated"] = True
        info["config_previous_path"] = cfg_old or ""

        info["old_dir_removed"] = False
        info["old_dir_removal_reason"] = "not_requested"
        if self.remove_empty_old_dir:
            if _is_ancestor_or_equal(old_dir, base_dir):
                info["old_dir_removal_reason"] = (
                    "old_dir is base_dir or an ancestor of base_dir"
                )
            else:
                removed, rm_reason = self._try_rmdir_empty(old_dir)
                info["old_dir_removed"] = removed
                info["old_dir_removal_reason"] = (
                    "removed" if removed else rm_reason
                )

        return True, "", info

    def _compute_new_path(self, base_dir: str, basename: str,
                          old_path: str
                          ) -> Tuple[Optional[str], str]:
        for attempt in range(MAX_PATH_ATTEMPTS):
            try:
                raw_sub = time.strftime(self.path_pattern)
            except (ValueError, TypeError) as e:
                return None, f"strftime failed: {e}"
            if attempt > 0:
                raw_sub = f"{raw_sub}.{attempt}"
            safe_sub = _sanitize_path_component(raw_sub)
            if not safe_sub:
                continue
            candidate_dir = os.path.join(base_dir, safe_sub)
            candidate = os.path.join(candidate_dir, basename)
            if _path_equal(candidate, old_path):
                continue
            if len(candidate) > _MAX_PATH_LEN:
                return None, (
                    f"candidate path length {len(candidate)} "
                    f"exceeds {_MAX_PATH_LEN}: {candidate}"
                )
            if not os.path.exists(candidate) and \
               not os.path.exists(candidate_dir):
                return candidate, ""
        return None, (
            f"path generation failed after {MAX_PATH_ATTEMPTS} attempts"
        )

    def _rename_with_retry(self, src: str, dst: str
                           ) -> Tuple[bool, str, bool]:
        last_err = ""
        attempts = self.rename_retries + 1
        for attempt in range(attempts):
            try:
                os.replace(src, dst)
                return True, "", False
            except OSError as e:
                codes = _errno_codes(e)
                last_err = f"{e} (codes={codes})"
                if _is_cross_device(codes):
                    return False, last_err, True
                if _is_sharing_violation(codes) and \
                   attempt + 1 < attempts:
                    delay = self.rename_retry_delay * (2 ** attempt)
                    time.sleep(delay)
                    continue
                return False, last_err, False
            except Exception as e:
                return False, str(e), False
        return False, last_err or "rename failed", False

    @staticmethod
    def _try_rmdir_empty(path: str) -> Tuple[bool, str]:
        try:
            if not os.path.isdir(path):
                return False, "not_a_directory"
            if os.listdir(path):
                return False, "not_empty"
            os.rmdir(path)
            return True, "removed"
        except PermissionError as e:
            return False, f"permission: {e}"
        except OSError as e:
            return False, f"oserror: {e}"
        except Exception as e:
            return False, f"unexpected: {e}"

    def _update_config(
        self,
        new_path: str,
        base_dir_to_persist: Optional[str] = None,
    ) -> Tuple[bool, str, Optional[str], str]:
        done = threading.Event()
        cancel = threading.Event()
        result: List[Tuple[bool, str, Optional[str], str]] = []

        def worker():
            try:
                r = self._update_config_locked(
                    new_path, cancel, base_dir_to_persist)
            except Exception as e:
                r = (False, f"worker exception: {e}", None, "uncertain")
            result.append(r)
            done.set()

        tid = _next_thread_id()
        t = threading.Thread(
            target=worker, daemon=True,
            name=f"path-rot-config-{os.getpid()}-{tid}",
        )
        t.start()
        done.wait(timeout=self.config_lock_timeout)

        if done.is_set():
            return result[0]

        cancel.set()
        done.wait(timeout=CONFIG_LOCK_CANCEL_GRACE)

        if done.is_set():
            ok, err, old, outcome = result[0]
            if (not ok
                    and outcome == "resolved"
                    and "cancelled" in (err or "")):
                return (False,
                        f"config lock busy (timeout "
                        f"{self.config_lock_timeout}s)",
                        old, "resolved")
            return result[0]

        return (False,
                f"config lock busy (timeout "
                f"{self.config_lock_timeout}s)",
                None, "uncertain")

    def _update_config_locked(
        self,
        new_path: str,
        cancel: threading.Event,
        base_dir_to_persist: Optional[str],
    ) -> Tuple[bool, str, Optional[str], str]:
        if not _LOCK_AVAILABLE:
            return self._update_config_unlocked(
                new_path, cancel, base_dir_to_persist)

        try:
            os.makedirs(os.path.dirname(self._config_lock_file),
                        exist_ok=True)
            lf = open(self._config_lock_file, "a+")
        except Exception as e:
            return (False, f"cannot open config lock: {e}", None,
                    "resolved")

        try:
            try:
                acquire_lock(lf.fileno(), exclusive=True)
            except Exception as e:
                return (False, f"cannot acquire config lock: {e}",
                        None, "resolved")

            if cancel.is_set():
                return (False, "cancelled before write", None,
                        "resolved")

            try:
                return self._update_config_unlocked(
                    new_path, cancel, base_dir_to_persist)
            finally:
                try:
                    release_lock(lf.fileno())
                except Exception:
                    pass
        finally:
            try:
                lf.close()
            except Exception:
                pass

    def _update_config_unlocked(
        self,
        new_path: str,
        cancel: threading.Event,
        base_dir_to_persist: Optional[str],
    ) -> Tuple[bool, str, Optional[str], str]:
        try:
            with open(self.config_path, "rb") as f:
                original_bytes = f.read()
        except Exception as e:
            return (False, f"cannot read config: {e}", None,
                    "resolved")

        try:
            data = json.loads(original_bytes.decode("utf-8"))
        except Exception as e:
            return (False, f"cannot parse config: {e}", None,
                    "resolved")

        if not isinstance(data, dict):
            return (False, "config is not a JSON object", None,
                    "resolved")

        cap = self.capability
        paths = data.get("capability_paths")
        if not isinstance(paths, dict):
            paths = {}
            data["capability_paths"] = paths

        is_hardcoded = False
        if _CONFIG_AVAILABLE and Config is not None:
            try:
                is_hardcoded = cap in Config.SERVICE_MAP
            except Exception:
                return (False, (
                    "cannot determine if capability is hardcoded "
                    "(Config.SERVICE_MAP inaccessible)"
                ), None, "resolved")
        else:
            return (False, (
                "Config module unavailable; cannot determine "
                "capability home"
            ), None, "resolved")

        old_value: Optional[str] = None
        if is_hardcoded:
            existing = paths.get(cap)
            if existing is not None and not isinstance(existing, str):
                return (False, (
                    f"capability_paths.{cap} exists and is not a "
                    f"string; refusing to overwrite"
                ), None, "resolved")
            if isinstance(existing, str):
                old_value = existing
            paths[cap] = new_path
        else:
            custom = paths.get("custom")
            if custom is not None and not isinstance(custom, dict):
                return (False, (
                    "capability_paths.custom exists and is not an "
                    "object; refusing to overwrite"
                ), None, "resolved")
            if not isinstance(custom, dict):
                custom = {}
                paths["custom"] = custom
            existing_custom = custom.get(cap)
            if existing_custom is not None and \
               not isinstance(existing_custom, str):
                return (False, (
                    f"capability_paths.custom.{cap} exists and is "
                    f"not a string; refusing to overwrite"
                ), None, "resolved")
            if isinstance(existing_custom, str):
                old_value = existing_custom
            if cap in paths and not isinstance(paths[cap], dict):
                if not isinstance(paths[cap], str):
                    return (False, (
                        f"capability_paths.{cap} exists and is not "
                        f"a string; refusing to relocate to custom"
                    ), None, "resolved")
                if old_value is None:
                    old_value = paths[cap]
                del paths[cap]
            custom[cap] = new_path

        if base_dir_to_persist:
            rules = data.get("capability_rules")
            if not isinstance(rules, dict):
                rules = {}
                data["capability_rules"] = rules
            cap_rules = rules.get(cap)
            if not isinstance(cap_rules, dict):
                cap_rules = {}
                rules[cap] = cap_rules
            pr = cap_rules.get("path_rotation")
            if not isinstance(pr, dict):
                pr = {}
                cap_rules["path_rotation"] = pr
            existing_base = pr.get("base_dir")
            if existing_base is not None and \
               not isinstance(existing_base, str):
                return (False, (
                    f"capability_rules.{cap}.path_rotation.base_dir "
                    f"exists and is not a string; refusing to "
                    f"overwrite"
                ), old_value, "resolved")
            pr["base_dir"] = base_dir_to_persist

        tmp = (f"{self.config_path}.tmp.{os.getpid()}."
               f"{uuid.uuid4().hex[:8]}")

        try:
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            try:
                if os.path.exists(tmp):
                    os.remove(tmp)
            except Exception:
                pass
            return (False, f"cannot write config tmp: {e}", old_value,
                    "resolved")

        acl_ok = _copy_acl(self.config_path, tmp)
        if not acl_ok:
            _safe_emit(self.capability, _LAYER, "warn",
                       "config file ACL not preserved on rewrite")

        try:
            with open(tmp, "r", encoding="utf-8") as f:
                verify_temp = json.load(f)
            temp_paths = verify_temp.get("capability_paths", {})
            if is_hardcoded:
                temp_value = temp_paths.get(cap) \
                    if isinstance(temp_paths, dict) else None
            else:
                custom_t = temp_paths.get("custom") \
                    if isinstance(temp_paths, dict) else None
                temp_value = custom_t.get(cap) \
                    if isinstance(custom_t, dict) else None
            if temp_value != new_path:
                self._safe_remove(tmp)
                return (False, (
                    f"temp verification mismatch: expected "
                    f"{new_path!r}, got {temp_value!r}"
                ), old_value, "resolved")
            if base_dir_to_persist:
                temp_rules = verify_temp.get("capability_rules", {})
                temp_pr = (temp_rules.get(cap, {})
                           .get("path_rotation", {})
                           if isinstance(temp_rules, dict) else {})
                if not isinstance(temp_pr, dict) or \
                        temp_pr.get("base_dir") != base_dir_to_persist:
                    self._safe_remove(tmp)
                    return (False, (
                        f"temp verification mismatch on base_dir: "
                        f"expected {base_dir_to_persist!r}, got "
                        f"{temp_pr.get('base_dir')!r}"
                    ), old_value, "resolved")
        except Exception as e:
            self._safe_remove(tmp)
            return (False, f"temp verification read failed: {e}",
                    old_value, "resolved")

        if cancel.is_set():
            self._safe_remove(tmp)
            return (False, "cancelled before replace", None, "resolved")

        try:
            os.replace(tmp, self.config_path)
        except Exception as e:
            self._safe_remove(tmp)
            return (False, f"cannot replace config: {e}", old_value,
                    "resolved")

        if cancel.is_set():
            restore_ok, restore_err = self._restore_bytes(
                original_bytes)
            if not restore_ok:
                return (False, (
                    f"cancelled after replace; restore failed: "
                    f"{restore_err}"
                ), old_value, "uncertain")
            return (False, "cancelled after replace (restored)",
                    old_value, "resolved")

        try:
            with open(self.config_path, "r", encoding="utf-8") as f:
                verify = json.load(f)
        except Exception as e:
            restore_ok, restore_err = self._restore_bytes(
                original_bytes)
            if not restore_ok:
                return (False, (
                    f"verify read failed: {e}; restore failed: "
                    f"{restore_err}"
                ), old_value, "uncertain")
            return (False, (
                f"verify read failed: {e} (restored)"
            ), old_value, "resolved")

        vpaths = verify.get("capability_paths", {})
        v_value = None
        if isinstance(vpaths, dict):
            if is_hardcoded:
                v_value = vpaths.get(cap)
            else:
                custom_v = vpaths.get("custom")
                if isinstance(custom_v, dict):
                    v_value = custom_v.get(cap)

        if v_value != new_path:
            restore_ok, restore_err = self._restore_bytes(
                original_bytes)
            if not restore_ok:
                return (False, (
                    f"verification mismatch: expected "
                    f"{new_path!r}, got {v_value!r}; restore "
                    f"failed: {restore_err}"
                ), old_value, "uncertain")
            return (False, (
                f"verification mismatch: expected {new_path!r}, "
                f"got {v_value!r} (restored)"
            ), old_value, "resolved")

        if base_dir_to_persist:
            vrules = verify.get("capability_rules", {})
            vpr = (vrules.get(cap, {}).get("path_rotation", {})
                   if isinstance(vrules, dict) else {})
            v_base = vpr.get("base_dir") \
                if isinstance(vpr, dict) else None
            if v_base != base_dir_to_persist:
                restore_ok, restore_err = self._restore_bytes(
                    original_bytes)
                if not restore_ok:
                    return (False, (
                        f"base_dir verification mismatch: expected "
                        f"{base_dir_to_persist!r}, got {v_base!r}; "
                        f"restore failed: {restore_err}"
                    ), old_value, "uncertain")
                return (False, (
                    f"base_dir verification mismatch: expected "
                    f"{base_dir_to_persist!r}, got {v_base!r} "
                    f"(restored)"
                ), old_value, "resolved")

        return (True, "", old_value, "resolved")

    def _restore_bytes(self, original_bytes: bytes
                       ) -> Tuple[bool, str]:
        tmp = (f"{self.config_path}.restore.{os.getpid()}."
               f"{uuid.uuid4().hex[:8]}")
        try:
            with open(tmp, "wb") as f:
                f.write(original_bytes)
            _copy_acl(self.config_path, tmp)
            os.replace(tmp, self.config_path)
            return True, ""
        except Exception as e:
            self._safe_remove(tmp)
            return False, str(e)

    @staticmethod
    def _safe_remove(path: str) -> None:
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass

    def _record_locked(self, action: str, ok: bool, err: str = "",
                       **fields) -> None:
        entry = {"ts": time.time(), "action": action, "ok": ok}
        for k, v in fields.items():
            if isinstance(v, str) and len(v) > 200:
                v = v[:200]
            entry[k] = v
        if err:
            entry["error"] = err[:200]
        self._actions.append(entry)
        if len(self._actions) > 50:
            self._actions = self._actions[-50:]

    def status(self) -> Dict[str, Any]:
        with _get_snapshot_lock(self._lock_key):
            return {
                "backend": "path_rotate",
                "log_path": self.log_path,
                "base_dir": self.base_dir or (
                    os.path.dirname(self.log_path) if self.log_path
                    else ""
                ),
                "base_dir_source": self._base_dir_source,
                "path_pattern": self.path_pattern,
                "path_pattern_supported":
                    self._path_pattern_regex is not None,
                "unsupported_directive":
                    self._unsupported_directive,
                "config_path": self.config_path,
                "remove_empty_old_dir": self.remove_empty_old_dir,
                "require_acl_preservation":
                    self.require_acl_preservation,
                "min_seconds_between_rotations":
                    self.min_seconds_between_rotations,
                "config_lock_timeout": self.config_lock_timeout,
                "trigger_red_seconds": self.trigger_red_seconds,
                "gate_reason": self._gate_reason,
                "last_state": self._last_state,
                "last_rotation_ts": self._last_rotation_ts,
                "rotations_total": self._rotations_total,
                "last_rotation_info": dict(self._last_rotation_info),
                "reader_restart_required":
                    self._reader_restart_required,
                "reader_restart_at": self._reader_restart_at,
                "reader_restart_reason":
                    self._reader_restart_reason,
                "config_state_uncertain":
                    self._config_state_uncertain,
                "config_state_uncertain_at":
                    self._config_state_uncertain_at,
                "config_state_uncertain_reason":
                    self._config_state_uncertain_reason,
                "init_warnings": list(self._init_warnings),
                "preflight_warnings": list(self._check_warnings),
                "construction_warnings":
                    list(self._init_warnings) + list(self._check_warnings),
                "actions": list(self._actions),
            }