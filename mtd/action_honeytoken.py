#!/usr/bin/env python3
"""
mtd/action_honeytoken.py - Honeytoken MTD action.

Places a plausible file at the path that path rotation vacated.
Asks the OS to watch the file for any access. On a touch, records
the details to the Blackboard. Response reads the touch and acts.

This file is ASCII-only on purpose. Accented strings in source are
a recurring source of encoding damage when files move between
editors, so every comparison string below is already normalized.

=====================================================================
AUDIT POLICY CHECK
=====================================================================

  preflight() runs auditpol /get /subcategory:<GUID> /r, parses the
  CSV, reads the Inclusion Setting at column index 4, normalizes it
  (lowercase, accents stripped, typographic apostrophes folded,
  whitespace collapsed) and classifies it:

    enabled   Success, or Success and Failure
    disabled  No Auditing, or Failure only
    unknown   auditpol returned no data row
    error     auditpol failed, output malformed, or the text is not
              in any known language table

  What each outcome does to preflight:

    enabled   READY / MODE_PRIMARY
    disabled  BLOCKED. Auditing is CONFIRMED off, so the token would
              sit unwatched. The message names the command to run.
    unknown   READY / MODE_ADAPTED. The token still arms, and the
    error     reason ("audit policy unverified: ...") is visible in
              the action registry and in status(). A check that
              cannot read the policy must not silently disable the
              defence, and must not silently claim success either.

  The classification tables hold post-normalization text only.
  English and French are listed. Any other Windows language falls
  into "error", which arms in adapted mode instead of blocking.

  The full reasoning (command, raw output, rows, value, normalized
  form, result) is written to the log whenever the outcome changes.

  Language-independent alternatives, if a host needs them:
    - set the policy instead of reading it:
        auditpol /set /subcategory:{0CCE921D-69AE-11D9-BED3-505054503030} /success:enable
    - read the numeric Setting Value from an auditpol /backup export.

=====================================================================
WHAT AN ADMIN DOES MANUALLY (the formula)
=====================================================================

  1. Path rotation moves the live log to a new path.
  2. Place a plausible file at the old path.
  3. Set a SACL on that file.
  4. Subscribe to event 4663 and watch for that path.
  5. Wait. The OS watches. The admin does nothing.
  6. When the file is touched, the OS writes 4663 with the access.
  7. Read the event. Write the details to the shared record.
  8. Response reads the shared record and acts.
  9. On release, remove the file and drop the subscription.

=====================================================================
PRE-CONFIGURATION (operator setup, once per host)
=====================================================================

  1. Machine audit policy. File System success auditing must be
     enabled once per host:

        auditpol /set /subcategory:{0CCE921D-69AE-11D9-BED3-505054503030} /success:enable

     The subcategory is referenced by GUID so the command works on
     every OS locale.

  2. The capability's log must be a file, not an eventlog, its
     path_rotation must be configured, and the process that WRITES
     the log must follow the new path. A writer that reopens the old
     path by name will create or touch the file at the old path, and
     that is a false touch on the token.

  3. Optional per-capability overrides in system_config.json:
       capability_rules.<cap>.honeytoken:
         release_after_seconds   - default 3600
         tail_bytes              - default 65536
         release                 - boolean, forces release when true

=====================================================================
WHAT A TOUCH RECORD CONTAINS
=====================================================================

  Event 4663 carries the object name, the account, the process, the
  access list and the access mask. It does NOT carry a source IP.
  The ip_address field of every touch is therefore always empty.
  Identifying a remote source needs a different event (a logon
  event, or event 5145 for network shares). This action does not
  subscribe to those.

Requires Administrator, Windows only.
"""

import csv
import io
import json
import os
import re
import shutil
import subprocess
import sys
import threading
import time
import unicodedata
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
    MODE_ADAPTED,
)

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
    import win32evtlog
    _HAS_WIN32EVTLOG = True
except ImportError:
    win32evtlog = None
    _HAS_WIN32EVTLOG = False

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


# ----------------------------------------------------------------------
# Constants
# ----------------------------------------------------------------------
_LAYER = "layer4c"

BLACKBOARD_FILE = (
    getattr(Config, "BLACKBOARD_FILE", None)
    if _CONFIG_AVAILABLE else None
) or os.path.join(os.environ.get("TEMP", "/tmp"), "acf_state.json")

DEFAULT_RELEASE_AFTER_SECONDS = 3600
DEFAULT_TAIL_BYTES = 65536
MAX_TOUCH_HISTORY = 200
PS_TIMEOUT = 15.0

_EVENT_ID_OBJECT_ACCESS = 4663
_CHANNEL_SECURITY = "Security"
_SUBSCRIPTION_QUERY = f"*[System[({_EVENT_ID_OBJECT_ACCESS})]]"

_EVERYONE_SID = "S-1-1-0"
_FILE_SYSTEM_SUBCATEGORY_GUID = "{0CCE921D-69AE-11D9-BED3-505054503030}"

# Column index of "Inclusion Setting" in the auditpol /r report:
# Machine Name, Policy Target, Subcategory, Subcategory GUID,
# Inclusion Setting, Exclusion Setting.
_INCLUSION_SETTING_COLUMN = 4

# Post-normalization text only. Every string here is lowercase ASCII
# with no accents, because the raw value is normalized before it is
# compared. Do not add accented or capitalized forms: they can never
# match.
#
#   English raw: No Auditing / Success / Failure / Success and Failure
#   French raw:  Pas d'audit / Succes / Echec / Succes et echec
#                (written with accents by Windows)
#
# "aucun audit" is kept as a harmless extra variant.
_AUDIT_TEXT_NONE = ("no auditing", "pas d'audit", "aucun audit")
_AUDIT_TEXT_SUCCESS = ("success", "succes")
_AUDIT_TEXT_FAILURE = ("failure", "echec")
_AUDIT_TEXT_BOTH = ("success and failure", "succes et echec")

_EVT_ACTION_DELIVER = 1
_EVT_RENDER_XML = 1
_EVT_SUBSCRIBE_FUTURE = 1

_STATE_IDLE = "IDLE"
_STATE_ARMED = "ARMED"
_STATE_TRIPPED = "TRIPPED"
_STATE_RELEASED = "RELEASED"

_EMIT_WINDOW_SECONDS = 60.0

_AUDIT_CHECK_TTL = 60.0
_AUDIT_CHECK_CACHE: Dict[str, Any] = {
    "at": 0.0,
    "state": "unknown",
    "detail": "",
}
_AUDIT_CHECK_LOCK = threading.Lock()
_AUDIT_LAST_LOGGED: Dict[str, Any] = {"key": None}

_CACHED_POWERSHELL: Optional[str] = None


# ----------------------------------------------------------------------
# Byte decoding and text normalization
# ----------------------------------------------------------------------
def _decode_output(raw_bytes: bytes) -> str:
    """
    Decode bytes from a Windows console tool. NUL bytes mean UTF-16.
    Otherwise try UTF-8, then Western European ANSI (cp1252), then
    OEM (cp850). Falls back to UTF-8 with replacement.

    Note: cp1252 accepts almost every byte, so cp850 is only reached
    for the few bytes cp1252 leaves undefined. The comparison below
    is run on normalized text, which keeps the common cases working.
    """
    if not raw_bytes:
        return ""
    if b"\x00" in raw_bytes:
        try:
            return raw_bytes.decode("utf-16")
        except (UnicodeDecodeError, LookupError):
            pass
    for enc in ("utf-8", "cp1252", "cp850"):
        try:
            return raw_bytes.decode(enc)
        except (UnicodeDecodeError, LookupError):
            continue
    return raw_bytes.decode("utf-8", errors="replace")


def _normalize_audit_value(value: str) -> str:
    """
    Return the lowercased, accent-stripped form of an auditpol
    Inclusion Setting, ready for comparison against the tuples.

    Typographic apostrophes are folded to an ASCII apostrophe, and
    runs of whitespace (including no-break spaces) collapse to one
    space.
    """
    if not isinstance(value, str):
        return ""
    text = value.strip().lower()
    text = text.replace("\u2019", "'").replace("\u2018", "'")
    text = unicodedata.normalize("NFKD", text)
    text = "".join(c for c in text if not unicodedata.combining(c))
    return " ".join(text.split())


# ----------------------------------------------------------------------
# Lock registry
# ----------------------------------------------------------------------
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


# ----------------------------------------------------------------------
# Config caching
# ----------------------------------------------------------------------
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


# ----------------------------------------------------------------------
# Coercion helpers
# ----------------------------------------------------------------------
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


# ----------------------------------------------------------------------
# Elevation and subprocess
# ----------------------------------------------------------------------
def _is_admin() -> bool:
    if os.name != "nt":
        return True
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


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
            [ps, "-NoProfile", "-NonInteractive",
             "-Command", "$ErrorActionPreference = 'Continue'; " + cmd],
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
        return (r.returncode == 0), r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired:
        return False, "", "timeout"
    except Exception as e:
        return False, "", str(e)


# ----------------------------------------------------------------------
# Audit policy precondition
#
# Returns (state, detail). state is one of:
#   enabled, disabled, unknown, error
#
# The result is cached for _AUDIT_CHECK_TTL seconds. The full trace
# is logged only when the outcome changes, so a steady state does not
# flood the log.
# ----------------------------------------------------------------------
def _log_audit_trace(state: str, detail: str, cmd: List[str],
                     returncode: Any, stdout_text: str,
                     stderr_text: str, rows: List[List[str]],
                     raw_value: str, normalized: str) -> None:
    key = (state, detail, raw_value, normalized)
    with _AUDIT_CHECK_LOCK:
        if _AUDIT_LAST_LOGGED["key"] == key:
            return
        _AUDIT_LAST_LOGGED["key"] = key

    level = "info" if state in ("enabled", "disabled") else "warn"
    _safe_emit("honeytoken", _LAYER, "info",
               f"audit check: command = {cmd}")
    _safe_emit("honeytoken", _LAYER, "info",
               f"audit check: returncode = {returncode}")
    _safe_emit("honeytoken", _LAYER, "info",
               f"audit check: stdout = {stdout_text[:600]!r}")
    if stderr_text.strip():
        _safe_emit("honeytoken", _LAYER, "info",
                   f"audit check: stderr = {stderr_text[:300]!r}")
    _safe_emit("honeytoken", _LAYER, "info",
               f"audit check: rows = {rows!r}")
    _safe_emit("honeytoken", _LAYER, "info",
               f"audit check: raw value = {raw_value!r}, "
               f"normalized = {normalized!r}")
    _safe_emit("honeytoken", _LAYER, "info",
               f"audit check: tuples success={_AUDIT_TEXT_SUCCESS} "
               f"both={_AUDIT_TEXT_BOTH} none={_AUDIT_TEXT_NONE} "
               f"failure={_AUDIT_TEXT_FAILURE}")
    _safe_emit("honeytoken", _LAYER, level,
               f"audit check: RESULT = {state}"
               + (f" ({detail})" if detail else ""))


def _file_system_audit_enabled(use_cache: bool = True
                               ) -> Tuple[str, str]:
    now = time.time()
    if use_cache:
        with _AUDIT_CHECK_LOCK:
            if now - _AUDIT_CHECK_CACHE["at"] < _AUDIT_CHECK_TTL:
                return (_AUDIT_CHECK_CACHE["state"],
                        _AUDIT_CHECK_CACHE["detail"])

    cmd = [
        "auditpol.exe",
        "/get",
        f"/subcategory:{_FILE_SYSTEM_SUBCATEGORY_GUID}",
        "/r",
    ]

    state = "unknown"
    detail = ""
    returncode: Any = None
    stdout_text = ""
    stderr_text = ""
    rows: List[List[str]] = []
    raw_value = ""
    normalized = ""

    try:
        result = subprocess.run(
            cmd, capture_output=True, timeout=PS_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        state = "error"
        detail = "auditpol timed out"
    except FileNotFoundError:
        state = "error"
        detail = "auditpol.exe not found on PATH"
    except Exception as e:
        state = "error"
        detail = f"auditpol invocation raised: {type(e).__name__}: {e}"
    else:
        returncode = result.returncode
        stdout_text = _decode_output(result.stdout or b"")
        stderr_text = _decode_output(result.stderr or b"")

        if result.returncode != 0:
            blob = (stderr_text or stdout_text or "").strip()
            state = "error"
            detail = f"auditpol returned {result.returncode}: {blob[:200]}"
        else:
            try:
                parsed = list(csv.reader(io.StringIO(stdout_text)))
            except Exception as e:
                state = "error"
                detail = f"CSV parse failed: {type(e).__name__}: {e}"
                parsed = []

            if state != "error":
                rows = [r for r in parsed
                        if r and any(c.strip() for c in r)]
                if len(rows) < 2:
                    state = "unknown"
                    detail = (f"auditpol returned {len(rows)} "
                              f"non-empty row(s); expected a header "
                              f"and at least one data row")
                else:
                    data = rows[1]
                    if len(data) <= _INCLUSION_SETTING_COLUMN:
                        state = "error"
                        detail = (f"data row has {len(data)} "
                                  f"column(s); expected at least "
                                  f"{_INCLUSION_SETTING_COLUMN + 1}")
                    else:
                        raw_value = data[_INCLUSION_SETTING_COLUMN].strip()
                        normalized = _normalize_audit_value(raw_value)
                        if (normalized in _AUDIT_TEXT_BOTH
                                or normalized in _AUDIT_TEXT_SUCCESS):
                            state = "enabled"
                            detail = ""
                        elif normalized in _AUDIT_TEXT_NONE:
                            state = "disabled"
                            detail = "inclusion_setting=no auditing"
                        elif normalized in _AUDIT_TEXT_FAILURE:
                            state = "disabled"
                            detail = ("inclusion_setting=failure only; "
                                      "the honeytoken requires success "
                                      "auditing")
                        else:
                            state = "error"
                            detail = (
                                f"unmatched value: raw={raw_value!r} "
                                f"normalized={normalized!r}")

    _log_audit_trace(state, detail, cmd, returncode, stdout_text,
                     stderr_text, rows, raw_value, normalized)

    with _AUDIT_CHECK_LOCK:
        _AUDIT_CHECK_CACHE["at"] = now
        _AUDIT_CHECK_CACHE["state"] = state
        _AUDIT_CHECK_CACHE["detail"] = detail

    return state, detail


# ----------------------------------------------------------------------
# Blackboard reads
# ----------------------------------------------------------------------
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
            _safe_emit("honeytoken", _LAYER, "warn",
                       f"blackboard read failed: "
                       f"{type(e).__name__}: {e}")
        return {}


def _read_section(bb: Dict, name: str) -> Dict:
    s = bb.get(name, {})
    return s if isinstance(s, dict) else {}


def _read_rotation_baton_from(bb: Dict, capability: str
                               ) -> Optional[Tuple[str, str]]:
    section = _read_section(bb, f"layer_4c_mtd_{capability}")
    registry = section.get("action_registry", {})
    if not isinstance(registry, dict):
        return None
    pr = registry.get("path_rotation", {})
    if not isinstance(pr, dict):
        return None
    status = pr.get("status", {})
    if not isinstance(status, dict):
        return None
    info = status.get("last_rotation_info", {})
    if not isinstance(info, dict):
        return None
    old_path = info.get("old_path")
    new_path = info.get("new_path")
    if not (isinstance(old_path, str) and old_path.strip()
            and isinstance(new_path, str) and new_path.strip()):
        return None
    return (old_path, new_path)


def _read_release_requested_from(bb: Dict, capability: str) -> bool:
    cfg = _load_system_config_cached()
    rules = cfg.get("capability_rules", {})
    if isinstance(rules, dict):
        entry = rules.get(capability)
        if isinstance(entry, dict):
            ht = entry.get("honeytoken")
            if isinstance(ht, dict):
                if _coerce_bool(ht.get("release", False), False):
                    return True

    section = _read_section(bb, f"layer_4c_mtd_{capability}")
    registry = section.get("action_registry", {})
    if isinstance(registry, dict):
        ht = registry.get("honeytoken", {})
        if isinstance(ht, dict):
            status = ht.get("status", {})
            if isinstance(status, dict):
                if _coerce_bool(status.get("release_requested", False),
                                False):
                    return True
    return False


# ----------------------------------------------------------------------
# Event XML parser
# ----------------------------------------------------------------------
def _extract_data(xml: str, name: str) -> str:
    if not isinstance(xml, str) or not name:
        return ""
    m = re.search(rf'<Data Name="{re.escape(name)}">([^<]*)</Data>', xml)
    return m.group(1).strip() if m else ""


def _parse_object_access(xml: str) -> Dict[str, str]:
    return {
        "object_name": _extract_data(xml, "ObjectName"),
        "subject_user": _extract_data(xml, "SubjectUserName"),
        "subject_domain": _extract_data(xml, "SubjectDomainName"),
        "process_name": _extract_data(xml, "ProcessName"),
        "process_id": _extract_data(xml, "ProcessId"),
        "access_list": _extract_data(xml, "AccessList"),
        "access_mask": _extract_data(xml, "AccessMask"),
        # Event 4663 does not carry a source IP. The key is kept so
        # the touch schema stays stable; the value is always empty.
        "ip_address": "",
    }


# ----------------------------------------------------------------------
# EvtRender - version-tolerant
# ----------------------------------------------------------------------
def _evt_render_xml(event: Any) -> Optional[str]:
    for args in ((None, event, _EVT_RENDER_XML),
                 (event, _EVT_RENDER_XML)):
        try:
            result = win32evtlog.EvtRender(*args)
            if result:
                return result
        except Exception:
            continue
    return None


# ----------------------------------------------------------------------
# Directory ACL preservation
# ----------------------------------------------------------------------
def _copy_directory_acl(src_dir: str, dst_dir: str) -> bool:
    if not src_dir or not dst_dir:
        return False
    src_esc = src_dir.replace("'", "''")
    dst_esc = dst_dir.replace("'", "''")
    ps = (
        f"try {{ "
        f"  $acl = Get-Acl -LiteralPath '{src_esc}'; "
        f"  Set-Acl -LiteralPath '{dst_esc}' -AclObject $acl; "
        f"  'ok' "
        f"}} catch {{ 'fail: ' + $_.Exception.Message }}"
    )
    ok, out, _err = _run_ps(ps, timeout=PS_TIMEOUT)
    return ok and "ok" in (out or "")


# ----------------------------------------------------------------------
# The action
# ----------------------------------------------------------------------
class HoneytokenAction(MTDAction):
    name = "honeytoken"
    one_shot = False
    requires_admin = True

    @classmethod
    def supports(cls, capability: str, context: Dict[str, Any]) -> bool:
        if not isinstance(capability, str) or not capability:
            return False
        ctx = context if isinstance(context, dict) else {}
        path = ctx.get("log_path")
        return isinstance(path, str) and bool(path.strip())

    def __init__(self, capability: str, context: Dict[str, Any]):
        super().__init__(capability, context)

        self._lock_key: str = f"honeytoken::{capability}"
        self.capability = capability

        cfg = _load_system_config_cached()
        rules = cfg.get("capability_rules", {})
        ht_cfg: Dict[str, Any] = {}
        if isinstance(rules, dict):
            entry = rules.get(capability)
            if isinstance(entry, dict):
                h = entry.get("honeytoken")
                if isinstance(h, dict):
                    ht_cfg = h

        self.release_after_seconds: int = _coerce_int(
            ht_cfg.get("release_after_seconds"),
            DEFAULT_RELEASE_AFTER_SECONDS, 30, 30 * 86400)
        self.tail_bytes: int = _coerce_int(
            ht_cfg.get("tail_bytes"),
            DEFAULT_TAIL_BYTES, 1, 10 * 1024 * 1024)

        self._state: str = _STATE_IDLE
        self._token_path: str = ""
        self._source_path: str = ""
        self._pending_baton: Optional[Tuple[str, str]] = None
        self._last_rotation_seen: Optional[Tuple[str, str]] = None
        self._armed_at: float = 0.0
        self._tripped_at: float = 0.0
        self._touches: List[Dict[str, Any]] = []
        self._subscription_handle: Any = None
        self._subscription_active: bool = False
        self._last_error: str = ""
        self._actions: List[Dict[str, Any]] = []
        self._emit_seen: Dict[Tuple[str, str], float] = {}
        self._audit_state: str = "unchecked"
        self._audit_detail: str = ""

    # ------------------------------------------------------------------
    # Preflight
    # ------------------------------------------------------------------
    def preflight(self) -> Tuple[str, str, str]:
        try:
            if os.name != "nt":
                return (STATUS_BLOCKED, "", "Windows only")
            if not _CONFIG_AVAILABLE:
                return (STATUS_BLOCKED, "",
                        "config module not importable")
            if not _HAS_WIN32EVTLOG:
                return (STATUS_BLOCKED, "",
                        "pywin32 (win32evtlog) not available")
            if not _is_admin():
                return (STATUS_BLOCKED, "",
                        "requires elevation (Administrator)")
            if self.release_after_seconds <= 0:
                return (STATUS_BLOCKED, "",
                        "release_after_seconds must be positive")

            state, detail = _file_system_audit_enabled()
            with _get_snapshot_lock(self._lock_key):
                self._audit_state = state
                self._audit_detail = detail

            if state == "enabled":
                return (STATUS_READY, MODE_PRIMARY, "")

            if state == "disabled":
                # Confirmed off: the token would sit unwatched.
                return (STATUS_BLOCKED, "",
                        f"File System success auditing is disabled at "
                        f"machine level ({detail}). Enable it with "
                        f"'auditpol /set /subcategory:"
                        f"{_FILE_SYSTEM_SUBCATEGORY_GUID} "
                        f"/success:enable'")

            # unknown or error: the policy could not be read. Arm in
            # adapted mode and say so, rather than silently disabling
            # the defence or silently claiming it is verified.
            return (STATUS_READY, MODE_ADAPTED,
                    f"audit policy unverified: {detail}")
        except Exception as e:
            return (STATUS_BLOCKED, "", f"preflight error: {e}")

    # ------------------------------------------------------------------
    # State predicate
    # ------------------------------------------------------------------
    def is_active(self) -> bool:
        with _get_snapshot_lock(self._lock_key):
            return self._state in (
                _STATE_ARMED, _STATE_TRIPPED, _STATE_RELEASED)

    # ------------------------------------------------------------------
    # Trigger
    # ------------------------------------------------------------------
    def should_activate(self, state: str) -> bool:
        with _get_snapshot_lock(self._lock_key):
            current_state = self._state
            armed_at = self._armed_at

        bb = _read_blackboard()
        now = time.time()

        if current_state in (_STATE_ARMED, _STATE_TRIPPED):
            if _read_release_requested_from(bb, self.capability):
                with _get_snapshot_lock(self._lock_key):
                    self._state = _STATE_RELEASED
                return False
            if (self.release_after_seconds > 0
                    and armed_at > 0
                    and (now - armed_at) >= self.release_after_seconds):
                with _get_snapshot_lock(self._lock_key):
                    self._state = _STATE_RELEASED
                return False
            return True

        baton = _read_rotation_baton_from(bb, self.capability)
        if baton is None:
            return False

        with _get_snapshot_lock(self._lock_key):
            if self._last_rotation_seen == baton:
                return False
            self._pending_baton = baton
            self._token_path = baton[0]
            self._source_path = baton[1]
        return True

    # ------------------------------------------------------------------
    # Activate
    # ------------------------------------------------------------------
    def activate(self) -> Tuple[bool, str]:
        if os.name != "nt":
            return False, "Windows only"
        if not _is_admin():
            return False, "requires elevation (Administrator)"
        if not _HAS_WIN32EVTLOG:
            return False, "pywin32 (win32evtlog) not available"

        with _get_mutation_lock(self._lock_key):
            with _get_snapshot_lock(self._lock_key):
                if self._state in (_STATE_ARMED, _STATE_TRIPPED):
                    return True, ""
                token_path = self._token_path
                source_path = self._source_path
                baton = self._pending_baton

            if not token_path or not source_path or baton is None:
                return False, "no rotation baton staged"

            ok, err = self._place_content(source_path, token_path)
            if not ok:
                self._record("activate", False, err,
                             token_path=token_path)
                with _get_snapshot_lock(self._lock_key):
                    self._last_error = err
                    self._pending_baton = None
                return False, err

            ok, err = self._set_sacl(token_path)
            if not ok:
                self._safe_remove(token_path)
                self._record("activate", False, err,
                             token_path=token_path)
                with _get_snapshot_lock(self._lock_key):
                    self._last_error = err
                    self._pending_baton = None
                return False, err

            ok, err = self._open_subscription(token_path)
            if not ok:
                self._safe_remove(token_path)
                self._record("activate", False, err,
                             token_path=token_path)
                with _get_snapshot_lock(self._lock_key):
                    self._last_error = err
                    self._pending_baton = None
                return False, err

            with _get_snapshot_lock(self._lock_key):
                self._state = _STATE_ARMED
                self._armed_at = time.time()
                self._tripped_at = 0.0
                self._touches = []
                self._emit_seen = {}
                self._last_rotation_seen = baton
                self._pending_baton = None
                self._last_error = ""

            self._record("activate", True, "",
                         token_path=token_path,
                         source_path=source_path)
            _safe_emit(self.capability, _LAYER, "info",
                       f"honeytoken placed at {token_path} "
                       f"(watching for any access)")
            return True, ""

    # ------------------------------------------------------------------
    # Deactivate
    # ------------------------------------------------------------------
    def deactivate(self) -> Tuple[bool, str]:
        with _get_mutation_lock(self._lock_key):
            with _get_snapshot_lock(self._lock_key):
                token_path = self._token_path
                was_active = self._state in (
                    _STATE_ARMED, _STATE_TRIPPED, _STATE_RELEASED)

            # Drop the subscription first so removing the file does
            # not register as a touch.
            self._close_subscription()

            ok = True
            err = ""
            if token_path and os.path.isfile(token_path):
                try:
                    os.remove(token_path)
                except Exception as e:
                    ok = False
                    err = f"file removal failed: {e}"

            with _get_snapshot_lock(self._lock_key):
                self._state = _STATE_IDLE
                self._armed_at = 0.0
                self._tripped_at = 0.0
                self._token_path = ""
                self._source_path = ""
                self._pending_baton = None
                self._emit_seen = {}
                if ok:
                    self._last_error = ""

            self._record("deactivate", ok, err)
            if ok and was_active:
                _safe_emit(self.capability, _LAYER, "info",
                           "honeytoken released")
            return ok, err

    # ------------------------------------------------------------------
    # File placement
    # ------------------------------------------------------------------
    def _place_content(self, source_path: str,
                       token_path: str) -> Tuple[bool, str]:
        try:
            # Never overwrite something that is already there. If a
            # file exists at the vacated path, something recreated it
            # (possibly the process that writes the log). Truncating
            # it would destroy live data.
            if os.path.exists(token_path):
                return False, (
                    f"token path is already occupied: {token_path}; "
                    f"refusing to overwrite (something recreated the "
                    f"file, possibly the log writer)")

            data = b""
            src_stat = None
            if os.path.isfile(source_path):
                src_stat = os.stat(source_path)
                size = src_stat.st_size
                start = max(0, size - self.tail_bytes)
                with open(source_path, "rb") as f:
                    f.seek(start)
                    data = f.read()
            if not data:
                data = (b"#Version: 1.5\r\n"
                        b"#Software: Microsoft Windows Firewall\r\n"
                        b"#Fields: date time action protocol "
                        b"src-ip dst-ip src-port dst-port size\r\n")

            parent = os.path.dirname(token_path)
            if parent and not os.path.isdir(parent):
                src_parent = os.path.dirname(source_path)
                if not (src_parent and os.path.isdir(src_parent)):
                    return False, (
                        f"cannot preserve ACL: source parent "
                        f"'{src_parent}' does not exist")
                os.makedirs(parent, exist_ok=True)
                if not _copy_directory_acl(src_parent, parent):
                    return False, (
                        f"directory {parent} created but ACL copy "
                        f"from {src_parent} failed; refusing to "
                        f"place the token on a weakened directory")

            with open(token_path, "wb") as f:
                f.write(data)

            if src_stat is not None:
                try:
                    os.utime(token_path,
                             (src_stat.st_atime, src_stat.st_mtime))
                except Exception as e:
                    _safe_emit(
                        self.capability, _LAYER, "warn",
                        f"honeytoken mtime preservation failed: {e}; "
                        f"the token carries the placement timestamp "
                        f"and is less plausible")

            return True, ""
        except Exception as e:
            return False, f"place content failed: {e}"

    @staticmethod
    def _safe_remove(path: str) -> None:
        try:
            if os.path.isfile(path):
                os.remove(path)
        except Exception:
            pass

    # ------------------------------------------------------------------
    # SACL
    # ------------------------------------------------------------------
    def _set_sacl(self, token_path: str) -> Tuple[bool, str]:
        path_esc = token_path.replace("'", "''")
        ps = (
            f"try {{ "
            f"  $path = '{path_esc}'; "
            f"  $sid = New-Object System.Security.Principal."
            f"SecurityIdentifier('{_EVERYONE_SID}'); "
            f"  $acl = Get-Acl -Path $path -Audit; "
            f"  $rule = New-Object System.Security.AccessControl."
            f"FileSystemAuditRule($sid, 'Read, Write, Delete', "
            f"    'None', 'None', 'Success'); "
            f"  $acl.SetAuditRule($rule); "
            f"  Set-Acl -Path $path -AclObject $acl; "
            f"  'ok' "
            f"}} catch {{ 'fail: ' + $_.Exception.Message }}"
        )
        ok, out, _err = _run_ps(ps, timeout=PS_TIMEOUT)
        if not ok:
            return False, "SACL PowerShell failed"
        if "ok" not in (out or ""):
            detail = (out or "").strip()[:200]
            return False, f"SACL set failed: {detail}"
        return True, ""

    # ------------------------------------------------------------------
    # Subscription
    # ------------------------------------------------------------------
    def _open_subscription(self, token_path: str) -> Tuple[bool, str]:
        if not _HAS_WIN32EVTLOG:
            return False, "pywin32 not available"
        try:
            handle = win32evtlog.EvtSubscribe(
                Session=None,
                SignalEvent=None,
                ChannelPath=_CHANNEL_SECURITY,
                Query=_SUBSCRIPTION_QUERY,
                Bookmark=None,
                Context=None,
                Callback=self._on_event,
                Flags=_EVT_SUBSCRIBE_FUTURE,
            )
        except Exception as e:
            return False, f"EvtSubscribe failed: {e}"

        with _get_snapshot_lock(self._lock_key):
            self._subscription_handle = handle
            self._subscription_active = True
        return True, ""

    def _close_subscription(self) -> None:
        with _get_snapshot_lock(self._lock_key):
            handle = self._subscription_handle
            self._subscription_handle = None
            self._subscription_active = False
        if handle is None:
            return
        try:
            if hasattr(win32evtlog, "EvtClose"):
                win32evtlog.EvtClose(handle)
            elif hasattr(handle, "close"):
                handle.close()
        except Exception:
            pass

    # ------------------------------------------------------------------
    # Subscription callback (runs on a pywin32 native thread)
    # ------------------------------------------------------------------
    def _on_event(self, action: int, context: Any, event: Any) -> int:
        try:
            if action != _EVT_ACTION_DELIVER:
                return 0

            with _get_snapshot_lock(self._lock_key):
                token_path = self._token_path
                active = self._state in (_STATE_ARMED, _STATE_TRIPPED)

            if not active or not token_path:
                return 0

            xml = _evt_render_xml(event)
            if not xml:
                with _get_snapshot_lock(self._lock_key):
                    now = time.time()
                    should_emit = self._should_emit_locked(
                        "(render_failed)", "", now)
                    self._touches.append({
                        "ts": now,
                        "object_name": "",
                        "user": "",
                        "process_name": "",
                        "process_id": "",
                        "access_list": "render_failed",
                        "access_mask": "",
                        "ip_address": "",
                    })
                    if len(self._touches) > MAX_TOUCH_HISTORY:
                        self._touches = self._touches[-MAX_TOUCH_HISTORY:]
                if should_emit:
                    _safe_emit(
                        self.capability, _LAYER, "warn",
                        "honeytoken: event could not be rendered "
                        "to XML; the subscription's renderer may "
                        "be broken")
                return 0

            fields = _parse_object_access(xml)
            object_name = fields.get("object_name", "")
            if not object_name:
                return 0

            if object_name.lower() != token_path.lower():
                return 0

            user = fields.get("subject_user", "")
            domain = fields.get("subject_domain", "")
            user_full = f"{domain}\\{user}" if domain else user
            proc = fields.get("process_name", "")

            touch = {
                "ts": time.time(),
                "object_name": object_name,
                "user": user_full,
                "process_name": proc,
                "process_id": fields.get("process_id", ""),
                "access_list": fields.get("access_list", ""),
                "access_mask": fields.get("access_mask", ""),
                "ip_address": fields.get("ip_address", ""),
            }

            with _get_snapshot_lock(self._lock_key):
                self._touches.append(touch)
                if len(self._touches) > MAX_TOUCH_HISTORY:
                    self._touches = self._touches[-MAX_TOUCH_HISTORY:]
                if self._state == _STATE_ARMED:
                    self._state = _STATE_TRIPPED
                if self._tripped_at == 0.0:
                    self._tripped_at = touch["ts"]
                should_emit = self._should_emit_locked(
                    proc, user_full, touch["ts"])

            if should_emit:
                _safe_emit(
                    self.capability, _LAYER, "warn",
                    f"honeytoken touched: {object_name} by "
                    f"{proc or 'unknown'} ({user_full or 'unknown'})")
        except Exception as e:
            try:
                with _get_snapshot_lock(self._lock_key):
                    self._touches.append({
                        "ts": time.time(),
                        "object_name": "",
                        "user": "",
                        "process_name": "",
                        "process_id": "",
                        "access_list": "callback_error",
                        "access_mask": "",
                        "ip_address": "",
                        "error": str(e)[:200],
                    })
                    if len(self._touches) > MAX_TOUCH_HISTORY:
                        self._touches = self._touches[-MAX_TOUCH_HISTORY:]
            except Exception:
                pass
        return 0

    def _should_emit_locked(self, proc: str, user: str,
                            now: float) -> bool:
        key = (proc or "", user or "")
        last = self._emit_seen.get(key, 0.0)
        if (now - last) >= _EMIT_WINDOW_SECONDS:
            self._emit_seen[key] = now
            return True
        return False

    # ------------------------------------------------------------------
    # Bookkeeping
    # ------------------------------------------------------------------
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
            if len(self._actions) > 50:
                self._actions = self._actions[-50:]

    # ------------------------------------------------------------------
    # Status
    # ------------------------------------------------------------------
    def status(self) -> Dict[str, Any]:
        with _get_snapshot_lock(self._lock_key):
            return {
                "backend": "honeytoken",
                "state": self._state,
                "active": self._state in (
                    _STATE_ARMED, _STATE_TRIPPED, _STATE_RELEASED),
                "token_path": self._token_path,
                "source_path": self._source_path,
                "armed_at": self._armed_at,
                "tripped_at": self._tripped_at,
                "release_after_seconds": self.release_after_seconds,
                "subscription_active": self._subscription_active,
                "audit_policy_state": self._audit_state,
                "audit_policy_detail": self._audit_detail,
                "touch_count": len(self._touches),
                "touches": list(self._touches),
                "last_rotation_seen": (
                    list(self._last_rotation_seen)
                    if self._last_rotation_seen else None),
                "last_error": self._last_error,
                "actions": list(self._actions),
            }


# ----------------------------------------------------------------------
# Standalone test (read-only)
# ----------------------------------------------------------------------
if __name__ == "__main__":
    print("=" * 64)
    print("  HoneytokenAction standalone test (read-only)")
    print("=" * 64)
    print()

    ctx = {"capability": "firewall",
           "log_path": r"C:\Windows\System32\LogFiles\Firewall\pfirewall.log"}

    print("supports('firewall'):",
          HoneytokenAction.supports("firewall", ctx))
    print("supports('ssh') with no path:",
          HoneytokenAction.supports("ssh", {}))
    print()

    print("os.name:", os.name)
    print("elevated:", _is_admin())
    print("pywin32 available:", _HAS_WIN32EVTLOG)
    print()

    print("normalizer checks:")
    for sample in ("Success and Failure", "No Auditing",
                   "Succ\u00e8s et \u00e9chec", "Pas d\u2019audit",
                   "\u00c9chec"):
        print(f"  {sample!r} -> {_normalize_audit_value(sample)!r}")
    print()

    state, detail = _file_system_audit_enabled(use_cache=False)
    print("File System audit policy state:", state)
    if detail:
        print("  detail:", detail)
    print()

    action = HoneytokenAction("firewall", ctx)
    print("release_after_seconds:", action.release_after_seconds)
    print("preflight:", action.preflight())
    print()

    print("status:")
    print(json.dumps(action.status(), indent=2, default=str))
    print()

    print("activate and deactivate were NOT called.")
    print("No file was created. No subscription was opened.")