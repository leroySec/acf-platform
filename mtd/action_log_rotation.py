#!/usr/bin/env python3
"""
mtd/action_log_rotation.py - In-place log rotation MTD action.

Renames the log file when it exceeds the size threshold and creates
a fresh empty file at the same path. Prunes old rotated files by
count and by total bytes.

Formula (manual steps):
  1. Stat the log file.
  2. If size is over threshold and state is elevated:
     a. Capture the ACL of the current log.
     b. Create an empty file at a temp path, apply the captured ACL.
     c. Rename the log to a timestamped rotated name.
     d. Rename the temp file onto the log's original path.
     e. Prune older rotated files (count cap and byte cap).
  3. Record the rotation.
"""

import hashlib
import os
import re
import shutil
import subprocess
import sys
import threading
import time
from typing import Any, Dict, List, Optional, Tuple

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

from mtd.base import (
    MTDAction, STATUS_READY, STATUS_BLOCKED, MODE_PRIMARY,
)

try:
    from event_emit import emit as _emit_impl
except ImportError:
    def _emit_impl(src, layer, level, msg):
        ts = time.strftime("%H:%M:%S")
        print(f"[{ts}][{src}][{layer}][{level.upper()}] {msg}")


def _safe_emit(src: str, layer: str, level: str, msg: str) -> None:
    try:
        _emit_impl(src, layer, level, msg)
    except Exception:
        pass


_LAYER = "layer4c"

DEFAULT_THRESHOLD_BYTES = 5 * 1024 * 1024
DEFAULT_KEEP_ROTATED = 5
DEFAULT_MAX_BYTES_TOTAL = 100 * 1024 * 1024
DEFAULT_SUFFIX_FORMAT = "%Y%m%d-%H%M%S"
DEFAULT_MIN_SECONDS_BETWEEN = 30.0
DEFAULT_RENAME_RETRIES = 4
DEFAULT_RENAME_RETRY_DELAY = 0.25
DEFAULT_REQUIRE_ACL = False
MAX_SUFFIX_ATTEMPTS = 16
_MAX_PATH_LEN = 240

_SUFFIX_SAFE_RE = re.compile(r"^[A-Za-z0-9._-]+$")

_STRFTIME_RE = {
    "%Y": r"\d{4}", "%y": r"\d{2}", "%m": r"\d{2}",
    "%d": r"\d{2}", "%H": r"\d{2}", "%M": r"\d{2}",
    "%S": r"\d{2}", "%j": r"\d{3}", "%U": r"\d{2}",
    "%W": r"\d{2}", "%%": re.escape("%"),
}

_WSA_SHARING_VIOLATION = 32
_WSA_ACCESS_DENIED = 5
_WSA_LOCK_VIOLATION = 33
_WSA_DISK_FULL = 112
_WSA_HANDLE_DISK_FULL = 39
_WSA_NOT_SAME_DEVICE = 17

_STATE_THRESHOLD_FIELD = {
    "ORANGE": "threshold_bytes",
    "RED": "red_threshold_bytes",
}

_MIN_FREE_BYTES = 1 * 1024 * 1024
_NEVER_MATCH = r"(?!)"

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


def _coerce_int(value, default, minimum, maximum):
    try:
        n = int(value)
    except (TypeError, ValueError):
        return default
    return default if n < minimum or n > maximum else n


def _coerce_float(value, default, minimum, maximum):
    try:
        f = float(value)
    except (TypeError, ValueError):
        return default
    return default if f < minimum or f > maximum else f


def _coerce_str(value, default):
    if isinstance(value, str) and value.strip():
        return value.strip()
    return default


def _coerce_bool(value, default):
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        v = value.strip().lower()
        if v in ("1", "true", "yes", "on"):
            return True
        if v in ("0", "false", "no", "off"):
            return False
    return default


def _same_volume(path_a: str, path_b: str) -> bool:
    if os.name == "nt":
        a = os.path.splitdrive(os.path.abspath(path_a))[0].lower()
        b = os.path.splitdrive(os.path.abspath(path_b))[0].lower()
        return a == b
    try:
        return os.stat(path_a).st_dev == os.stat(path_b).st_dev
    except OSError:
        return False


def _errno_codes(e: BaseException) -> Tuple[int, ...]:
    codes = []
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
        return any(c in (_WSA_SHARING_VIOLATION, _WSA_ACCESS_DENIED,
                         _WSA_LOCK_VIOLATION) for c in codes)
    import errno as _e
    return any(c in (_e.EACCES, _e.EBUSY, _e.EAGAIN, _e.EPERM)
               for c in codes)


def _is_disk_full(codes: Tuple[int, ...]) -> bool:
    if any(c in (_WSA_DISK_FULL, _WSA_HANDLE_DISK_FULL) for c in codes):
        return True
    if os.name != "nt":
        import errno as _e
        return any(c in (_e.ENOSPC, _e.EDQUOT) for c in codes)
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
            encoding="utf-8", errors="replace")
        return r.returncode, r.stdout or "", r.stderr or ""
    except subprocess.TimeoutExpired:
        return -1, "", "timeout"
    except Exception as e:
        return -1, "", str(e)


def _copy_acl_windows(src: str, dst: str) -> bool:
    se = src.replace("'", "''")
    de = dst.replace("'", "''")
    cmd = (
        f"try {{ "
        f"  $acl = Get-Acl -LiteralPath '{se}'; "
        f"  Set-Acl -LiteralPath '{de}' -AclObject $acl; "
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


def _sanitize_suffix(raw: str) -> str:
    if not isinstance(raw, str) or not raw:
        return ""
    cleaned = "".join(ch for ch in raw
                      if (ch.isascii() and ch.isalnum()) or ch in "._-")
    if not cleaned or not _SUFFIX_SAFE_RE.match(cleaned):
        return ""
    return cleaned


def _strftime_to_regex(fmt: str) -> Tuple[Optional[str], str]:
    if not isinstance(fmt, str) or not fmt:
        return None, ""
    parts = []
    i = 0
    while i < len(fmt):
        ch = fmt[i]
        if ch == "%" and i + 1 < len(fmt):
            tok = fmt[i:i + 2]
            if tok in _STRFTIME_RE:
                parts.append(_STRFTIME_RE[tok])
            else:
                return None, tok
            i += 2
        else:
            parts.append(re.escape(ch))
            i += 1
    return "".join(parts), ""


def _read_text_with_encoding(path: str) -> Tuple[str, bytes, str]:
    with open(path, "rb") as f:
        raw = f.read()
    return _decode_raw(raw)


def _decode_raw(raw: bytes) -> Tuple[str, bytes, str]:
    bom_checks = (
        (b"\xff\xfe\x00\x00", "utf-32-le"),
        (b"\x00\x00\xfe\xff", "utf-32-be"),
        (b"\xef\xbb\xbf", "utf-8"),
        (b"\xff\xfe", "utf-16-le"),
        (b"\xfe\xff", "utf-16-be"),
    )
    for bom, enc in bom_checks:
        if raw.startswith(bom):
            body = raw[len(bom):]
            try:
                if enc in ("utf-16-le", "utf-16-be",
                           "utf-32-le", "utf-32-be"):
                    text = body.decode(enc, errors="surrogatepass")
                    return (text, bom, enc + "+surrogatepass")
                return (body.decode(enc), bom, enc)
            except (LookupError, UnicodeDecodeError):
                continue
    try:
        return (raw.decode("utf-8"), b"", "utf-8")
    except UnicodeDecodeError:
        pass
    return (raw.decode("cp1252", errors="surrogateescape"),
            b"", "cp1252+surrogateescape")


def _write_text_with_encoding(path: str, text: str, bom: bytes,
                              encoding: str) -> None:
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


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _split_head_tail(content: str) -> Tuple[str, str]:
    m = re.search(r"^\s*Match\b", content, re.MULTILINE | re.IGNORECASE)
    if m:
        return (content[:m.start()], content[m.start():])
    return (content, "")


def _parse_port(content: str) -> int:
    """Return the effective top-level Port, or 22 (sshd default)."""
    head, _tail = _split_head_tail(content)
    for line in head.splitlines():
        m = re.match(r"^\s*Port\s+(\d+)", line, re.IGNORECASE)
        if m:
            return int(m.group(1))
    return 22


def _parse_listen_addresses(content: str) -> List[str]:
    head, _tail = _split_head_tail(content)
    out = []
    for line in head.splitlines():
        m = re.match(r"^\s*ListenAddress\s+(\S+)", line, re.IGNORECASE)
        if m:
            out.append(m.group(1).strip())
    return out


def _has_include_directive(content: str) -> bool:
    return bool(re.search(r"^\s*Include\s+\S", content,
                          re.MULTILINE | re.IGNORECASE))


def _hosts_from_addresses(addrs: List[str]) -> List[str]:
    if not addrs:
        return ["127.0.0.1"]
    hosts = []
    for a in addrs:
        if a in ("0.0.0.0", "::", "*"):
            h = "127.0.0.1"
        elif a.startswith("[") and "]" in a:
            h = a[1:a.index("]")]
        elif ":" in a and a.count(":") == 1:
            h = a.split(":", 1)[0]
        else:
            h = a
        if h and h not in hosts:
            hosts.append(h)
    if "127.0.0.1" not in hosts:
        hosts.append("127.0.0.1")
    return hosts


class LogRotationAction(MTDAction):
    name = "log_rotation"
    one_shot = True
    requires_admin = False

    @classmethod
    def supports(cls, capability, context):
        ctx = context if isinstance(context, dict) else {}
        path = ctx.get("log_path")
        return isinstance(path, str) and bool(path.strip())

    def __init__(self, capability, context):
        super().__init__(capability, context)
        ctx = context if isinstance(context, dict) else {}
        raw = _coerce_str(ctx.get("log_path"), "")
        if raw:
            try:
                self.log_path = os.path.abspath(os.path.realpath(raw))
            except Exception:
                self.log_path = os.path.abspath(raw)
        else:
            self.log_path = ""
        self._lock_key = (f"log_rotation::{self.log_path}"
                          if self.log_path
                          else f"log_rotation::{capability}")
        self.rotation_dir = None
        rd = ctx.get("rotation_dir")
        if isinstance(rd, str) and rd.strip():
            try:
                self.rotation_dir = os.path.abspath(os.path.realpath(rd))
            except Exception:
                self.rotation_dir = os.path.abspath(rd.strip())
        self.threshold_bytes = _coerce_int(
            ctx.get("threshold_bytes"), DEFAULT_THRESHOLD_BYTES,
            1, 1 << 40)
        raw_red = ctx.get("red_threshold_bytes")
        red = _coerce_int(raw_red, max(1, self.threshold_bytes // 5),
                          1, 1 << 40)
        self._init_warnings = []
        if red > self.threshold_bytes:
            red = self.threshold_bytes
            self._init_warnings.append(
                f"red_threshold_bytes clamped from {raw_red} "
                f"to {self.threshold_bytes}")
        self.red_threshold_bytes = red
        self.keep_rotated = _coerce_int(
            ctx.get("keep_rotated"), DEFAULT_KEEP_ROTATED, 0, 1000)
        self.max_bytes_total = _coerce_int(
            ctx.get("max_bytes_total"), DEFAULT_MAX_BYTES_TOTAL,
            0, 1 << 40)
        self.suffix_format = _coerce_str(
            ctx.get("suffix_format"), DEFAULT_SUFFIX_FORMAT)
        self.min_seconds_between_rotations = _coerce_float(
            ctx.get("min_seconds_between_rotations"),
            DEFAULT_MIN_SECONDS_BETWEEN, 0.0, 3600.0)
        self.rename_retries = _coerce_int(
            ctx.get("rename_retries"), DEFAULT_RENAME_RETRIES, 0, 20)
        self.rename_retry_delay = _coerce_float(
            ctx.get("rename_retry_delay"), DEFAULT_RENAME_RETRY_DELAY,
            0.0, 10.0)
        self.require_acl_preservation = _coerce_bool(
            ctx.get("require_acl_preservation"), DEFAULT_REQUIRE_ACL)
        fmt_re, unsupported = _strftime_to_regex(self.suffix_format)
        self._suffix_regex_source = fmt_re
        self._unsupported_directive = unsupported
        self._check_warnings = []
        self._last_state = ""
        self._last_rotation_ts = 0.0
        self._rotations_total = 0
        self._last_rotation_info = {}
        self._actions = []
        self._preflight_reason = ""
        self._check_environment()

    def _check_environment(self):
        self._preflight_reason = ""
        self._check_warnings = []
        if not self.log_path:
            self._preflight_reason = "no log_path provided"
            return
        if self._suffix_regex_source is None:
            self._preflight_reason = (
                f"suffix_format {self.suffix_format!r} uses an "
                f"unsupported directive "
                f"{self._unsupported_directive or '<unknown>'}")
            return
        try:
            sample = time.strftime(self.suffix_format)
        except (ValueError, TypeError) as e:
            self._preflight_reason = f"invalid suffix_format: {e}"
            return
        if not sample or _sanitize_suffix(sample) != sample:
            self._preflight_reason = (
                f"suffix_format produces unusable output: {sample!r}")
            return
        if not os.path.exists(self.log_path):
            self._preflight_reason = f"log path missing: {self.log_path}"
            return
        if os.path.isdir(self.log_path):
            self._preflight_reason = f"log path is a directory: {self.log_path}"
            return
        if not os.path.isfile(self.log_path):
            self._preflight_reason = (
                f"log path is not a regular file: {self.log_path}")
            return
        parent = os.path.dirname(self.log_path)
        if parent and not os.access(parent, os.W_OK):
            self._preflight_reason = f"log dir not writable: {parent}"
            return
        if self.rotation_dir is not None:
            if not os.path.isdir(self.rotation_dir):
                self._preflight_reason = (
                    f"rotation_dir missing: {self.rotation_dir}")
                return
            if not os.access(self.rotation_dir, os.W_OK):
                self._preflight_reason = (
                    f"rotation_dir not writable: {self.rotation_dir}")
                return
        target_dir = self.rotation_dir or parent
        if target_dir:
            try:
                if not _same_volume(self.log_path, target_dir):
                    self._preflight_reason = (
                        f"log and rotation dir on different volumes")
                    return
            except OSError:
                pass
        if os.name == "nt" and not _resolve_powershell():
            self._check_warnings.append(
                "no PowerShell; new file inherits directory default ACL")

    def preflight(self):
        self._check_environment()
        if self._preflight_reason:
            return (STATUS_BLOCKED, "", self._preflight_reason)
        return (STATUS_READY, MODE_PRIMARY, "")

    def should_activate(self, state):
        if not isinstance(state, str):
            state = ""
        n = state.strip().upper()
        with _get_snapshot_lock(self._lock_key):
            self._last_state = n
        return n in ("ORANGE", "RED")

    def is_active(self):
        return False

    def activate(self):
        with _get_mutation_lock(self._lock_key):
            if self._suffix_regex_source is None:
                return False, (
                    f"suffix_format {self.suffix_format!r} uses an "
                    f"unsupported directive")
            with _get_snapshot_lock(self._lock_key):
                state = self._last_state
            if not state:
                return False, (
                    "should_activate() must be called before activate()")
            if state not in _STATE_THRESHOLD_FIELD:
                self._record("rotation", True, "", state=state,
                             noop_reason="state_not_active")
                return True, ""
            threshold = getattr(self, _STATE_THRESHOLD_FIELD[state])
            now = time.time()
            with _get_snapshot_lock(self._lock_key):
                last = self._last_rotation_ts
            if (self.min_seconds_between_rotations > 0
                    and (now - last) < self.min_seconds_between_rotations):
                self._record("rotation", True, "", state=state,
                             noop_reason="rate_limited")
                return True, ""
            try:
                st = os.stat(self.log_path)
            except FileNotFoundError:
                return False, "log file disappeared"
            except PermissionError as e:
                return False, f"stat permission denied: {e}"
            except OSError as e:
                return False, f"stat failed: {e}"
            if st.st_size < threshold:
                return True, ""
            try:
                usage = shutil.disk_usage(os.path.dirname(self.log_path))
                if usage.free < _MIN_FREE_BYTES:
                    return False, (
                        f"free space below {_MIN_FREE_BYTES} bytes")
            except Exception:
                pass
            ok, err, info = self._perform_rotation()
            with _get_snapshot_lock(self._lock_key):
                self._record_locked("rotation", ok, err, state=state,
                                    threshold=threshold, **info)
                if ok:
                    self._last_rotation_ts = time.time()
                    self._rotations_total += 1
                    self._last_rotation_info = dict(info)
            if ok:
                _safe_emit(self.capability, _LAYER, "info",
                           f"log rotated: {info.get('bytes', 0)}B")
            else:
                _safe_emit(self.capability, _LAYER, "error",
                           f"log rotation failed: {err}")
            return ok, err

    def deactivate(self):
        return True, ""

    def _perform_rotation(self):
        info = {}
        try:
            info["bytes"] = os.stat(self.log_path).st_size
        except Exception:
            info["bytes"] = 0
        rotated_path, reason = self._compute_rotated_path()
        if rotated_path is None:
            return False, reason or "no rotated path", info
        info["rotated_to"] = os.path.basename(rotated_path)
        temp_path = f"{self.log_path}.new.{os.getpid()}"
        try:
            acl_ok = self._create_empty_with_acl(self.log_path, temp_path)
        except OSError as e:
            codes = _errno_codes(e)
            if _is_disk_full(codes):
                return False, f"disk full: {e}", info
            return False, f"temp create failed: {e}", info
        if not acl_ok and self.require_acl_preservation:
            self._silent_remove(temp_path)
            return False, "ACL preservation required but failed", info
        ok, err, cross = self._rename_with_retry(self.log_path, rotated_path)
        if not ok:
            self._silent_remove(temp_path)
            if cross:
                return False, "cross-filesystem rename refused", info
            return False, f"rename original failed: {err}", info
        ok, err, _cross = self._rename_with_retry(temp_path, self.log_path)
        if not ok:
            rb_ok, rb_err, _rbc = self._rename_with_retry(
                rotated_path, self.log_path)
            info["rollback_ok"] = rb_ok
            if not rb_ok:
                info["rollback_error"] = rb_err[:200]
            self._silent_remove(temp_path)
            if not rb_ok:
                return False, (
                    f"rename temp failed: {err}; rollback also "
                    f"failed: {rb_err}; log path is missing, "
                    f"rotated file at {rotated_path}"), info
            return False, f"rename temp failed: {err} (rolled back)", info
        try:
            st_new = os.stat(self.log_path)
            info["new_size"] = st_new.st_size
        except FileNotFoundError:
            rb_ok, rb_err, _rbc = self._rename_with_retry(
                rotated_path, self.log_path)
            info["rollback_ok"] = rb_ok
            if not rb_ok:
                info["rollback_error"] = rb_err[:200]
                return False, (
                    f"verify failed: new log missing; rollback also "
                    f"failed: {rb_err}"), info
            return False, "verify failed: new log missing (rolled back)", info
        except OSError as e:
            info["verify_error"] = str(e)[:200]
        try:
            st_rot = os.stat(rotated_path)
            info["rotated_size"] = st_rot.st_size
        except Exception:
            pass
        pruned, freed, prune_err = self._prune_old_rotated()
        info["pruned"] = pruned
        info["freed_bytes"] = freed
        info["kept"] = self._count_rotated()
        if prune_err:
            info["prune_error"] = prune_err
        return True, "", info

    def _compute_rotated_path(self):
        base = os.path.basename(self.log_path)
        target = self.rotation_dir or os.path.dirname(self.log_path)
        for attempt in range(MAX_SUFFIX_ATTEMPTS):
            try:
                raw = time.strftime(self.suffix_format)
            except (ValueError, TypeError) as e:
                return None, f"strftime failed: {e}"
            if attempt > 0:
                raw = f"{raw}.{attempt}"
            safe = _sanitize_suffix(raw)
            if not safe:
                continue
            candidate = os.path.join(target, f"{base}.{safe}")
            if not os.path.exists(candidate):
                return candidate, ""
        return None, f"suffix collision after {MAX_SUFFIX_ATTEMPTS}"

    def _create_empty_with_acl(self, src, dst):
        with open(dst, "wb"):
            pass
        ok = _copy_acl(src, dst)
        if not ok:
            _safe_emit(self.capability, _LAYER, "warn",
                       f"could not copy ACL from {src} to {dst}")
        return ok

    def _rename_with_retry(self, src, dst):
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
                if _is_sharing_violation(codes) and attempt + 1 < attempts:
                    time.sleep(self.rename_retry_delay * (2 ** attempt))
                    continue
                return False, last_err, False
            except Exception as e:
                return False, str(e), False
        return False, last_err or "rename failed", False

    def _silent_remove(self, path):
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass

    def _rotated_pattern(self):
        if self._suffix_regex_source is None:
            return re.compile(_NEVER_MATCH)
        base = re.escape(os.path.basename(self.log_path))
        return re.compile(
            rf"^{base}\.{self._suffix_regex_source}(?:\.\d+)?$")

    def _list_rotated(self):
        target = self.rotation_dir or os.path.dirname(self.log_path)
        pattern = self._rotated_pattern()
        prefix = os.path.basename(self.log_path) + "."
        out = []
        try:
            for name in os.listdir(target):
                if not pattern.match(name):
                    continue
                full = os.path.join(target, name)
                if not os.path.isfile(full):
                    continue
                try:
                    st = os.stat(full)
                except Exception:
                    continue
                suffix = name[len(prefix):] if name.startswith(prefix) else ""
                out.append((full, st.st_mtime, st.st_size, suffix))
        except Exception:
            pass
        return out

    def _count_rotated(self):
        return len(self._list_rotated())

    @staticmethod
    def _suffix_sort_key(entry):
        _path, mtime, _size, suffix = entry
        if not suffix:
            return (f"~mtime~{mtime:020.6f}", 0)
        m = re.match(r"^(.*?)\.(\d+)$", suffix)
        if m:
            return (m.group(1), int(m.group(2)))
        return (suffix, 0)

    def _prune_old_rotated(self):
        entries = self._list_rotated()
        if not entries:
            return 0, 0, ""
        entries.sort(key=self._suffix_sort_key)
        to_delete = []
        kept = list(entries)
        while len(kept) > self.keep_rotated:
            to_delete.append(kept.pop(0))
        if self.max_bytes_total > 0:
            total = sum(sz for _, _, sz, _ in kept)
            i = 0
            while total > self.max_bytes_total and i < len(kept):
                to_delete.append(kept[i])
                total -= kept[i][2]
                i += 1
            kept = kept[i:]
        seen = set()
        unique_delete = []
        for item in to_delete:
            if item[0] in seen:
                continue
            seen.add(item[0])
            unique_delete.append(item)
        pruned = 0
        freed = 0
        errors = []
        for path, _mt, sz, _suffix in unique_delete:
            try:
                os.remove(path)
                pruned += 1
                freed += sz
            except Exception as e:
                errors.append(f"{os.path.basename(path)}: {e}")
        return pruned, freed, "; ".join(errors)

    def _record_locked(self, action, ok, err="", **fields):
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

    def _record(self, action, ok, err="", **fields):
        with _get_snapshot_lock(self._lock_key):
            self._record_locked(action, ok, err, **fields)

    def status(self):
        with _get_snapshot_lock(self._lock_key):
            return {
                "backend": "in_place_rotate",
                "log_path": self.log_path,
                "rotation_dir": self.rotation_dir or (
                    os.path.dirname(self.log_path) if self.log_path
                    else ""),
                "threshold_bytes": self.threshold_bytes,
                "red_threshold_bytes": self.red_threshold_bytes,
                "keep_rotated": self.keep_rotated,
                "max_bytes_total": self.max_bytes_total,
                "suffix_format": self.suffix_format,
                "suffix_regex_supported":
                    self._suffix_regex_source is not None,
                "unsupported_directive": self._unsupported_directive,
                "min_seconds_between_rotations":
                    self.min_seconds_between_rotations,
                "require_acl_preservation":
                    self.require_acl_preservation,
                "last_state": self._last_state,
                "last_rotation_ts": self._last_rotation_ts,
                "rotations_total": self._rotations_total,
                "last_rotation_info": dict(self._last_rotation_info),
                "init_warnings": list(self._init_warnings),
                "preflight_warnings": list(self._check_warnings),
                "construction_warnings":
                    list(self._init_warnings) + list(self._check_warnings),
                "rotated_files_visible":
                    self._suffix_regex_source is not None,
                "rotated_files": [
                    {"path": p, "mtime": mt, "size": sz, "suffix": s}
                    for p, mt, sz, s in self._list_rotated()],
                "actions": list(self._actions),
            }