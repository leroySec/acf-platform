#!/usr/bin/env python3
"""
mtd/action_address_rotation.py - Address rotation MTD action.

Rotates the SSH listener between loopback IPs. Requires elevation.
Active at ORANGE or RED.

State mapping:
  GREEN, YELLOW  -> 127.0.0.1 (canonical loopback)
  ORANGE         -> 127.0.0.2
  RED            -> 127.0.0.3

deactivate() is the reverse transaction: it rotates the listener
back to base_ip. This makes AddressRotationAction symmetric with
PortShuffleAction for the engine's dispatch contract.

Rate-limit asymmetry (deliberate):
    activate() enforces min_seconds_between_rotations.
    deactivate() does not, and does not refresh the timestamp.
    The safe direction (returning to base_ip) is always allowed
    even within the rate-limit window. A quick ORANGE -> GREEN ->
    ORANGE sequence moves the listener to .1, then waits out the
    remaining window before the next escalation. That is the
    intended behavior: the operator-visible state never stays
    escalated for longer than the configured window, and the safe
    direction is never blocked.
"""

import hashlib
import ipaddress
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


def _safe_emit(src, layer, level, msg):
    try:
        _emit_impl(src, layer, level, msg)
    except Exception:
        pass


_LAYER = "layer4c"

WINDIR = os.environ.get("WINDIR", r"C:\Windows")
SSHD_CONFIG_PATH = r"C:\ProgramData\ssh\sshd_config"
SSHD_BINARY_PATH = os.path.join(WINDIR, "System32", "OpenSSH", "sshd.exe")
SSHD_SERVICE_NAME = "sshd"

DEFAULT_BASE_IP = "127.0.0.1"
DEFAULT_ALTERNATE_IP = "127.0.0.2"
DEFAULT_AGGRESSIVE_IP = "127.0.0.3"

DEFAULT_RENAME_RETRIES = 4
DEFAULT_RENAME_RETRY_DELAY = 0.25
DEFAULT_REMOVE_PREVIOUS = True
DEFAULT_MIN_SECONDS_BETWEEN = 30.0
DEFAULT_CLAIM_RANGE = True

SERVICE_RESTART_TIMEOUT = 45.0
SERVICE_STATE_POLL_INTERVAL = 0.4

PORT_VERIFY_RETRIES = 6
PORT_VERIFY_BASE_DELAY = 0.8
PORT_VERIFY_MAX_DELAY = 6.0

FILE_LOCK_RETRIES = 5
FILE_LOCK_DELAYS = (0.2, 0.5, 1.0, 2.0)

MAX_ACTION_HISTORY = 50
MAX_RECORD_FIELD_LEN = 200
MAX_ADDED_IPS = 8
MAX_REMOVED_IPS_HISTORY = 8

IFACE_CACHE_TTL = 60.0

_BROADCAST_IP = "127.255.255.255"
_LOOPBACK_NET = ipaddress.ip_network("127.0.0.0/8")

_SC_ERR_SERVICE_ALREADY_RUNNING = "1056"
_SC_ERR_SERVICE_DISABLED = "1058"
_SC_ERR_SERVICE_CANNOT_ACCEPT_CTRL = "1061"
_SC_ERR_SERVICE_NOT_ACTIVE = "1062"

_SC_TRANSIENT_FROM_START = ("startpending", "continuepending")
_SC_TRANSIENT_FROM_STOP = ("stoppending",)

_STATE_TARGET_FIELD = {
    "ORANGE": "alternate_ip",
    "RED": "aggressive_ip",
}

_CACHED_POWERSHELL: Optional[str] = None
_CACHED_IFACE_INDEX: Optional[int] = None
_CACHED_IFACE_INDEX_AT: float = 0.0

_MUTATION_LOCKS: Dict[str, threading.Lock] = {}
_SNAPSHOT_LOCKS: Dict[str, threading.Lock] = {}
_LOCKS_MUTEX = threading.Lock()


def _get_mutation_lock(lock_key):
    with _LOCKS_MUTEX:
        if lock_key not in _MUTATION_LOCKS:
            _MUTATION_LOCKS[lock_key] = threading.Lock()
        return _MUTATION_LOCKS[lock_key]


def _get_snapshot_lock(lock_key):
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


def _coerce_optional_int(value, default, minimum, maximum):
    if value is None:
        return default
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


def _is_admin():
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


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
    "$ErrorActionPreference = 'Stop'; "
    "try { [Console]::OutputEncoding = "
    "[System.Text.Encoding]::UTF8 } catch {}; "
    "try { $OutputEncoding = [System.Text.Encoding]::UTF8 } catch {}; "
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


def _service_status_ps(name, timeout=8.0):
    esc = name.replace("'", "''")
    cmd = (f"try {{ "
           f"  $svc = Get-Service -Name '{esc}' -ErrorAction Stop; "
           f"  $svc.Status.ToString() "
           f"}} catch {{ 'unknown' }}")
    rc, out, _err = _run_ps(cmd, timeout=timeout)
    if rc != 0:
        return "unknown"
    return (out or "").strip().lower() or "unknown"


def _service_resolve_once(name, timeout):
    esc = name.replace("'", "''")
    cmd = (f"try {{ "
           f"  $s = Get-Service -Name '{esc}' -ErrorAction Stop; "
           f"  $s.Name + '|' + $s.Status.ToString() "
           f"}} catch {{ 'no' }}")
    rc, out, _err = _run_ps(cmd, timeout=timeout)
    if rc == 0:
        line = (out or "").strip().splitlines()[0] if out else ""
        if "|" in line:
            rname, state = line.split("|", 1)
            return (rname.strip(), state.strip().lower())
    alias = "OpenSSH SSH Server".replace("'", "''")
    cmd = (f"$s = Get-Service -ErrorAction SilentlyContinue | "
           f"     Where-Object {{ $_.DisplayName -ceq '{alias}' }} | "
           f"     Select-Object -First 1; "
           f"if ($null -eq $s) {{ 'not_installed' }} "
           f"else {{ $s.Name + '|' + $s.Status.ToString() }}")
    rc, out, _err = _run_ps(cmd, timeout=timeout)
    if rc != 0:
        return ("", "unknown")
    line = (out or "").strip().splitlines()[0] if out else ""
    if not line:
        return ("", "unknown")
    if line == "not_installed":
        return ("", "not_installed")
    if "|" in line:
        rname, state = line.split("|", 1)
        return (rname.strip(), state.strip().lower())
    return ("", "unknown")


def _service_resolve_and_state(name, retries=3):
    for attempt in range(retries):
        t = 15.0 if attempt == 0 else 8.0
        rname, state = _service_resolve_once(name, timeout=t)
        if state != "unknown":
            return (rname, state)
        if attempt + 1 < retries:
            time.sleep(0.5 * (attempt + 1))
    return ("", "unknown")


def _wait_for_service(name, want, timeout):
    deadline = time.time() + timeout
    while time.time() < deadline:
        if _service_status_ps(name) == want:
            return True
        time.sleep(SERVICE_STATE_POLL_INTERVAL)
    return False


def _resolve_transition_before_verb(name):
    st = _service_status_ps(name)
    if st in _SC_TRANSIENT_FROM_START:
        _wait_for_service(name, "running", SERVICE_RESTART_TIMEOUT)
    elif st in _SC_TRANSIENT_FROM_STOP:
        _wait_for_service(name, "stopped", SERVICE_RESTART_TIMEOUT)


def _service_stop(name):
    _resolve_transition_before_verb(name)
    rc, out, err = _sc(["stop", name])
    blob = (out or "") + (err or "")
    if rc != 0:
        if _SC_ERR_SERVICE_NOT_ACTIVE in blob:
            return True, ""
        if _SC_ERR_SERVICE_CANNOT_ACCEPT_CTRL in blob:
            _wait_for_service(name, "running", SERVICE_RESTART_TIMEOUT)
            rc2, out2, err2 = _sc(["stop", name])
            blob2 = (out2 or "") + (err2 or "")
            if rc2 != 0 and _SC_ERR_SERVICE_NOT_ACTIVE not in blob2:
                return False, (err2 or out2 or
                               "sc stop failed").strip()[:200]
        else:
            return False, (err or out or "sc stop failed").strip()[:200]
    if not _wait_for_service(name, "stopped", SERVICE_RESTART_TIMEOUT):
        return False, "service did not reach stopped"
    return True, ""


def _service_start(name):
    _resolve_transition_before_verb(name)
    rc, out, err = _sc(["start", name])
    blob = (out or "") + (err or "")
    if rc != 0:
        if _SC_ERR_SERVICE_ALREADY_RUNNING in blob:
            return True, ""
        if _SC_ERR_SERVICE_DISABLED in blob:
            return False, "service is disabled"
        if _SC_ERR_SERVICE_CANNOT_ACCEPT_CTRL in blob:
            _wait_for_service(name, "stopped", SERVICE_RESTART_TIMEOUT)
            rc2, out2, err2 = _sc(["start", name])
            blob2 = (out2 or "") + (err2 or "")
            if rc2 != 0 and _SC_ERR_SERVICE_ALREADY_RUNNING not in blob2:
                if _SC_ERR_SERVICE_DISABLED in blob2:
                    return False, "service is disabled"
                return False, (err2 or out2 or
                               "sc start failed").strip()[:200]
        else:
            return False, (err or out or "sc start failed").strip()[:200]
    if not _wait_for_service(name, "running", SERVICE_RESTART_TIMEOUT):
        return False, "service did not reach running"
    return True, ""


def _loopback_interface_index(force=False):
    global _CACHED_IFACE_INDEX, _CACHED_IFACE_INDEX_AT
    now = time.time()
    if (not force and _CACHED_IFACE_INDEX is not None
            and (now - _CACHED_IFACE_INDEX_AT) < IFACE_CACHE_TTL):
        return _CACHED_IFACE_INDEX or None
    cmd = ("try { "
           "  $ip = Get-NetIPAddress -IPAddress 127.0.0.1 "
           "        -AddressFamily IPv4 -ErrorAction Stop; "
           "  $ip.InterfaceIndex "
           "} catch { 'none' }")
    rc, out, _err = _run_ps(cmd, timeout=6.0)
    if rc != 0:
        return None
    line = (out or "").strip().splitlines()[0] if out else ""
    if not line or line == "none":
        return None
    try:
        idx = int(line)
    except ValueError:
        return None
    _CACHED_IFACE_INDEX = idx
    _CACHED_IFACE_INDEX_AT = now
    return idx


def _ip_owner_index(ip):
    cmd = (f"try {{ "
           f"  $a = Get-NetIPAddress -IPAddress '{ip}' "
           f"        -AddressFamily IPv4 -ErrorAction Stop; "
           f"  if ($a) {{ $a.InterfaceIndex }} else {{ 'none' }} "
           f"}} catch {{ 'none' }}")
    rc, out, _err = _run_ps(cmd, timeout=6.0)
    if rc != 0:
        return None
    line = (out or "").strip().splitlines()[0] if out else ""
    if not line or line == "none":
        return None
    try:
        return int(line)
    except ValueError:
        return None


def _ip_owned_by_loopback(ip, iface_index):
    owner = _ip_owner_index(ip)
    return owner is not None and owner == iface_index


def _add_loopback_ip(ip, iface_index):
    cmd = (f"try {{ "
           f"  New-NetIPAddress -InterfaceIndex {iface_index} "
           f"    -IPAddress '{ip}' -PrefixLength 8 "
           f"    -AddressFamily IPv4 -ErrorAction Stop | Out-Null; "
           f"  'ok' "
           f"}} catch {{ 'fail: ' + $_.Exception.Message }}")
    rc, out, _err = _run_ps(cmd, timeout=10.0)
    if rc != 0:
        return False, (out or "add failed").strip()[:200]
    if "fail:" in (out or ""):
        return False, out.strip()[:200]
    for _ in range(3):
        if _ip_owned_by_loopback(ip, iface_index):
            return True, ""
        time.sleep(0.4)
    return False, f"added but not visible: {ip}"


def _remove_loopback_ip(ip, iface_index):
    cmd = (f"try {{ "
           f"  Remove-NetIPAddress -InterfaceIndex {iface_index} "
           f"    -IPAddress '{ip}' -AddressFamily IPv4 "
           f"    -Confirm:$false -ErrorAction Stop; "
           f"  'ok' "
           f"}} catch {{ 'fail: ' + $_.Exception.Message }}")
    rc, out, _err = _run_ps(cmd, timeout=10.0)
    if rc != 0:
        return False, (out or "remove failed").strip()[:200]
    if "fail:" in (out or ""):
        return False, out.strip()[:200]
    for _ in range(3):
        if not _ip_owned_by_loopback(ip, iface_index):
            return True, ""
        time.sleep(0.4)
    return False, f"removed but still visible: {ip}"


def _list_loopback_ips(iface_index):
    if iface_index <= 0:
        return []
    cmd = (f"try {{ "
           f"  Get-NetIPAddress -InterfaceIndex {iface_index} "
           f"    -AddressFamily IPv4 -ErrorAction Stop | "
           f"  ForEach-Object {{ $_.IPAddress }} "
           f"}} catch {{ '' }}")
    rc, out, _err = _run_ps(cmd, timeout=6.0)
    if rc != 0:
        return []
    ips = []
    for line in (out or "").splitlines():
        s = line.strip()
        if not s:
            continue
        try:
            ipaddress.IPv4Address(s)
            ips.append(s)
        except ValueError:
            continue
    return ips


def _decode_bytes(raw):
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


def _read_text_with_encoding(path):
    with open(path, "rb") as f:
        raw = f.read()
    return _decode_bytes(raw)


def _write_text_with_encoding(path, text, bom, encoding):
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


def _copy_acl_windows(src, dst):
    se = src.replace("'", "''")
    de = dst.replace("'", "''")
    cmd = (f"try {{ "
           f"  $acl = Get-Acl -LiteralPath '{se}'; "
           f"  Set-Acl -LiteralPath '{de}' -AclObject $acl; "
           f"  'ok' "
           f"}} catch {{ 'fail' }}")
    rc, out, _err = _run_ps(cmd, timeout=10.0)
    return rc == 0 and "ok" in (out or "")


def _validate_loopback_target(ip, base_ip):
    if not isinstance(ip, str) or not ip.strip():
        return "empty target IP"
    try:
        addr = ipaddress.IPv4Address(ip.strip())
    except Exception as e:
        return f"not a valid IPv4 address: {e}"
    if addr not in _LOOPBACK_NET:
        return f"{ip} is outside 127.0.0.0/8"
    if str(addr) == base_ip:
        return f"{ip} is the base loopback address"
    if str(addr) == _BROADCAST_IP:
        return f"{ip} is the loopback broadcast address"
    return None


def _parse_listen_address(content):
    head, _tail = _split_head_tail(content)
    for line in head.splitlines():
        m = re.match(r"^\s*ListenAddress\s+(\S+)", line, re.IGNORECASE)
        if not m:
            continue
        value = m.group(1).strip()
        if value.startswith("["):
            end = value.find("]")
            if end < 0:
                return (value, None, True)
            addr = value[1:end]
            port = None
            if len(value) > end + 1 and value[end + 1] == ":":
                try:
                    port = int(value[end + 2:])
                except ValueError:
                    port = None
            return (addr, port, True)
        if value.count(":") == 1:
            addr_s, port_s = value.split(":", 1)
            try:
                return (addr_s, int(port_s), False)
            except ValueError:
                return (addr_s, None, False)
        try:
            ipaddress.IPv4Address(value)
            return (value, None, False)
        except Exception:
            pass
        try:
            ipaddress.IPv6Address(value)
            return (value, None, True)
        except Exception:
            return (value, None, False)
    return None


def _count_listen_address_lines(content):
    head, _tail = _split_head_tail(content)
    n = 0
    for line in head.splitlines():
        if re.match(r"^\s*ListenAddress\s+\S", line, re.IGNORECASE):
            n += 1
    return n


def _parse_port(content):
    head, _tail = _split_head_tail(content)
    for line in head.splitlines():
        m = re.match(r"^\s*Port\s+(\d+)", line, re.IGNORECASE)
        if m:
            try:
                return int(m.group(1))
            except ValueError:
                continue
    return None


class AddressRotationAction(MTDAction):
    name = "address_rotation"
    one_shot = False
    requires_admin = True

    @classmethod
    def supports(cls, capability, context):
        return capability == "ssh"

    def __init__(self, capability, context):
        super().__init__(capability, context)
        ctx = context if isinstance(context, dict) else {}
        self._lock_key = f"address_rotation::{capability}"

        self.config_path = _coerce_str(ctx.get("config_path"),
                                       SSHD_CONFIG_PATH)
        self.binary_path = _coerce_str(ctx.get("binary_path"),
                                       SSHD_BINARY_PATH)
        self.service_name = _coerce_str(ctx.get("service_name"),
                                        SSHD_SERVICE_NAME)
        self.backup_path = self.config_path + ".acf.bak"

        self.base_ip = _coerce_str(ctx.get("base_ip"), DEFAULT_BASE_IP)
        self.alternate_ip = _coerce_str(ctx.get("alternate_ip"),
                                        DEFAULT_ALTERNATE_IP)
        self.aggressive_ip = _coerce_str(ctx.get("aggressive_ip"),
                                         DEFAULT_AGGRESSIVE_IP)

        self.listen_port_for_verify = _coerce_optional_int(
            ctx.get("listen_port_for_verify"), None, 1, 65535)
        self.rename_retries = _coerce_int(
            ctx.get("rename_retries"), DEFAULT_RENAME_RETRIES, 0, 20)
        self.rename_retry_delay = _coerce_float(
            ctx.get("rename_retry_delay"), DEFAULT_RENAME_RETRY_DELAY,
            0.0, 10.0)
        self.remove_previous_ip = _coerce_bool(
            ctx.get("remove_previous_ip"), DEFAULT_REMOVE_PREVIOUS)
        self.min_seconds_between_rotations = _coerce_float(
            ctx.get("min_seconds_between_rotations"),
            DEFAULT_MIN_SECONDS_BETWEEN, 0.0, 3600.0)
        self.claim_configured_range = _coerce_bool(
            ctx.get("claim_configured_range"), DEFAULT_CLAIM_RANGE)

        self._last_state = ""
        self._current_ip = ""
        self._previous_ip = ""
        self._target_ip = ""
        self._is_active = False
        self._last_read_ok = False
        self._listen_address_present = False
        self._initialized_ip = False
        self.config_hash = ""
        self._added_ips = []
        self._last_removed_ips = []
        self.orphaned_ips = []
        self._last_rotation_ts = 0.0
        self._rotations_total = 0
        self._last_rotation_info = {}
        self.actions = []
        self._acl_warning = ""
        self._address_state_uncertain = False
        self._address_state_uncertain_reason = ""
        self._address_state_uncertain_at = 0.0
        self._preflight_reason = ""
        self._construction_warnings = []

        with _get_snapshot_lock(self._lock_key):
            self._refresh_locked()
        self._check_environment(force_iface_lookup=True)

    def _refresh_locked(self):
        try:
            with open(self.config_path, "rb") as f:
                raw = f.read()
        except Exception:
            self._last_read_ok = False
            self.config_hash = ""
            self._listen_address_present = False
            return
        try:
            content, _bom, _enc = _decode_bytes(raw)
        except Exception:
            self._last_read_ok = False
            self.config_hash = ""
            self._listen_address_present = False
            return
        self.config_hash = hashlib.sha256(raw).hexdigest()
        parsed = _parse_listen_address(content)
        self._listen_address_present = parsed is not None
        if parsed is not None:
            self._current_ip = parsed[0]
        else:
            self._current_ip = self.base_ip
        self._last_read_ok = True
        if not self._initialized_ip:
            self._previous_ip = self._current_ip
            self._target_ip = self._current_ip
            self._initialized_ip = True
        self._is_active = (self._current_ip != self.base_ip)

    def _refresh(self):
        with _get_snapshot_lock(self._lock_key):
            self._refresh_locked()

    def _check_environment(self, force_iface_lookup=False):
        self._preflight_reason = ""
        self._construction_warnings = []
        if not os.path.isfile(self.config_path):
            self._preflight_reason = f"config not found: {self.config_path}"
            return
        if not os.path.isfile(self.binary_path):
            self._preflight_reason = "sshd binary not found"
            return
        if not _resolve_powershell():
            self._preflight_reason = "no PowerShell binary found"
            return
        if _loopback_interface_index(force=force_iface_lookup) is None:
            self._preflight_reason = "cannot resolve loopback interface"
            return
        for ip in (self.alternate_ip, self.aggressive_ip):
            reason = _validate_loopback_target(ip, self.base_ip)
            if reason:
                self._preflight_reason = f"invalid target IP: {reason}"
                return
        try:
            content, _bom, _enc = _read_text_with_encoding(
                self.config_path)
        except Exception as e:
            self._preflight_reason = f"cannot read config: {e}"
            return
        n = _count_listen_address_lines(content)
        if n > 1:
            self._preflight_reason = (
                f"config has {n} top-level ListenAddress lines; "
                f"this action rotates a single listener")
            return
        parsed = _parse_listen_address(content)
        if parsed is not None and parsed[2]:
            self._preflight_reason = (
                "config ListenAddress is IPv6; this action rotates "
                "IPv4 loopback addresses only")
            return

    def preflight(self):
        self._check_environment()
        if self._preflight_reason:
            return (STATUS_BLOCKED, "", self._preflight_reason)
        if not _is_admin():
            return (STATUS_BLOCKED, "", "requires elevation")
        rname, state = _service_resolve_and_state(self.service_name)
        if state == "not_installed":
            return (STATUS_BLOCKED, "",
                    f"service '{self.service_name}' not installed")
        if state == "unknown":
            return (STATUS_BLOCKED, "",
                    f"service '{self.service_name}' state unknown")
        if state != "running":
            return (STATUS_BLOCKED, "",
                    f"service '{self.service_name}' is {state}")
        with _get_snapshot_lock(self._lock_key):
            self.service_name = rname or self.service_name
        if _loopback_interface_index() is None:
            return (STATUS_BLOCKED, "",
                    "loopback interface not resolvable")
        return (STATUS_READY, MODE_PRIMARY, "")

    def should_activate(self, state):
        if not isinstance(state, str):
            state = ""
        n = state.strip().upper()
        with _get_snapshot_lock(self._lock_key):
            self._last_state = n
        return n in ("ORANGE", "RED")

    def is_active(self):
        with _get_snapshot_lock(self._lock_key):
            return self._is_active

    def _target_for_state(self, state):
        if state == "RED":
            return self.aggressive_ip
        if state == "ORANGE":
            return self.alternate_ip
        return self.base_ip

    def acknowledge_address_reconciled(self):
        with _get_snapshot_lock(self._lock_key):
            was = self._address_state_uncertain
            self._address_state_uncertain = False
            self._address_state_uncertain_reason = ""
        return True, "cleared" if was else "was not set"

    def activate(self):
        with _get_mutation_lock(self._lock_key):
            self._check_environment(force_iface_lookup=False)
            if self._preflight_reason:
                return False, self._preflight_reason
            if not _is_admin():
                return False, "requires elevation"
            if not os.path.isfile(self.config_path):
                return False, f"config missing: {self.config_path}"
            if os.path.isdir(self.config_path):
                return False, "config path is a directory"
            iface_idx = _loopback_interface_index()
            if iface_idx is None:
                return False, "loopback interface not resolvable"
            with _get_snapshot_lock(self._lock_key):
                state = self._last_state
                self._refresh_locked()
                observed_old = self._current_ip or self.base_ip
            if not state:
                return False, (
                    "should_activate() must be called before activate()")
            if state not in _STATE_TARGET_FIELD:
                self._record("address_rotation", True, "", state=state,
                             noop_reason="state_not_activating")
                return True, ""
            target = self._target_for_state(state)
            reason = _validate_loopback_target(target, self.base_ip)
            if reason:
                return False, f"target invalid: {reason}"
            now = time.time()
            with _get_snapshot_lock(self._lock_key):
                last_ts = self._last_rotation_ts
            if (self.min_seconds_between_rotations > 0
                    and (now - last_ts)
                    < self.min_seconds_between_rotations):
                self._record("address_rotation", True, "",
                             state=state, target=target,
                             noop_reason="rate_limited")
                return True, ""
            with _get_snapshot_lock(self._lock_key):
                self._target_ip = target
            if observed_old == target:
                return True, ""
            self._reconcile_orphans(iface_idx, target)
            ok, err, info = self._perform_rotation(
                target, iface_idx, observed_old)
            with _get_snapshot_lock(self._lock_key):
                self._refresh_locked()
                self._record_locked("address_rotation", ok, err,
                                    state=state, target=target, **info)
                if ok:
                    self._last_rotation_ts = time.time()
                    self._rotations_total += 1
                    self._last_rotation_info = dict(info)
                    self._previous_ip = observed_old
                    self._address_state_uncertain = False
                    self._address_state_uncertain_reason = ""
            if ok:
                _safe_emit(self.capability, _LAYER, "info",
                           f"address rotated {observed_old} -> {target}")
            else:
                _safe_emit(self.capability, _LAYER, "error",
                           f"address rotation failed: {err}")
            return ok, err

    def deactivate(self):
        """
        Reverse transaction: rotate the listener back to base_ip.

        Called by the engine when the state is not an activating
        state and is_active() reports True. Symmetric with
        PortShuffleAction.deactivate().

        Rate-limit: not enforced here. The safe direction (returning
        to base_ip) is always allowed, and no timestamp is refreshed.
        See the module docstring for the reasoning.
        """
        with _get_mutation_lock(self._lock_key):
            self._check_environment(force_iface_lookup=False)
            if self._preflight_reason:
                return False, self._preflight_reason
            if not _is_admin():
                return False, "requires elevation"
            if not os.path.isfile(self.config_path):
                return False, f"config missing: {self.config_path}"
            iface_idx = _loopback_interface_index()
            if iface_idx is None:
                return False, "loopback interface not resolvable"

            with _get_snapshot_lock(self._lock_key):
                self._refresh_locked()
                observed_old = self._current_ip or self.base_ip

            if observed_old == self.base_ip:
                return True, ""

            self._reconcile_orphans(iface_idx, self.base_ip)
            ok, err, info = self._perform_rotation(
                self.base_ip, iface_idx, observed_old)

            with _get_snapshot_lock(self._lock_key):
                self._refresh_locked()
                self._record_locked("address_restore", ok, err, **info)
                if ok:
                    self._previous_ip = observed_old

            if ok:
                _safe_emit(self.capability, _LAYER, "info",
                           f"address restored {observed_old} -> "
                           f"{self.base_ip}")
            else:
                _safe_emit(self.capability, _LAYER, "error",
                           f"address restore failed: {err}")
            return ok, err

    def _perform_rotation(self, target, iface_idx, old_ip):
        info = {"old_ip": old_ip, "new_ip": target}
        owner = _ip_owner_index(target)
        if owner is not None and owner != iface_idx:
            return False, (
                f"{target} is assigned to a non-loopback interface"), info
        added_here = False
        if owner != iface_idx:
            with _get_snapshot_lock(self._lock_key):
                if len(self._added_ips) >= MAX_ADDED_IPS:
                    return False, "_added_ips limit reached", info
            ok, err = _add_loopback_ip(target, iface_idx)
            if not ok:
                return False, f"add IP failed: {err}", info
            added_here = True
            with _get_snapshot_lock(self._lock_key):
                if target not in self._added_ips:
                    self._added_ips.append(target)
        info["ip_added"] = added_here

        try:
            shutil.copy2(self.config_path, self.backup_path)
        except Exception as e:
            self._maybe_remove(target, added_here, iface_idx)
            self._cleanup_backup()
            return False, f"backup failed: {e}", info

        try:
            original_text, bom, encoding = _read_text_with_encoding(
                self.config_path)
        except Exception as e:
            self._maybe_remove(target, added_here, iface_idx)
            self._cleanup_backup()
            return False, f"config read failed: {e}", info

        try:
            new_text = self._rewrite_listen_address(
                original_text, target)
        except Exception as e:
            self._maybe_remove(target, added_here, iface_idx)
            self._cleanup_backup()
            return False, f"rewrite failed: {e}", info

        tmp = self.config_path + ".tmp"
        try:
            _write_text_with_encoding(tmp, new_text, bom, encoding)
        except Exception as e:
            self._safe_remove(tmp)
            self._maybe_remove(target, added_here, iface_idx)
            self._cleanup_backup()
            return False, f"temp write failed: {e}", info

        if not _copy_acl_windows(self.config_path, tmp):
            self._acl_warning = "ACL not preserved on config rewrite"
            _safe_emit(self.capability, _LAYER, "warn",
                       self._acl_warning)
        else:
            self._acl_warning = ""

        ok, err = self._validate_config_syntax(tmp)
        if not ok:
            self._safe_remove(tmp)
            self._maybe_remove(target, added_here, iface_idx)
            self._cleanup_backup()
            return False, f"temp validation failed: {err}", info

        last_err = None
        replaced = False
        for attempt in range(FILE_LOCK_RETRIES):
            try:
                os.replace(tmp, self.config_path)
                replaced = True
                break
            except (PermissionError, OSError) as e:
                last_err = e
                if attempt + 1 < FILE_LOCK_RETRIES:
                    time.sleep(FILE_LOCK_DELAYS[attempt])
        if not replaced:
            self._safe_remove(tmp)
            self._maybe_remove(target, added_here, iface_idx)
            self._cleanup_backup()
            return False, f"replace failed: {last_err}", info

        ok, err = self._validate_config_effective(target)
        if not ok:
            self._rollback(target, old_ip, added_here, iface_idx,
                           info, "effective check failed: " + err)
            return False, f"effective check failed: {err}", info

        ok, err = _service_stop(self.service_name)
        if not ok:
            self._rollback(target, old_ip, added_here, iface_idx,
                           info, "service stop failed: " + err)
            return False, f"service stop failed: {err}", info
        ok, err = _service_start(self.service_name)
        if not ok:
            self._rollback(target, old_ip, added_here, iface_idx,
                           info, "service start failed: " + err)
            return False, f"service start failed: {err}", info

        port = self._effective_verify_port()
        if port is None:
            self._rollback(target, old_ip, added_here, iface_idx,
                           info, "cannot determine verify port")
            return False, "cannot determine verify port", info
        info["verify_port"] = port

        if not self._verify_listener(target, port):
            self._rollback(target, old_ip, added_here, iface_idx,
                           info,
                           f"listener not bound to {target}:{port}")
            return False, (
                f"listener not bound to {target}:{port} after restart"), \
                info

        info["previous_removed"] = False
        if (self.remove_previous_ip and old_ip
                and old_ip != self.base_ip and old_ip != target):
            with _get_snapshot_lock(self._lock_key):
                we_own_it = old_ip in self._added_ips
            if we_own_it:
                ok, err = _remove_loopback_ip(old_ip, iface_idx)
                if ok:
                    with _get_snapshot_lock(self._lock_key):
                        if old_ip in self._added_ips:
                            self._added_ips.remove(old_ip)
                        if old_ip not in self._last_removed_ips:
                            self._last_removed_ips.append(old_ip)
                            if len(self._last_removed_ips) > \
                                    MAX_REMOVED_IPS_HISTORY:
                                self._last_removed_ips = \
                                    self._last_removed_ips[
                                        -MAX_REMOVED_IPS_HISTORY:]
                    info["previous_removed"] = True
                else:
                    info["previous_remove_error"] = err

        self._cleanup_backup()
        return True, "", info

    def _effective_verify_port(self):
        try:
            content, _b, _e = _read_text_with_encoding(self.config_path)
        except Exception:
            return self.listen_port_for_verify
        p = _parse_port(content)
        if p is not None:
            return p
        if self.listen_port_for_verify is not None:
            return self.listen_port_for_verify
        return 22

    @staticmethod
    def _rewrite_listen_address(content, new_ip):
        head, tail = _split_head_tail(content)
        pattern = re.compile(r"^(\s*)ListenAddress\s+(\S+)(.*)$",
                             re.IGNORECASE | re.MULTILINE)

        def repl(m):
            indent = m.group(1)
            value = m.group(2)
            rest = m.group(3)
            if value.startswith("["):
                return m.group(0)
            if ":" in value:
                _old, port = value.split(":", 1)
                new_value = f"{new_ip}:{port}"
            else:
                new_value = new_ip
            return f"{indent}ListenAddress {new_value}{rest}"

        new_head, count = pattern.subn(repl, head, count=1)
        if count == 0:
            if new_head and not new_head.endswith("\n"):
                new_head += "\n"
            new_head += f"ListenAddress {new_ip}\n"
        return new_head + tail

    def _validate_config_syntax(self, path):
        try:
            r = subprocess.run([self.binary_path, "-t", "-f", path],
                               capture_output=True, text=True, timeout=10,
                               encoding="utf-8", errors="replace")
            if r.returncode != 0:
                return False, (r.stderr or r.stdout or "").strip()[:200]
            return True, ""
        except Exception as e:
            return False, str(e)[:200]

    def _validate_config_effective(self, expected_ip):
        try:
            r = subprocess.run([self.binary_path, "-T", "-f",
                                self.config_path],
                               capture_output=True, text=True, timeout=10,
                               encoding="utf-8", errors="replace")
            if r.returncode != 0:
                return False, (r.stderr or r.stdout or "").strip()[:200]
            found = False
            for line in (r.stdout or "").splitlines():
                m = re.match(r"^listenaddress\s+(\S+)\s*$",
                             line.strip(), re.IGNORECASE)
                if not m:
                    continue
                found = True
                value = m.group(1)
                if value.startswith("["):
                    return False, f"effective is IPv6: {value}"
                ip_part = value.split(":", 1)[0]
                if ip_part != expected_ip:
                    return False, (
                        f"effective is {ip_part}, expected {expected_ip}")
            if not found:
                return False, "no ListenAddress in sshd -T output"
            return True, ""
        except Exception as e:
            return False, str(e)[:200]

    def _verify_listener(self, ip, port):
        delay = PORT_VERIFY_BASE_DELAY
        for _ in range(PORT_VERIFY_RETRIES):
            cmd = (f"try {{ "
                   f"  $c = Get-NetTCPConnection "
                   f"        -LocalAddress '{ip}' "
                   f"        -LocalPort {port} "
                   f"        -State Listen -ErrorAction Stop; "
                   f"  if ($c) {{ 'yes' }} else {{ 'no' }} "
                   f"}} catch {{ 'no' }}")
            rc, out, _err = _run_ps(cmd, timeout=6.0)
            if rc == 0 and "yes" in (out or ""):
                return True
            time.sleep(delay)
            delay = min(delay * 1.6, PORT_VERIFY_MAX_DELAY)
        return False

    def _rollback(self, target, old_ip, added_here, iface_idx,
                  info, reason):
        try:
            if os.path.isfile(self.backup_path):
                tmp = self.config_path + ".tmp"
                shutil.copy2(self.backup_path, tmp)
                _copy_acl_windows(self.backup_path, tmp)
                replaced = False
                for attempt in range(FILE_LOCK_RETRIES):
                    try:
                        os.replace(tmp, self.config_path)
                        replaced = True
                        break
                    except (PermissionError, OSError):
                        if attempt + 1 < FILE_LOCK_RETRIES:
                            time.sleep(FILE_LOCK_DELAYS[attempt])
                if not replaced:
                    self._safe_remove(tmp)
                    self._mark_uncertain(
                        f"rollback replace failed ({reason})")
                else:
                    ok_s, _ = _service_stop(self.service_name)
                    ok_t, _ = _service_start(self.service_name)
                    if not (ok_s and ok_t):
                        self._mark_uncertain(
                            f"rollback restart failed ({reason})")
                    else:
                        port = self._effective_verify_port()
                        if port is None:
                            self._mark_uncertain(
                                f"rollback cannot determine verify "
                                f"port ({reason})")
                        elif old_ip and not self._verify_listener(
                                old_ip, port):
                            self._mark_uncertain(
                                f"rollback started but listener not "
                                f"bound to {old_ip}:{port} ({reason})")
        except Exception as e:
            self._mark_uncertain(
                f"rollback exception: {e} ({reason})")

        if added_here:
            ok, err = _remove_loopback_ip(target, iface_idx)
            if ok:
                with _get_snapshot_lock(self._lock_key):
                    if target in self._added_ips:
                        self._added_ips.remove(target)
                    if target not in self._last_removed_ips:
                        self._last_removed_ips.append(target)
                        if len(self._last_removed_ips) > \
                                MAX_REMOVED_IPS_HISTORY:
                            self._last_removed_ips = \
                                self._last_removed_ips[
                                    -MAX_REMOVED_IPS_HISTORY:]
            else:
                self._mark_uncertain(
                    f"rollback could not remove {target}: {err} "
                    f"({reason})")

        info["rollback_reason"] = reason
        self._cleanup_backup()

    def _mark_uncertain(self, reason):
        with _get_snapshot_lock(self._lock_key):
            self._address_state_uncertain = True
            self._address_state_uncertain_reason = reason[:200]
            self._address_state_uncertain_at = time.time()

    def _maybe_remove(self, ip, added_here, iface_idx):
        if not added_here:
            return
        ok, _err = _remove_loopback_ip(ip, iface_idx)
        if ok:
            with _get_snapshot_lock(self._lock_key):
                if ip in self._added_ips:
                    self._added_ips.remove(ip)

    def _cleanup_backup(self):
        try:
            if os.path.isfile(self.backup_path):
                os.remove(self.backup_path)
        except Exception:
            pass

    def _reconcile_orphans(self, iface_idx, target):
        current = _list_loopback_ips(iface_idx)
        with _get_snapshot_lock(self._lock_key):
            owned = set(self._added_ips)
        configured = {self.alternate_ip, self.aggressive_ip}
        orphans = []
        for ip in current:
            if ip == self.base_ip or ip == target:
                continue
            in_range = ip in configured
            in_owned = ip in owned
            if in_range and self.claim_configured_range:
                orphans.append(ip)
            elif in_owned:
                orphans.append(ip)
        with _get_snapshot_lock(self._lock_key):
            self.orphaned_ips = list(orphans)
        for ip in orphans:
            ok, err = _remove_loopback_ip(ip, iface_idx)
            if ok:
                with _get_snapshot_lock(self._lock_key):
                    if ip in self._added_ips:
                        self._added_ips.remove(ip)
            else:
                # Surface the failure instead of swallowing it.
                _safe_emit(self.capability, _LAYER, "warn",
                           f"could not remove orphan loopback IP "
                           f"{ip}: {err}")
                self._record("orphan_remove_failed", False,
                             err, ip=ip)

    def _record_locked(self, action, ok, err="", **fields):
        entry = {"ts": time.time(), "action": action, "ok": ok}
        for k, v in fields.items():
            if isinstance(v, str) and len(v) > MAX_RECORD_FIELD_LEN:
                v = v[:MAX_RECORD_FIELD_LEN]
            entry[k] = v
        if err:
            entry["error"] = err[:MAX_RECORD_FIELD_LEN]
        self.actions.append(entry)
        if len(self.actions) > MAX_ACTION_HISTORY:
            self.actions = self.actions[-MAX_ACTION_HISTORY:]

    def _record(self, action, ok, err="", **fields):
        with _get_snapshot_lock(self._lock_key):
            self._record_locked(action, ok, err, **fields)

    @staticmethod
    def _safe_remove(path):
        try:
            if os.path.exists(path):
                os.remove(path)
        except Exception:
            pass

    def status(self):
        with _get_snapshot_lock(self._lock_key):
            return {
                "backend": "address_rotation",
                "config_path": self.config_path,
                "config_hash": self.config_hash,
                "service_name": self.service_name,
                "base_ip": self.base_ip,
                "alternate_ip": self.alternate_ip,
                "aggressive_ip": self.aggressive_ip,
                "current_ip": self._current_ip,
                "previous_ip": self._previous_ip,
                "target_ip": self._target_ip,
                "active": self._is_active,
                "active_verified": self._last_read_ok,
                "listen_address_present":
                    self._listen_address_present,
                "added_ips": list(self._added_ips),
                "last_removed_ips": list(self._last_removed_ips),
                "orphaned_ips": list(self.orphaned_ips),
                "claim_configured_range": self.claim_configured_range,
                "last_state": self._last_state,
                "last_rotation_ts": self._last_rotation_ts,
                "rotations_total": self._rotations_total,
                "last_rotation_info": dict(self._last_rotation_info),
                "address_state_uncertain":
                    self._address_state_uncertain,
                "address_state_uncertain_at":
                    self._address_state_uncertain_at,
                "address_state_uncertain_reason":
                    self._address_state_uncertain_reason,
                "listen_port_for_verify": self.listen_port_for_verify,
                "acl_warning": self._acl_warning,
                "construction_warnings":
                    list(self._construction_warnings),
                "actions": list(self.actions[-MAX_ACTION_HISTORY:]),
            }