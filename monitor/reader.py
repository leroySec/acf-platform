#!/usr/bin/env python3
# ============================================================================
# READER — Single reader for the whole system
# ============================================================================
# FIX (PAYLOAD): _record_from_xml now extracts the OpenSSH message from the
# named "payload" field instead of the first <Data> element. The first
# <Data> element in an OpenSSH event is "process" (value "sshd"), not the
# authentication message. The monitor rule matches "Failed password" in
# event_strings, so the wrong extraction produced zero detections.
# ============================================================================

import os
import sys
import json
import time
import signal
import threading
import re
import hashlib
import ipaddress
import queue
import subprocess

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from platform_utils import acquire_lock, release_lock, get_temp_dir
from config import Config

try:
    from event_emit import emit
    _EVENT_EMIT_AVAILABLE = True
except ImportError:
    _EVENT_EMIT_AVAILABLE = False
    def emit(src, layer, level, msg, capability=None, cycle=None):
        ts = time.strftime("%H:%M:%S")
        print(f"[{ts}][{src}][{layer}][{level.upper()}] {msg}")


_CAP_PREFIX_RE = re.compile(r"^\[([A-Za-z0-9_\-]+)\]\s*")


def _split_capability(m):
    if not isinstance(m, str):
        return None, m
    match = _CAP_PREFIX_RE.match(m)
    if match:
        return match.group(1), m[match.end():]
    return None, m


def _boot_print(m):  emit(SRC, LAYER, "debug", f"[BOOT] {m}")
def _loop_print(m):
    cap, rest = _split_capability(m)
    emit(SRC, LAYER, "debug", f"[LOOP] {rest}", capability=cap)
def _err_print(m):
    cap, rest = _split_capability(m)
    emit(SRC, LAYER, "error", f"[ERR] {rest}", capability=cap)
def _sub_print(m):
    cap, rest = _split_capability(m)
    emit(SRC, LAYER, "debug", f"[SUB] {rest}", capability=cap)
def _cyc_print(m):
    cap, rest = _split_capability(m)
    emit(SRC, LAYER, "debug", f"[CYCLE] {rest}", capability=cap)
def _file_print(m):
    cap, rest = _split_capability(m)
    emit(SRC, LAYER, "debug", f"[FILE] {rest}", capability=cap)
def _evt_print(m):
    cap, rest = _split_capability(m)
    emit(SRC, LAYER, "debug", f"[EVT] {rest}", capability=cap)


SRC = "reader"
LAYER = "-"

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYSTEM_CONFIG_FILE = os.path.join(ROOT, "system_config.json")
BLACKBOARD_FILE = Config.BLACKBOARD_FILE
HEARTBEAT_FILE = os.path.join(get_temp_dir(), "acf_reader.heartbeat")

READER_CYCLE_SECONDS = 10
MIN_CYCLE_SECONDS = 3
MAX_CYCLE_SECONDS = 30
WATCHDOG_MULTIPLIER = 5
OWNERSHIP_STALE_CYCLES = 6
GAP_THRESHOLD_MULTIPLIER = 2

MAX_READ_BYTES = 10 * 1024
MAX_RECENT_LINES = 200
FINGERPRINT_BYTES = 64
WINDOWS_LOCK_RETRIES = 5
WINDOWS_LOCK_DELAY = 1.0

EVENTLOG_MAX_PER_CYCLE = 50
EVENTLOG_CATCHUP_BUDGET_SECONDS = 5.0
EVENTLOG_QUEUE_MAXSIZE = 200_000
EVENTLOG_SUBSCRIBE_RETRY_SECONDS = 60.0
EVENTLOG_STALL_WARN_CYCLES = 30
EVENTLOG_STALL_WARN_INTERVAL = 300.0

EVT_QUERY_CHANNEL_PATH       = 0x1
EVT_QUERY_FORWARD            = 0x100
EVT_QUERY_TOLERATE_ERRORS    = 0x1000
EVT_RENDER_EVENT_XML         = 1
EVT_RENDER_BOOKMARK          = 2
EVT_SEEK_RELATIVE_TO_BOOKMARK = 4

_EVTX_MAGIC = b'ElfFile\x00'

_H16 = r'[0-9a-fA-F]{1,4}'
_IPV4_OCTET = r'(?:25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])'
_IPV4 = r'(?:' + _IPV4_OCTET + r'\.){3}' + _IPV4_OCTET
_LS32 = r'(?:' + _H16 + r':' + _H16 + r'|' + _IPV4 + r')'

_IPV6_PATTERN = (
    r'(?:'
    + r'(?:' + _H16 + r':){6}' + _LS32
    + r'|::(?:' + _H16 + r':){5}' + _LS32
    + r'|(?:' + _H16 + r')?::(?:' + _H16 + r':){4}' + _LS32
    + r'|(?:(?:' + _H16 + r':){0,1}' + _H16 + r')?::(?:' + _H16 + r':){3}' + _LS32
    + r'|(?:(?:' + _H16 + r':){0,2}' + _H16 + r')?::(?:' + _H16 + r':){2}' + _LS32
    + r'|(?:(?:' + _H16 + r':){0,3}' + _H16 + r')?::' + _H16 + r':' + _LS32
    + r'|(?:(?:' + _H16 + r':){0,4}' + _H16 + r')?::' + _LS32
    + r'|(?:(?:' + _H16 + r':){0,5}' + _H16 + r')?::' + _H16
    + r'|(?:(?:' + _H16 + r':){0,6}' + _H16 + r')?::'
    + r')'
)

_CANDIDATE_IP_REGEX = re.compile(
    r'(?<![0-9a-fA-F:.])'
    r'(' + _IPV6_PATTERN + r'|' + _IPV4 + r')'
    r'(?![0-9a-fA-F:])'
)


try:
    import win32evtlog
    import win32evtlogutil
    HAS_WIN32EVTLOG = True
    WIN32EVTLOG_FILE = getattr(win32evtlog, "__file__", "unknown")
    _WIN32EVTLOG_IMPORT_ERR = ""
except ImportError as e:
    HAS_WIN32EVTLOG = False
    WIN32EVTLOG_FILE = ""
    _WIN32EVTLOG_IMPORT_ERR = str(e)

try:
    from importlib.metadata import version as _pkg_version
    PYWIN32_VERSION = _pkg_version("pywin32")
except Exception:
    PYWIN32_VERSION = "unknown"

_EVT_REQUIRED = ("EvtSubscribe", "EvtRender")
EVT_MISSING_ATTRS = []
if HAS_WIN32EVTLOG:
    for _name in _EVT_REQUIRED:
        if not hasattr(win32evtlog, _name):
            EVT_MISSING_ATTRS.append(_name)
HAS_EVT_SUBSCRIBE = (HAS_WIN32EVTLOG and not EVT_MISSING_ATTRS)
HAS_EVT_CLOSE = HAS_WIN32EVTLOG and hasattr(win32evtlog, "EvtClose")

HAS_EVT_QUERY = HAS_WIN32EVTLOG and hasattr(win32evtlog, "EvtQuery")
HAS_EVT_NEXT = HAS_WIN32EVTLOG and hasattr(win32evtlog, "EvtNext")
HAS_EVT_SEEK = HAS_WIN32EVTLOG and hasattr(win32evtlog, "EvtSeek")
HAS_EVT_BOOKMARK = (
    HAS_WIN32EVTLOG
    and hasattr(win32evtlog, "EvtCreateBookmark")
    and hasattr(win32evtlog, "EvtUpdateBookmark")
)

if HAS_WIN32EVTLOG:
    _FLAG_FUTURE = getattr(win32evtlog, "EvtSubscribeToFutureEvents", 1)
    _ACTION_DELIVER = getattr(win32evtlog, "EvtSubscribeActionDeliver", 1)
    _RENDER_XML = getattr(win32evtlog, "EvtRenderEventXml", 1)
else:
    _FLAG_FUTURE = 1
    _ACTION_DELIVER = 1
    _RENDER_XML = 1

try:
    import psutil
    HAS_PSUTIL = True
except ImportError:
    HAS_PSUTIL = False

_running = True
_last_cycle_time = time.time()
_parent_pid = None


def _marker_file_path(capability):
    return os.path.join(
        get_temp_dir(), f"acf_reader_{capability}.marker.json")


def _marker_read(capability):
    path = _marker_file_path(capability)
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, dict):
            return data
    except FileNotFoundError:
        return {}
    except Exception as e:
        _err_print(f"marker read failed for {capability}: "
                   f"{type(e).__name__}: {e}")
    return {}


def _marker_write(capability, updates):
    path = _marker_file_path(capability)
    current = _marker_read(capability)
    current.update(updates)
    current["marker_timestamp"] = time.time()

    tmp = path + ".tmp"
    try:
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(current, f, indent=2)
            try:
                f.flush()
                os.fsync(f.fileno())
            except Exception:
                pass
        os.replace(tmp, path)
        return True
    except Exception as e:
        _err_print(f"marker write failed for {capability}: "
                   f"{type(e).__name__}: {e}")
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except Exception:
            pass
        return False


def _marker_clear(capability):
    path = _marker_file_path(capability)
    try:
        if os.path.exists(path):
            os.remove(path)
        return True
    except Exception as e:
        _err_print(f"marker clear failed for {capability}: "
                   f"{type(e).__name__}: {e}")
        return False


def _extract_provider_from_xml(xml):
    if not isinstance(xml, str):
        return None
    m = re.search(r"<Provider[^>]*Name=['\"]([^'\"]+)['\"]", xml)
    return m.group(1) if m else None


def _extract_data_fields(xml):
    if not isinstance(xml, str) or not xml:
        return {}
    out = {}
    for m in re.finditer(
            r"<Data\s+Name=['\"]([^'\"]+)['\"]\s*>([^<]*)</Data>", xml):
        name = m.group(1).strip()
        value = m.group(2).strip()
        if name and value:
            out.setdefault(name, value)
    return out


def _has_windows_admin():
    if os.name != 'nt':
        return True
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def _parent_alive(pid):
    if pid is None or pid <= 0:
        return True
    if HAS_PSUTIL:
        try:
            return (psutil.pid_exists(pid)
                    and psutil.Process(pid).status() != psutil.STATUS_ZOMBIE)
        except Exception:
            return False
    if os.name == 'nt':
        try:
            import ctypes
            SYNCHRONIZE = 0x00100000
            WAIT_TIMEOUT = 0x00000102
            k = ctypes.windll.kernel32
            h = k.OpenProcess(SYNCHRONIZE, False, pid)
            if not h:
                return True
            try:
                return k.WaitForSingleObject(h, 0) == WAIT_TIMEOUT
            finally:
                k.CloseHandle(h)
        except Exception:
            return True
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def _check_permissions_at_startup():
    if os.name != 'nt':
        _boot_print("permission check: non-Windows, skipped")
        return
    if _has_windows_admin():
        _boot_print("permission check: elevated, full access")
        return
    emit(SRC, LAYER, "warn",
         "reader is not elevated; Security Event Log and "
         "Windows Firewall log will be unreadable. "
         "Re-run as Administrator for full source access.")
    _boot_print("permission check: NOT elevated")


def _classify_subscription_error(exc):
    if isinstance(exc, TypeError):
        return "signature_mismatch", f"pywin32 rejected arguments: {exc}"
    winerr = getattr(exc, "winerror", None)
    if winerr == 5:
        return "access_denied", "EvtSubscribe requires elevation."
    if winerr == 87:
        return "invalid_parameter", "A parameter was rejected (query or flags)."
    if winerr in (2, 15007):
        return "channel_not_found", f"Channel not accessible: {exc}"
    if winerr == 1314:
        return "privilege_not_held", "SeAuditPrivilege not held."
    if isinstance(exc, OSError):
        return "os_error", f"winerror={winerr}: {exc}"
    return "unknown", f"{type(exc).__name__}: {exc}"


def _boot_diagnostics():
    _boot_print(f"pid={os.getpid()}")
    _boot_print(f"parent pid={_parent_pid}")
    _boot_print(f"cwd={os.getcwd()}")
    _boot_print(f"config={SYSTEM_CONFIG_FILE}")
    _boot_print(f"blackboard={BLACKBOARD_FILE}")
    _boot_print(f"heartbeat={HEARTBEAT_FILE}")
    _boot_print(f"event_emit={'yes' if _EVENT_EMIT_AVAILABLE else 'no'}")
    _boot_print(f"psutil={'yes' if HAS_PSUTIL else 'no'}")
    _boot_print(f"win32evtlog={'yes' if HAS_WIN32EVTLOG else 'no'}")
    if HAS_WIN32EVTLOG:
        _boot_print(f"  pywin32 version={PYWIN32_VERSION}")
        _boot_print(f"  subscription available="
                    f"{'yes' if HAS_EVT_SUBSCRIBE else 'no'}")
        _boot_print(f"  modern query available="
                    f"{'yes' if HAS_EVT_QUERY and HAS_EVT_NEXT else 'no'}")
        _boot_print(f"  bookmark available="
                    f"{'yes' if HAS_EVT_BOOKMARK else 'no'}")


def decode_bytes(data):
    if not data:
        return "", "utf-8", False
    for marker, enc in ((b'\xef\xbb\xbf', 'utf-8'),
                        (b'\xff\xfe', 'utf-16-le'),
                        (b'\xfe\xff', 'utf-16-be')):
        if data.startswith(marker):
            data = data[len(marker):]
            break
    for enc in ('utf-8', 'utf-16-le', 'utf-16-be'):
        try:
            return data.decode(enc), enc, False
        except UnicodeDecodeError:
            continue
    return data.decode('utf-8', errors='replace'), 'utf-8-replace', True


def load_config():
    if not os.path.exists(SYSTEM_CONFIG_FILE):
        return {}, "missing"
    try:
        with open(SYSTEM_CONFIG_FILE, 'r') as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        return {}, f"parse_error: {e}"
    except Exception as e:
        return {}, f"read_error: {e}"
    if not isinstance(data, dict):
        return {}, "not_object"
    return data, None


def _canonical_eventlog_ref(path):
    if not isinstance(path, str):
        return None
    s = path.strip()
    if not s:
        return None
    if s.startswith("Windows Event Log (") and s.endswith(")"):
        inner = s[len("Windows Event Log ("):-1].strip()
        return inner or None
    if s.lower().endswith(".evtx"):
        base = os.path.basename(s)[:-len(".evtx")]
        base = base.replace("%4", "/")
        return base or None
    return s


def _looks_like_evtx(path):
    try:
        with open(path, 'rb') as f:
            return f.read(8) == _EVTX_MAGIC
    except Exception:
        return False


def _classify_source(name, path, declared_type=None):
    if declared_type == "eventlog":
        canonical = _canonical_eventlog_ref(path)
        if canonical:
            return ("eventlog", canonical)
        return ("unknown", f"cannot derive channel from: {path!r}")
    if declared_type == "file":
        if isinstance(path, str) and os.path.isfile(path):
            if _looks_like_evtx(path):
                return ("unknown",
                        f"{path!r} is a Windows Event Log (.evtx) file; "
                        f"declare it with type \"eventlog\", not \"file\"")
        return ("file", path)
    if path and os.path.isfile(path):
        if _looks_like_evtx(path):
            return ("unknown",
                    f"{path!r} is a Windows Event Log (.evtx) file; "
                    f"declare it with type \"eventlog\", not \"file\"")
        return ("file", path)
    if isinstance(path, str) and ("Event Log" in path
                                  or "eventlog" in path.lower()):
        if not HAS_WIN32EVTLOG:
            return ("unknown", "win32evtlog not installed")
        m = re.search(r'\(([^)]+)', path)
        if m:
            return ("eventlog", m.group(1).strip())
        return ("eventlog", "Security")
    if os.name == 'nt' and name == "ssh":
        if HAS_WIN32EVTLOG:
            return ("eventlog", "OpenSSH/Operational")
        return ("unknown", "win32evtlog not installed")
    if not path:
        return ("unknown", "no path configured")
    return ("unknown", f"not a file and not a recognized event log: {path}")


def _coerce_event_ids(value):
    if value is None:
        return [], None
    if isinstance(value, bool):
        return [], "event_ids is a boolean, not an ID or ID list"
    if isinstance(value, int):
        if value <= 0:
            return [], f"event_ids {value} is not a positive ID"
        return [value], None
    if isinstance(value, str):
        parts = re.split(r'[\s,]+', value.strip())
        ids = []
        seen = set()
        for p in parts:
            if not p:
                continue
            try:
                n = int(p)
            except ValueError:
                return [], f"event_ids contains non-numeric value: {p!r}"
            if n <= 0:
                return [], f"event_ids contains non-positive value: {p!r}"
            if n not in seen:
                seen.add(n)
                ids.append(n)
        return ids, None
    if isinstance(value, list):
        ids = []
        seen = set()
        for item in value:
            if isinstance(item, bool):
                return [], "event_ids contains a boolean"
            n = None
            if isinstance(item, int):
                n = item
            elif isinstance(item, str):
                try:
                    n = int(item)
                except ValueError:
                    return [], f"event_ids contains non-numeric value: {item!r}"
            else:
                return [], (f"event_ids contains an unsupported type: "
                            f"{type(item).__name__}")
            if n <= 0:
                return [], f"event_ids contains non-positive value: {n!r}"
            if n not in seen:
                seen.add(n)
                ids.append(n)
        return ids, None
    return [], f"event_ids has unsupported type: {type(value).__name__}"


def read_sources():
    config, err = load_config()
    if err is not None:
        return {}, [], err

    enabled = config.get("enabled_capabilities", {})
    paths = config.get("capability_paths", {})
    sources = config.get("capability_sources", {})
    if not isinstance(sources, dict):
        sources = {}
    accepted, skipped = {}, []

    def _h(name, path):
        src = sources.get(name)
        declared_type = None
        declared_ids = None
        if isinstance(src, dict):
            declared_type = src.get("type")
            declared_ids = src.get("event_ids")
        kind, ref = _classify_source(name, path, declared_type)
        if kind == "unknown":
            skipped.append((name, ref))
            return
        if kind == "eventlog":
            ids, ids_err = _coerce_event_ids(declared_ids)
            if ids_err is not None:
                skipped.append((name,
                                f"eventlog event_ids invalid: {ids_err}"))
                return
            accepted[name] = {
                "type": kind,
                "ref": ref,
                "event_ids": ids,
            }
        else:
            accepted[name] = {
                "type": kind,
                "ref": ref,
                "event_ids": None,
            }

    for name, on in enabled.items():
        if name == "custom" or not on:
            continue
        _h(name, paths.get(name))

    ce = enabled.get("custom", {})
    cp = paths.get("custom", {})
    if isinstance(ce, dict) and isinstance(cp, dict):
        for name, on in ce.items():
            if on:
                _h(name, cp.get(name))

    seen, final = {}, {}
    for name, meta in accepted.items():
        key = (meta["type"], meta["ref"])
        if key in seen:
            skipped.append((name, f"source already used by {seen[key]}"))
            continue
        seen[key] = name
        final[name] = meta
    return final, skipped, None


def _bb_read():
    try:
        with open(BLACKBOARD_FILE, 'r') as f:
            return json.load(f)
    except Exception:
        return {}


def _bb_read_section(section):
    data = _bb_read()
    s = data.get(section, {})
    return s if isinstance(s, dict) else {}


def _bb_update(section, updates):
    try:
        with open(BLACKBOARD_FILE, 'r+') as f:
            acquire_lock(f.fileno(), exclusive=True)
            try:
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    data = {}
                if section not in data or not isinstance(data[section], dict):
                    data[section] = {}
                data[section].update(updates)
                f.seek(0)
                json.dump(data, f, indent=2)
                f.truncate()
                return True
            finally:
                release_lock(f.fileno())
    except Exception as e:
        emit(SRC, LAYER, "error", f"Blackboard update for {section}: {e}")
        _err_print(f"Blackboard update for {section} failed: {e}")
        return False


def _detect_startup_gap(section_name):
    sec = _bb_read_section(section_name)
    last_ts = float(sec.get("reading_timestamp", 0) or 0)
    if last_ts <= 0:
        return None
    now = time.time()
    gap = now - last_ts
    if gap <= GAP_THRESHOLD_MULTIPLIER * READER_CYCLE_SECONDS:
        return None
    return {"reader_gap_start": last_ts, "reader_gap_end": now,
            "reader_gap_seconds": gap,
            "reader_gap_reason": "process_restart",
            "reader_gap_events": None}


def _gap_from_section(section, reason, events=None):
    last_ts = float(section.get("reading_timestamp", 0) or 0)
    now = time.time()
    return {"reader_gap_start": last_ts if last_ts > 0 else now,
            "reader_gap_end": now,
            "reader_gap_seconds": (now - last_ts) if last_ts > 0 else None,
            "reader_gap_reason": reason, "reader_gap_events": events}


def _extract_ips(text):
    if not isinstance(text, str) or not text:
        return []
    out = []
    for m in _CANDIDATE_IP_REGEX.finditer(text):
        candidate = m.group(1)
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        out.append(candidate)
    return out


class Backend:
    kind = "base"

    def __init__(self, reader):
        self.reader = reader
        self.name = reader.name
        self.section = reader.section
        self.pathological_drops = 0

    def try_claim(self):
        return self.reader._try_claim_impl(self.section, self.name)

    def release(self):
        _bb_update(self.section, {"reader_owner": ""})

    def read_marker(self):  return None, 0, ""
    def write_marker(self, *a):  pass
    def cycle(self):  raise NotImplementedError
    def shutdown(self):  pass

    def write_output(self, items_read, cumulative, healthy,
                     recent_lines=None, recent_events=None,
                     recent_ips=None, gap=None,
                     encoding=None, lossy=None):
        updates = {
            "last_failures_cumulative": cumulative,
            "reading_timestamp": time.time(),
            "log_source": self.source_label(),
            "backend": self.kind,
            "source": "reader",
            "reader_pathological_drops": self.pathological_drops,
            "version": getattr(Config, "SCHEMA_VERSION", "unknown"),
        }
        if recent_lines is not None:
            recent_lines = recent_lines[-MAX_RECENT_LINES:]
            updates["recent_lines"] = recent_lines
            if encoding is not None:
                updates["recent_lines_encoding"] = encoding
            if lossy is not None:
                updates["recent_lines_lossy"] = lossy
        if recent_events is not None:
            recent_events = recent_events[-EVENTLOG_MAX_PER_CYCLE:]
            updates["recent_events"] = recent_events
            updates["recent_events_ts"] = time.time()
            _evt_print(f"[{self.name}] write_output "
                       f"recent_events={len(recent_events)}")
        else:
            _evt_print(f"[{self.name}] write_output "
                       f"preserving recent_events")
        if recent_ips is not None:
            updates["recent_ips"] = recent_ips
            if recent_ips:
                updates["last_attacker_ip"] = recent_ips[0]
        if self.reader._pending_startup_gap:
            updates.update(self.reader._pending_startup_gap)
            updates["reader_gap_detected"] = True
            self.reader._pending_startup_gap = None
        elif gap:
            updates.update(gap)
            updates["reader_gap_detected"] = True
        else:
            updates["reader_gap_detected"] = False
        ok = _bb_update(self.section, updates)
        _evt_print(f"[{self.name}] write_output ok={ok}")

    def mark_ready(self):
        updates = {
            "reader_ready": True,
            "reader_pid": os.getpid(),
            "reader_last_error": "",
            "reading_timestamp": time.time(),
        }
        if not self.reader._ready_announced:
            updates["reader_started"] = time.time()
            self.reader._ready_announced = True
        _bb_update(self.section, updates)

    def mark_not_ready(self, reason=""):
        updates = {
            "reader_ready": False,
            "reading_timestamp": time.time(),
        }
        if reason:
            updates["reader_last_error"] = reason
        _bb_update(self.section, updates)

    def source_label(self):
        return "unknown"


class FileBackend(Backend):
    kind = "file"

    def __init__(self, reader, path):
        super().__init__(reader)
        self.path = path

    def source_label(self):
        return self.path

    def _identity_key(self, st):
        ino = getattr(st, "st_ino", 0) or 0
        dev = getattr(st, "st_dev", 0) or 0
        if ino and ino > 0:
            return f"i:{dev}:{ino}"
        mtime = getattr(st, "st_mtime", 0)
        size = getattr(st, "st_size", 0)
        return f"ms:{mtime}:{size}"

    def read_marker(self):
        m = _marker_read(self.name)
        if m.get("backend") != self.kind:
            return None, 0, ""
        marker = m.get("last_processed_id", "")
        fp = m.get("last_processed_fingerprint", "")
        if not isinstance(marker, str) or ":" not in marker:
            return None, 0, ""
        identity, _, pos_str = marker.rpartition(":")
        try:
            position = int(pos_str)
        except ValueError:
            return None, 0, ""
        if not identity:
            return None, 0, ""
        if not (identity.startswith("i:") or identity.startswith("ms:")):
            identity = f"i:0:{identity}"
        return identity, position, fp

    def write_marker(self, identity, position, mtime, fingerprint):
        _marker_write(self.name, {
            "backend": self.kind,
            "last_processed_id": f"{identity}:{position}",
            "last_processed_mtime": mtime,
            "last_processed_time": time.time(),
            "last_processed_fingerprint": fingerprint,
        })

    def _open_with_retry(self):
        last = None
        for _ in range(WINDOWS_LOCK_RETRIES):
            try:
                return open(self.path, 'rb')
            except PermissionError as e:
                last = e
                time.sleep(WINDOWS_LOCK_DELAY)
        raise last or PermissionError("open failed")

    def _open_and_fstat(self):
        f = self._open_with_retry()
        try:
            return f, os.fstat(f.fileno())
        except Exception:
            f.close()
            raise

    def _fingerprint(self, f, pos):
        if pos <= 0:
            return ""
        start = max(0, pos - FINGERPRINT_BYTES)
        try:
            f.seek(start)
            data = f.read(pos - start)
        except Exception:
            return ""
        return hashlib.sha256(data).hexdigest() if data else ""

    def _read_chunk(self, f, start, max_bytes):
        f.seek(start)
        data = f.read(max_bytes)
        if not data:
            return "", 0, "utf-8", False
        idx = data.rfind(b'\n')
        if idx == -1:
            idx = data.rfind(b'\r')
        if idx == -1:
            if len(data) >= max_bytes:
                self.pathological_drops += 1
                text, enc, _ = decode_bytes(data)
                emit(self.name, LAYER, "warn",
                     f"line exceeds {max_bytes}B; emitting "
                     f"{len(data)}B as truncated "
                     f"(total drops: {self.pathological_drops})")
                return text + "\n", len(data), enc, True
            return "", 0, "utf-8", False
        text, encoding, lossy = decode_bytes(data[:idx + 1])
        return text, idx + 1, encoding, lossy

    def _split_lines(self, text):
        out = []
        for line in text.splitlines():
            if line.strip():
                out.append(line)
        return out

    def cycle(self):
        if not self.try_claim():
            _cyc_print(f"[{self.name}] claim failed; skipping cycle")
            return
        _cyc_print(f"[{self.name}] claim OK")
        try:
            f, st = self._open_and_fstat()
        except FileNotFoundError:
            _file_print(f"[{self.name}] open FileNotFoundError "
                        f"path={self.path}")
            emit(self.name, LAYER, "warn", f"log file missing: {self.path}")
            self.mark_not_ready("file missing")
            return
        except PermissionError as e:
            _file_print(f"[{self.name}] open PermissionError {e}")
            self.mark_not_ready(f"open denied: {e}")
            return
        except OSError as e:
            _file_print(f"[{self.name}] open OSError {e}")
            self.mark_not_ready(f"open failed: {e}")
            return
        try:
            size = st.st_size
            mtime = st.st_mtime
            identity = self._identity_key(st)
            section = _bb_read_section(self.section)
            last_identity, last_pos, last_fp = self.read_marker()
            cumulative = int(section.get("last_failures_cumulative", 0) or 0)

            start_pos, gap = 0, None
            start_reason = "fresh_start"
            if last_identity == identity:
                start_pos = last_pos
                start_reason = "resumed_from_marker"
                if size < start_pos:
                    start_pos = 0
                    start_reason = "file_shrank"
                elif start_pos > 0 and last_fp:
                    if self._fingerprint(f, start_pos) != last_fp:
                        start_pos = 0
                        start_reason = "fingerprint_mismatch"
            else:
                if last_identity is not None:
                    gap = _gap_from_section(section, "identity_changed")
                    start_reason = "identity_changed"

            if size > start_pos:
                text, consumed, encoding, lossy = self._read_chunk(
                    f, start_pos, MAX_READ_BYTES)
                if consumed > 0:
                    lines = self._split_lines(text)
                    n = len(lines)
                    cumulative += n
                    new_pos = start_pos + consumed
                    ips = _extract_ips("\n".join(lines))
                    self.write_output(
                        items_read=n,
                        cumulative=cumulative,
                        healthy=True,
                        recent_lines=lines,
                        recent_ips=ips,
                        gap=gap,
                        encoding=encoding,
                        lossy=lossy,
                    )
                    fp = self._fingerprint(f, new_pos)
                    self.write_marker(identity, new_pos, mtime, fp)
                    emit(self.name, LAYER, "info",
                         f"Cycle | lines={n} | ips={len(ips)} "
                         f"| enc={encoding} | lossy={lossy}")
                else:
                    self.write_output(
                        items_read=0,
                        cumulative=cumulative,
                        healthy=True,
                        recent_lines=[],
                        recent_ips=[],
                        gap=gap,
                        encoding="utf-8",
                        lossy=False,
                    )
                    emit(self.name, LAYER, "info",
                         "Cycle | no new complete lines")
            else:
                self.write_output(
                    items_read=0,
                    cumulative=cumulative,
                    healthy=True,
                    recent_lines=[],
                    recent_ips=[],
                    gap=gap,
                    encoding="utf-8",
                    lossy=False,
                )
                emit(self.name, LAYER, "info", "Cycle | no new data")
            self.mark_ready()
        finally:
            f.close()


class EventLogBackend(Backend):
    kind = "eventlog"

    def __init__(self, reader, log_name, event_ids=None):
        super().__init__(reader)
        self.log_name = log_name
        self._event_ids = list(event_ids) if event_ids else []
        self._subscription_handle = None
        self._active = False
        self._initialized = False
        self._stop_requested = False
        self._next_retry_ts = 0.0
        self._error_category = ""
        self._error_detail = ""
        self._queue = queue.Queue(maxsize=EVENTLOG_QUEUE_MAXSIZE)
        self._dropped = 0
        self._catchup_high_water = 0
        self._highest = 0
        self._events_delivered = 0
        self._last_events_delivered = 0
        self._stalled_cycles = 0
        self._last_stall_warn = 0.0

    def source_label(self):
        return f"Windows Event Log ({self.log_name})"

    def _make_record(self, event_id, record_id, timestamp, ips,
                     event_xml=None, event_strings=None,
                     user=None, threat_name=None,
                     path=None, process_name=None):
        provider = None
        if event_xml:
            provider = _extract_provider_from_xml(event_xml)
        record = {
            "event_id": event_id,
            "record_id": record_id,
            "channel": self.log_name,
            "provider": provider,
            "timestamp": timestamp,
            "ips": ips or [],
            "event_xml": None,
            "event_strings": event_strings,
        }
        if user is not None:
            record["user"] = user
        if threat_name is not None:
            record["threat_name"] = threat_name
        if path is not None:
            record["path"] = path
        if process_name is not None:
            record["process_name"] = process_name
        return record

    def _record_from_xml(self, xml):
        rec = None
        m = re.search(r'<EventRecordID>(\d+)</EventRecordID>', xml)
        if m:
            rec = int(m.group(1))
        eid = None
        m = re.search(r'<EventID[^>]*>(\d+)</EventID>', xml)
        if m:
            eid = int(m.group(1))
        ts = None
        m = re.search(r"<TimeCreated[^>]*SystemTime=['\"]([^'\"]+)['\"]", xml)
        if m:
            ts = m.group(1)

        data = _extract_data_fields(xml)
        user = (data.get("TargetUserName")
                or data.get("SubjectUserName"))
        threat_name = (data.get("Threat Name")
                       or data.get("ThreatName"))
        path = data.get("Path")
        process_name = (data.get("Process Name")
                        or data.get("ProcessName"))

        # OpenSSH/Operational stores the sshd message in the
        # named "payload" field. Do not use the first <Data> element.
        message = data.get("payload") or data.get("Payload")
        if message is not None:
            message = message.strip() or None

        return self._make_record(
            eid, rec, ts, _extract_ips(xml),
            event_xml=None,
            event_strings=message,
            user=user,
            threat_name=threat_name,
            path=path,
            process_name=process_name,
        )

    def read_marker(self):
        m = _marker_read(self.name)
        if m.get("backend") != self.kind:
            return None, None
        bm = m.get("last_bookmark_xml")
        rec = m.get("last_processed_id", "")
        if isinstance(bm, str) and bm:
            return rec, bm
        if isinstance(rec, str) and rec.startswith("evt:"):
            return rec, None
        return None, None

    def write_marker(self, record_id, bookmark_xml):
        upd = {
            "backend": self.kind,
            "last_processed_time": time.time(),
        }
        if record_id is not None:
            upd["last_processed_id"] = f"evt:{record_id}"
        if bookmark_xml is not None:
            upd["last_bookmark_xml"] = bookmark_xml
        _marker_write(self.name, upd)

    def _on_event(self, action, context, event):
        if self._stop_requested:
            return 1
        try:
            if action != _ACTION_DELIVER:
                return 0
            try:
                xml = win32evtlog.EvtRender(event, _RENDER_XML)
            except Exception as e:
                _err_print(f"EvtRender failed on {self.log_name}: {e}")
                return 0
            try:
                self._queue.put_nowait(self._record_from_xml(xml))
                self._events_delivered += 1
                _sub_print(f"[{self.name}] callback queued; "
                           f"delivered={self._events_delivered}")
            except queue.Full:
                self._dropped += 1
        except Exception as e:
            _err_print(f"callback error on {self.log_name}: {e}")
        return 0

    def _build_query(self):
        if not self._event_ids:
            return "*"
        parts = " or ".join(f"EventID={eid}" for eid in self._event_ids)
        return f"*[System[({parts})]]"

    def _channel_metadata(self):
        try:
            r = subprocess.run(
                ["wevtutil", "gl", self.log_name, "/f:xml"],
                capture_output=True, text=True, timeout=5.0,
                encoding="utf-8", errors="replace",
            )
        except Exception as e:
            _err_print(f"wevtutil gl {self.log_name} failed: "
                       f"{type(e).__name__}: {e}")
            return None, None
        if r.returncode != 0:
            return None, None
        out = r.stdout or ""
        oldest = None
        count = None
        m = re.search(r'<OldestRecordNumber>(\d+)</OldestRecordNumber>', out)
        if m:
            try:
                oldest = int(m.group(1))
            except ValueError:
                oldest = None
        m = re.search(r'<NumberOfLogRecords>(\d+)</NumberOfLogRecords>', out)
        if m:
            try:
                count = int(m.group(1))
            except ValueError:
                count = None
        return oldest, count

    def _bootstrap_start_record(self, metadata=None):
        if metadata is None:
            metadata = self._channel_metadata()
        oldest, count = metadata
        if oldest is None or count is None:
            return 0
        if count > EVENTLOG_MAX_PER_CYCLE:
            return oldest + count - EVENTLOG_MAX_PER_CYCLE - 1
        return oldest - 1

    def _ensure_subscription(self):
        if self._active:
            return True
        now = time.time()
        if self._initialized and now < self._next_retry_ts:
            return False
        self._initialized = True

        if not HAS_WIN32EVTLOG:
            self._error_category = "import_failure"
            self._error_detail = "win32evtlog not importable"
            self._next_retry_ts = now + EVENTLOG_SUBSCRIBE_RETRY_SECONDS
            self.mark_not_ready(
                f"subscription unavailable ({self._error_category}): "
                f"{self._error_detail}")
            return False
        if EVT_MISSING_ATTRS:
            self._error_category = "api_unavailable"
            self._error_detail = (f"pywin32 missing "
                                   f"{','.join(EVT_MISSING_ATTRS)}")
            self._next_retry_ts = now + EVENTLOG_SUBSCRIBE_RETRY_SECONDS
            self.mark_not_ready(
                f"subscription unavailable ({self._error_category}): "
                f"{self._error_detail}")
            return False

        query = self._build_query()
        try:
            self._subscription_handle = win32evtlog.EvtSubscribe(
                Session=None,
                SignalEvent=None,
                ChannelPath=self.log_name,
                Query=query,
                Bookmark=None,
                Context=None,
                Callback=self._on_event,
                Flags=_FLAG_FUTURE,
            )
        except Exception as e:
            category, detail = _classify_subscription_error(e)
            self._error_category = category
            self._error_detail = detail
            emit(self.name, LAYER, "error",
                 f"{self.log_name}: subscription failed ({category}): "
                 f"{detail}")
            self._active = False
            self._next_retry_ts = now + EVENTLOG_SUBSCRIBE_RETRY_SECONDS
            self.mark_not_ready(
                f"subscription failed ({category}): {detail}")
            return False

        self._active = True
        self._next_retry_ts = 0.0
        self._stalled_cycles = 0
        self._last_stall_warn = 0.0
        emit(self.name, LAYER, "info",
             f"{self.log_name}: subscription active")
        _bb_update(self.section, {
            "reader_subscription_active": True,
            "reader_subscription_query": self._build_query(),
            "reader_subscription_error": "",
            "reader_subscription_error_category": "",
            "reader_subscription_next_retry": 0.0,
        })
        return True

    def _stop_subscription(self):
        self._stop_requested = True
        if self._subscription_handle is not None:
            handle = self._subscription_handle
            self._subscription_handle = None
            closed = False
            if HAS_EVT_CLOSE:
                try:
                    win32evtlog.EvtClose(handle)
                    closed = True
                except Exception:
                    pass
            if not closed:
                for m in ("Close", "close"):
                    fn = getattr(handle, m, None)
                    if callable(fn):
                        try:
                            fn()
                            closed = True
                            break
                        except Exception:
                            pass
        self._active = False

    def shutdown(self):
        self._stop_subscription()

    def _drain(self):
        events = []
        highest = self._highest
        while True:
            try:
                item = self._queue.get_nowait()
            except queue.Empty:
                break
            rec = item.get("record_id")
            if isinstance(rec, int):
                if rec <= self._catchup_high_water:
                    continue
                if rec > highest:
                    highest = rec
            events.append(item)
        self._highest = highest
        return events, highest

    def _check_liveness(self):
        if not self._active:
            return
        if self._events_delivered == self._last_events_delivered:
            self._stalled_cycles += 1
            if self._stalled_cycles >= EVENTLOG_STALL_WARN_CYCLES:
                now = time.time()
                if (self._last_stall_warn == 0.0
                        or (now - self._last_stall_warn)
                           >= EVENTLOG_STALL_WARN_INTERVAL):
                    emit(self.name, LAYER, "warn",
                         f"{self.log_name}: subscription has received "
                         f"no events for {self._stalled_cycles} cycles")
                    self._last_stall_warn = now
                _bb_update(self.section, {
                    "reader_subscription_stalled": True,
                    "reader_subscription_stalled_cycles":
                        self._stalled_cycles,
                })
        else:
            self._stalled_cycles = 0
            self._last_events_delivered = self._events_delivered
            self._last_stall_warn = 0.0
            _bb_update(self.section, {
                "reader_subscription_stalled": False,
                "reader_subscription_stalled_cycles": 0,
            })

    def _query_events_modern(self, bookmark_xml):
        if not (HAS_EVT_QUERY and HAS_EVT_NEXT and HAS_EVT_SEEK):
            return [], bookmark_xml, False
        if not HAS_EVT_BOOKMARK:
            return [], bookmark_xml, False

        try:
            query_handle = win32evtlog.EvtQuery(
                self.log_name,
                EVT_QUERY_CHANNEL_PATH | EVT_QUERY_FORWARD,
                self._build_query(),
                None,
            )
        except Exception as e:
            emit(self.name, LAYER, "error",
                 f"EvtQuery failed on {self.log_name}: "
                 f"{type(e).__name__}: {e}")
            return [], bookmark_xml, False

        bookmark_handle = None
        records = []
        last_bookmark_xml = bookmark_xml
        count = 0

        try:
            if bookmark_xml:
                try:
                    bookmark_handle = win32evtlog.EvtCreateBookmark(
                        bookmark_xml)
                except Exception as e:
                    emit(self.name, LAYER, "warn",
                         f"bookmark init failed: "
                         f"{type(e).__name__}: {e}")
                    bookmark_handle = None

            while count < EVENTLOG_MAX_PER_CYCLE:
                try:
                    events = win32evtlog.EvtNext(query_handle, 10, 1000, 0)
                except Exception:
                    break
                if not events:
                    break
                for ev in events:
                    try:
                        xml = win32evtlog.EvtRender(ev, EVT_RENDER_EVENT_XML)
                    except Exception as e:
                        emit(self.name, LAYER, "warn",
                             f"EvtRender failed: {type(e).__name__}")
                        continue
                    records.append(self._record_from_xml(xml))
                    try:
                        if bookmark_handle is None:
                            bookmark_handle = \
                                win32evtlog.EvtCreateBookmark(None)
                        win32evtlog.EvtUpdateBookmark(bookmark_handle, ev)
                        last_bookmark_xml = win32evtlog.EvtRender(
                            bookmark_handle, EVT_RENDER_BOOKMARK)
                    except Exception as e:
                        emit(self.name, LAYER, "warn",
                             f"bookmark update failed: "
                             f"{type(e).__name__}")
                    count += 1
                    if count >= EVENTLOG_MAX_PER_CYCLE:
                        break
        finally:
            try:
                win32evtlog.EvtClose(query_handle)
            except Exception:
                pass

        return records, last_bookmark_xml, True

    def cycle(self):
        if not HAS_WIN32EVTLOG:
            _evt_print(f"[{self.name}] win32evtlog missing; not ready")
            self.mark_not_ready("win32evtlog missing")
            return
        if not self.try_claim():
            _evt_print(f"[{self.name}] claim failed; skipping cycle")
            return

        section = _bb_read_section(self.section)
        cumulative = int(section.get("last_failures_cumulative", 0) or 0)
        last_record_str, bookmark_xml = self.read_marker()
        _evt_print(f"[{self.name}] channel={self.log_name} "
                   f"active={self._active} "
                   f"initialized={self._initialized} "
                   f"bookmark={'yes' if bookmark_xml else 'no'} "
                   f"cumulative_before={cumulative} "
                   f"delivered={self._events_delivered}")

        if HAS_EVT_SUBSCRIBE:
            if not self._initialized:
                if self._ensure_subscription():
                    records, new_bm, ok = self._query_events_modern(
                        bookmark_xml)
                    _evt_print(f"[{self.name}] first-entry catchup "
                               f"opened={ok} events={len(records)}")
                    if ok:
                        n = len(records)
                        cumulative += n
                        last_rec = (records[-1].get("record_id")
                                    if records else None)
                        self.write_marker(last_rec, new_bm)
                        self._catchup_high_water = last_rec or 0
                        self._highest = last_rec or 0
                        if n > 0:
                            self.write_output(
                                items_read=n,
                                cumulative=cumulative,
                                healthy=True,
                                recent_events=records,
                                recent_ips=[ip for e in records
                                            for ip in (e.get("ips") or [])],
                            )
                        else:
                            self.write_output(
                                items_read=0,
                                cumulative=cumulative,
                                healthy=True,
                                recent_events=None,
                                recent_ips=None,
                            )
            elif not self._active:
                if self._ensure_subscription() and not bookmark_xml:
                    records, new_bm, ok = self._query_events_modern(None)
                    if ok:
                        n = len(records)
                        cumulative += n
                        last_rec = (records[-1].get("record_id")
                                    if records else None)
                        self.write_marker(last_rec, new_bm)
                        self._catchup_high_water = last_rec or 0
                        self._highest = last_rec or 0
                        if n > 0:
                            self.write_output(
                                items_read=n,
                                cumulative=cumulative,
                                healthy=True,
                                recent_events=records,
                                recent_ips=[ip for e in records
                                            for ip in (e.get("ips") or [])],
                            )

            if self._active:
                events, highest = self._drain()
                n = len(events)
                cumulative += n
                _evt_print(f"[{self.name}] drained n={n} highest={highest}")
                if highest and highest > 0:
                    self.write_marker(highest, bookmark_xml)
                if n > 0:
                    recent_ips = [ip for e in events
                                  for ip in (e.get("ips") or [])]
                    self.write_output(
                        items_read=n,
                        cumulative=cumulative,
                        healthy=True,
                        recent_events=events,
                        recent_ips=recent_ips,
                    )
                else:
                    self.write_output(
                        items_read=0,
                        cumulative=cumulative,
                        healthy=True,
                        recent_events=None,
                        recent_ips=None,
                    )
                self._check_liveness()
                _bb_update(self.section, {
                    "reader_queue_depth": self._queue.qsize(),
                    "reader_queue_dropped": self._dropped,
                    "reader_queue_overflow": self._dropped > 0,
                    "reader_catchup_high_water": self._catchup_high_water,
                    "reader_events_delivered": self._events_delivered,
                })
                _evt_print(f"[{self.name}] cycle done events={n} "
                           f"queue={self._queue.qsize()} "
                           f"cumulative={cumulative} "
                           f"delivered={self._events_delivered}")
                self.mark_ready()
                return

        _evt_print(f"[{self.name}] subscription unavailable; query fallback")
        records, new_bm, ok = self._query_events_modern(bookmark_xml)
        if not ok:
            _evt_print(f"[{self.name}] query path failed; not ready")
            self.mark_not_ready("query path unavailable")
            return
        n = len(records)
        cumulative += n
        last_rec = records[-1].get("record_id") if records else None
        self.write_marker(last_rec, new_bm)
        if n > 0:
            self.write_output(
                items_read=n,
                cumulative=cumulative,
                healthy=True,
                recent_events=records,
                recent_ips=[ip for e in records
                            for ip in (e.get("ips") or [])],
            )
        else:
            self.write_output(
                items_read=0,
                cumulative=cumulative,
                healthy=True,
                recent_events=None,
                recent_ips=None,
            )
        _evt_print(f"[{self.name}] query cycle events={n}")
        self.mark_ready()


class CapabilityReader:
    def __init__(self, name, source_type, source_ref, event_ids=None):
        self.name = name
        self.section = f"reader_{name}"
        self._ready_announced = False
        self.source_type = source_type
        self.source_ref = source_ref
        self.event_ids = list(event_ids) if isinstance(event_ids, list) else None
        self._pending_startup_gap = _detect_startup_gap(self.section)
        if source_type == "file":
            self.backend = FileBackend(self, source_ref)
        elif source_type == "eventlog":
            self.backend = EventLogBackend(self, source_ref,
                                            event_ids=self.event_ids)
        else:
            raise ValueError(f"unknown source type: {source_type}")

    def _try_claim_impl(self, section, name):
        try:
            with open(BLACKBOARD_FILE, 'r+') as f:
                acquire_lock(f.fileno(), exclusive=True)
                try:
                    try:
                        data = json.load(f)
                    except json.JSONDecodeError:
                        data = {}
                    if not isinstance(data, dict):
                        data = {}
                    sec = data.get(section)
                    if not isinstance(sec, dict):
                        sec = {}
                    current = sec.get("reader_owner", "")
                    if self._is_live_other_owner(current):
                        emit(name, LAYER, "debug",
                             f"[CLAIM] {section} held by {current}",
                             capability=name)
                        return False
                    sec["reader_owner"] = f"{os.getpid()}:{time.time()}"
                    data[section] = sec
                    f.seek(0)
                    json.dump(data, f, indent=2)
                    f.truncate()
                    return True
                finally:
                    release_lock(f.fileno())
        except Exception as e:
            emit(name, LAYER, "error", f"claim failed: {e}")
            return False

    def _is_live_other_owner(self, owner):
        if not isinstance(owner, str) or ":" not in owner:
            return False
        try:
            pid_s, ts_s = owner.split(":", 1)
            pid, ts = int(pid_s), float(ts_s)
        except (ValueError, TypeError):
            return False
        if pid == os.getpid():
            return False
        if HAS_PSUTIL:
            try:
                if not psutil.pid_exists(pid):
                    return False
            except Exception:
                pass
        return ((time.time() - ts)
                <= OWNERSHIP_STALE_CYCLES * READER_CYCLE_SECONDS)

    def cycle(self):       self.backend.cycle()
    def shutdown(self):
        try: self.backend.shutdown()
        except Exception: pass
    def mark_not_ready(self, reason=""):  self.backend.mark_not_ready(reason)
    def release(self):     self.backend.release()
    def identity(self):
        return (self.source_type, self.source_ref,
                tuple(self.event_ids or []))


def watchdog():
    threshold = READER_CYCLE_SECONDS * WATCHDOG_MULTIPLIER
    global _running
    while _running:
        time.sleep(threshold / 2)
        if not _running:
            return
        if time.time() - _last_cycle_time > threshold:
            emit(SRC, LAYER, "error", f"watchdog trip ({threshold}s)")
            _err_print(f"watchdog trip ({threshold}s)")
            _running = False
            return


def parent_watchdog():
    global _running
    not_running_since = None
    while True:
        time.sleep(5.0)
        if _running:
            if _parent_pid is None or _parent_pid <= 1:
                continue
            if not _parent_alive(_parent_pid):
                _err_print(f"parent pid {_parent_pid} is gone; exiting")
                emit(SRC, LAYER, "warn",
                     f"parent process {_parent_pid} disappeared; stopping")
                _running = False
                not_running_since = time.time()
            continue
        if not_running_since is None:
            not_running_since = time.time()
            continue
        if time.time() - not_running_since >= 30.0:
            _err_print("graceful shutdown did not finish in 30s")
            os._exit(0)


def write_heartbeat():
    try:
        os.makedirs(os.path.dirname(HEARTBEAT_FILE), exist_ok=True)
        with open(HEARTBEAT_FILE, "w") as f:
            f.write(str(time.time()))
    except Exception as e:
        _err_print(f"heartbeat write failed: {e}")


def remove_heartbeat():
    try:
        if os.path.exists(HEARTBEAT_FILE):
            os.remove(HEARTBEAT_FILE)
    except Exception:
        pass


def _shutdown(sig, frame):
    global _running
    emit(SRC, LAYER, "info", f"shutdown signal {sig}")
    _boot_print(f"shutdown signal {sig}")
    _running = False


def _cycle_sleep():
    return min(MAX_CYCLE_SECONDS, READER_CYCLE_SECONDS)


def _test_mode():
    _boot_print("one-shot test mode")
    _boot_diagnostics()
    if not os.path.exists(SYSTEM_CONFIG_FILE):
        _boot_print("FATAL: config not found")
        sys.exit(1)
    accepted, skipped, err = read_sources()
    if err is not None:
        _boot_print(f"FATAL: config {err}")
        sys.exit(1)
    _boot_print(f"accepted={list(accepted.keys())}")
    _boot_print(f"skipped={skipped}")
    if not accepted:
        _boot_print("no sources accepted")
        sys.exit(2)
    for name, meta in accepted.items():
        _boot_print(f"cycling {name} ({meta['type']}:{meta['ref']})")
        try:
            r = CapabilityReader(name, meta["type"], meta["ref"],
                                  event_ids=meta.get("event_ids"))
            r.cycle()
            sec = _bb_read_section(r.section)
            marker = _marker_read(name)
            _boot_print(f"--- {r.section} ---")
            _boot_print(f"  reader_ready={sec.get('reader_ready')}")
            _boot_print(f"  backend={sec.get('backend')}")
            _boot_print(f"  recent_events={len(sec.get('recent_events') or [])}")
            _boot_print(f"  recent_events_ts={sec.get('recent_events_ts')}")
            _boot_print(f"  last_processed_id="
                        f"{marker.get('last_processed_id')}")
            _boot_print(f"  last_bookmark_xml="
                        f"{'yes' if marker.get('last_bookmark_xml') else 'no'}")
            _boot_print(f"  last_failures_cumulative="
                        f"{sec.get('last_failures_cumulative')}")
            _boot_print(f"  reader_last_error="
                        f"{sec.get('reader_last_error')!r}")
            _boot_print(f"  marker_file={_marker_file_path(name)}")
            r.shutdown()
            r.release()
        except Exception as e:
            _boot_print(f"cycle for {name} failed: "
                        f"{type(e).__name__}: {e}")
    _boot_print("test complete")


def main():
    global _running, _last_cycle_time, _parent_pid

    _boot_print("process starting")
    _parent_pid = os.getppid()
    _boot_diagnostics()
    _check_permissions_at_startup()

    signal.signal(signal.SIGINT, _shutdown)
    signal.signal(signal.SIGTERM, _shutdown)

    if not os.path.exists(SYSTEM_CONFIG_FILE):
        emit(SRC, LAYER, "error", f"config not found: {SYSTEM_CONFIG_FILE}")
        _boot_print("FATAL: config not found")
        sys.exit(1)
    emit(SRC, LAYER, "info",
         f"Reader: config loaded from {SYSTEM_CONFIG_FILE}")
    emit(SRC, LAYER, "info", "Reader starting")
    _boot_print("entering main loop")

    threading.Thread(target=watchdog, daemon=True,
                     name="reader_watchdog").start()
    threading.Thread(target=parent_watchdog, daemon=True,
                     name="reader_parent_watchdog").start()

    readers = {}
    cycle_n = 0

    while _running:
        cycle_n += 1
        _last_cycle_time = time.time()

        accepted, skipped, cfg_err = read_sources()

        if cfg_err is not None:
            emit(SRC, LAYER, "warn",
                 f"config {cfg_err}; preserving {len(readers)} reader(s)")
            _loop_print(f"cycle={cycle_n} config error={cfg_err} "
                        f"preserving readers")
            for reader in readers.values():
                if not _running:
                    break
                try:
                    reader.cycle()
                except Exception as e:
                    import traceback
                    emit(reader.name, LAYER, "error",
                         f"cycle error: {e}")
                    _err_print(f"cycle error for {reader.name}: {e}")
                    _err_print(traceback.format_exc())
        else:
            _loop_print(f"cycle={cycle_n} accepted={list(accepted.keys())} "
                        f"skipped={len(skipped)} readers={len(readers)}")

            for name, reason in skipped:
                emit(name, LAYER, "warn", f"reader skipping: {reason}")

            for name in list(readers.keys()):
                if name not in accepted:
                    emit(name, LAYER, "info",
                         f"{name} no longer configured; dropping")
                    readers[name].mark_not_ready("no longer configured")
                    readers[name].shutdown()
                    readers[name].release()
                    del readers[name]

            for name, meta in accepted.items():
                stype = meta["type"]
                sref = meta["ref"]
                event_ids = meta.get("event_ids")
                new_identity = (stype, sref, tuple(event_ids or []))
                existing = readers.get(name)
                if existing is not None \
                        and existing.identity() == new_identity:
                    continue
                if existing is not None:
                    emit(name, LAYER, "info",
                         f"{name} source changed; recreating")
                    existing.mark_not_ready("source changed")
                    existing.shutdown()
                    existing.release()
                    _marker_clear(name)
                    del readers[name]
                try:
                    readers[name] = CapabilityReader(
                        name, stype, sref, event_ids=event_ids)
                    emit(name, LAYER, "info",
                         f"reader attached to {stype}: {sref}")
                    _loop_print(f"attached {name} ({stype}:{sref})")
                except Exception as e:
                    emit(name, LAYER, "error",
                         f"cannot attach reader: {e}")
                    _err_print(f"cannot attach reader {name}: {e}")

            for reader in readers.values():
                if not _running:
                    break
                try:
                    reader.cycle()
                except Exception as e:
                    import traceback
                    emit(reader.name, LAYER, "error",
                         f"cycle error: {e}")
                    _err_print(f"cycle error for {reader.name}: {e}")
                    _err_print(traceback.format_exc())

            if not readers and skipped:
                emit(SRC, LAYER, "warn",
                     "Reader: no readable sources. Skipped: "
                     + "; ".join(f"{n} ({r})" for n, r in skipped))

        write_heartbeat()
        sleep_total = _cycle_sleep()
        _loop_print(f"heartbeat written; sleeping {sleep_total}s")
        slept = 0.0
        while _running and slept < sleep_total:
            time.sleep(0.5)
            slept += 0.5

    for reader in readers.values():
        try:
            reader.shutdown()
            reader.mark_not_ready("shutdown")
            reader.release()
        except Exception:
            pass
    remove_heartbeat()
    emit(SRC, LAYER, "info", "Reader stopped")
    _boot_print("process stopping")


if __name__ == "__main__":
    if "--test" in sys.argv:
        _test_mode()
        sys.exit(0)
    main()