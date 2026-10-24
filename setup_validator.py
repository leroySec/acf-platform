#!/usr/bin/env python3
# ============================================================================
# SETUP VALIDATOR — Environment validation for ACF setup
# ============================================================================

import os
import re
import sys
import subprocess
import shutil
from typing import Tuple

from os_primitive_config import OsPrimitivePreconditionChecks  # os_primitive_config


_PLATFORM_UTILS_AVAILABLE = False
try:
    from platform_utils import acquire_lock, release_lock, get_temp_dir
    _PLATFORM_UTILS_AVAILABLE = True
except ImportError:
    def acquire_lock(fd, exclusive=True):
        pass
    def release_lock(fd):
        pass
    def get_temp_dir():
        return '/tmp' if os.name != 'nt' else os.environ.get('TEMP', 'C:\\Temp')


def check_admin_windows() -> bool:
    if os.name != 'nt':
        return True
    try:
        import ctypes
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def check_admin_linux() -> bool:
    if os.name == 'nt':
        return True
    try:
        return os.geteuid() == 0
    except Exception:
        return False


def check_admin() -> Tuple[bool, str]:
    if os.name == 'nt':
        if check_admin_windows():
            return True, "OK (Administrator)"
        return False, "ADMIN_REQUIRED"
    elif os.name == 'posix':
        if check_admin_linux():
            return True, "OK (root)"
        return False, "ROOT_REQUIRED"
    else:
        return True, "OK (unknown OS, assuming permissions)"


def check_ssh_event_log_windows() -> Tuple[bool, str]:
    if os.name != 'nt':
        return False, "NOT_WINDOWS"
    try:
        result = subprocess.run(
            ["wevtutil", "get-log", "Security"],
            capture_output=True, text=True, timeout=2
        )
        if result.returncode == 0 and "enabled: true" in result.stdout.lower():
            return True, "OK (Security Event Log)"

        result = subprocess.run(
            ["wevtutil", "get-log", "OpenSSH/Operational"],
            capture_output=True, text=True, timeout=2
        )
        if result.returncode == 0 and "enabled: true" in result.stdout.lower():
            return True, "OK (OpenSSH Operational Log)"
    except subprocess.TimeoutExpired:
        return False, "TIMEOUT"
    except FileNotFoundError:
        return False, "WEVTUTIL_NOT_FOUND"
    except Exception as e:
        return False, f"ERROR: {str(e)}"
    return False, "LOG_NOT_FOUND"


def pre_flight_ssh(config: dict) -> Tuple[bool, str]:
    if not isinstance(config, dict):
        return False, "INVALID_CONFIG"
    capability_paths = config.get("capability_paths") or {}
    custom_path = capability_paths.get("ssh", "").strip()
    if custom_path and os.path.exists(custom_path) and os.access(custom_path, os.R_OK):
        return True, "OK (file path)"
    if os.name == 'nt':
        ok, reason = check_ssh_event_log_windows()
        if ok:
            return True, "OK (Windows Event Log)"
    if os.name != 'nt':
        if os.path.exists("/var/log/auth.log") and os.access("/var/log/auth.log", os.R_OK):
            return True, "OK (auth.log)"
        if shutil.which("journalctl"):
            return True, "OK (journalctl)"
    return False, "LOG_SOURCE_MISSING"


def pre_flight_sensor(config: dict) -> Tuple[bool, str]:
    if not isinstance(config, dict):
        return False, "INVALID_CONFIG"
    if os.name == 'nt':
        admin_ok, admin_reason = check_admin()
        if not admin_ok:
            return False, admin_reason
    try:
        import psutil
        psutil.cpu_percent(interval=0.1)
        return True, "OK (psutil)"
    except ImportError:
        return False, "PSUTIL_MISSING"
    except Exception as e:
        return False, f"PSUTIL_ERROR: {str(e)}"


# ----------------------------------------------------------------------
# os_primitive_config — preflight for Windows OS primitive sources
# ----------------------------------------------------------------------

def pre_flight_defender() -> Tuple[bool, str]:
    r = OsPrimitivePreconditionChecks.check_defender_capabilities()
    if r.get("status") == "ready":
        return True, "OK (Defender channel)"
    return False, (r.get("details") or {}).get("error", "DEFENDER_UNAVAILABLE")


def pre_flight_firewall() -> Tuple[bool, str]:
    r = OsPrimitivePreconditionChecks.check_firewall_capabilities()
    if r.get("status") == "ready":
        return True, "OK (Firewall log)"
    if r.get("status") == "pending":
        return False, (r.get("details") or {}).get("info", "FIREWALL_PENDING")
    return False, (r.get("details") or {}).get("error", "FIREWALL_UNAVAILABLE")


# ----------------------------------------------------------------------
# Custom log path verification (file or Windows event log)
# ----------------------------------------------------------------------

def _event_log_channel_to_file(channel: str) -> str:
    """
    Compute the on-disk .evtx file path for a Windows event channel.
    Handles WOW64 redirection via Sysnative.
    """
    sysroot = (os.environ.get("SystemRoot")
               or os.environ.get("WINDIR")
               or r"C:\Windows")
    try:
        import ctypes
        if ctypes.sizeof(ctypes.c_void_p) == 4:
            sysnative = os.path.join(sysroot, "Sysnative")
            if os.path.isdir(sysnative):
                sysroot = sysnative
    except Exception:
        pass
    escaped = channel.replace("/", "%4")
    return os.path.join(sysroot, "System32", "Winevt", "Logs",
                         escaped + ".evtx")


def _verify_custom_path(cap_id: str, path: str) -> Tuple[bool, str]:
    """
    Verify a custom log path is accessible.

    Handles both:
      - Windows event log strings: "Windows Event Log (<channel>)"
      - file paths: C:\\path\\to\\log.log

    Returns (True, reason) if the source is accessible.
    """
    if path.startswith("Windows Event Log ("):
        m = re.search(r"\(([^)]+)", path)
        if not m:
            return False, "CUSTOM_PATH_INVALID"
        channel = m.group(1).strip()
        if not channel:
            return False, "CUSTOM_PATH_INVALID"
        if os.name != 'nt':
            return False, "NOT_WINDOWS"
        log_file = _event_log_channel_to_file(channel)
        if not os.path.exists(log_file):
            return False, f"Event log channel not present: {channel}"
        if not os.access(log_file, os.R_OK):
            return False, f"Event log channel not readable: {channel}"
        return True, f"OK (event log: {channel})"

    if not os.path.exists(path):
        return False, "CUSTOM_PATH_MISSING"
    if not os.access(path, os.R_OK):
        return False, "CUSTOM_PATH_NOT_READABLE"
    return True, f"OK (custom log: {cap_id})"


def pre_flight_check(cap_id: str, config: dict) -> Tuple[bool, str]:
    if not isinstance(config, dict):
        return False, "INVALID_CONFIG"
    if cap_id == "ssh":
        return pre_flight_ssh(config)
    if cap_id == "sensor":
        return pre_flight_sensor(config)
    if cap_id == "defender":
        return pre_flight_defender()          # os_primitive_config
    if cap_id == "firewall":
        return pre_flight_firewall()          # os_primitive_config

    # Any other capability is a custom log — Defender, Firewall, or
    # an operator-added file. Verify the path regardless of name.
    capability_paths = config.get("capability_paths") or {}
    custom_path = capability_paths.get(cap_id, "").strip()
    if not custom_path:
        return False, "CUSTOM_PATH_MISSING"
    return _verify_custom_path(cap_id, custom_path)


def check_locking_available() -> Tuple[bool, str]:
    if not _PLATFORM_UTILS_AVAILABLE:
        return False, "PLATFORM_UTILS_MISSING"
    test_file = os.path.join(get_temp_dir(), "acf_lock_test.lock")
    try:
        with open(test_file, 'w') as f:
            acquire_lock(f.fileno(), exclusive=True)
            release_lock(f.fileno())
        if os.path.exists(test_file):
            os.remove(test_file)
        return True, "OK"
    except Exception as e:
        if os.path.exists(test_file):
            try:
                os.remove(test_file)
            except Exception:
                pass
        return False, f"LOCKING_FAILED: {str(e)}"