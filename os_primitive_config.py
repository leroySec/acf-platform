#!/usr/bin/env python3
"""
os_primitive_config.py — Preconditions and metadata for Windows OS
primitive sources: Windows Defender Event Log and Windows Firewall
log.

Follows the SensorConfig / SensorPreconditionChecks pattern.
Imported by config_interactive.py for discovery and by
setup_validator.py for pre-flight dispatch.

Scope
-----
Preconditions check ACCESS, not state.

A source is available if the reader can open it and events can be
read from it. Whether the tool that writes to it is running,
disabled, or configured in any particular way is a separate
concern. The ACF reads what is emitted. It does not require the
emitter to be in a specific state to exist.

Consequences:
    - Defender's channel is checked by attempting to open the
      channel's log file. A silent channel is still a valid source.
    - Firewall logging is checked by attempting to open the log
      file. Firewall state is not queried.

Return shapes (divergent by design)
-----------------------------------
    check_defender_capabilities()   -> {status, method, details}
    check_firewall_capabilities()   -> {status, method, details}
    classify_log_language(path)     -> {language, hits, samples}

The two precondition checks share the discovery shape. The
classifier reports what the operator reads at setup time. The
shapes serve different consumers and are not unified.

Dependencies
------------
Standard library only. No pywin32. No subprocess. No locale text
parsing. The modern event-log channel is located through the
channel-to-filename mapping the OS itself uses (verified: the
channel's logFileName is
%SystemRoot%\System32\Winevt\Logs\<escaped>.evtx, where the '/'
character in the channel name is encoded as '%4').

WOW64
-----
On 32-bit Python running on 64-bit Windows, the file-system
redirector maps System32 to SysWOW64. The true System32 is
reachable via %SystemRoot%\Sysnative. _native_system32() uses
Sysnative when the process is 32-bit on 64-bit Windows. This
mirrors the suite's other binaries-resolution logic.

Local-file assumption
---------------------
classify_log_language assumes the file is local. It reads a small
tail sample. No timeout is applied. On a network path, the read may
block. Documented, not defended against; the alternative adds
thread machinery for a path no deployment target uses.

Encoding support
----------------
_decode_bytes decodes UTF-32 LE/BE, UTF-8, UTF-16 LE/BE, and cp1252
with surrogateescape as the final fallback. The BOM is read from
the start of the file separately, because the tail sample does not
include byte 0.

Language classification is fixed to English and French. The
classifier does not accept custom keyword lists. Spanish, German,
or other languages classify as 'unknown' and the operator is told.

The classifier is invoked on operator-exported text logs to decide
which vocabulary the operator is likely to see. It is not invoked
on live system files. It is a setup-time tool.
"""

import os
import re
import ctypes
from typing import Dict, Any, Optional


# ======================================================================
# Constants
# ======================================================================

class OsPrimitiveConfig:
    # Windows installation root. Read from the environment.
    SYSTEM_ROOT = (
        os.environ.get("SystemRoot")
        or os.environ.get("WINDIR")
        or r"C:\Windows"
    )

    # Windows Defender
    DEFENDER_CHANNEL = "Microsoft-Windows-Windows Defender/Operational"
    DEFENDER_EVENT_IDS = [1006, 1007, 1008, 1116, 1117, 5001, 5007]

    # Windows Firewall
    FIREWALL_LOG_DIR = os.path.join(
        SYSTEM_ROOT, "System32", "LogFiles", "Firewall")
    FIREWALL_LOG_PATH = os.path.join(FIREWALL_LOG_DIR, "pfirewall.log")
    # Patterns the operator is expected to see in the firewall log.
    # Metadata only. Used to seed the reader's per-capability pattern
    # list when the firewall capability is enabled. Not read by any
    # code in this module.
    FIREWALL_PATTERNS = ["DROP", "BLOCK", "Deny"]

    # Language vocabulary. Fixed, not exhaustive. A log using other
    # terms classifies as 'unknown' and the operator is told.
    ENGLISH_KEYWORDS = [
        "failed", "failure", "error", "denied",
        "invalid", "rejected", "unauthorized",
        "attack", "malware", "virus",
    ]
    FRENCH_KEYWORDS = [
        "échec", "echec", "échoué", "echoue",
        "erreur",
        "refusé", "refuse",
        "invalide",
        "non autorisé", "non autorise",
        "bloqué", "bloque",
        "dénié", "denie",
    ]

    # Number of bytes sampled from the tail of a log for language
    # classification. The tail reflects current traffic; the head of
    # a firewall log holds only the header block.
    SAMPLE_BYTES = 4096


# Precompile word-boundary patterns once. Word boundaries avoid
# substring false positives ("refuse" matching "refused").
_ENG_PATTERNS = [
    re.compile(r"\b" + re.escape(k) + r"\b", re.IGNORECASE)
    for k in OsPrimitiveConfig.ENGLISH_KEYWORDS
]
_FR_PATTERNS = [
    re.compile(r"\b" + re.escape(k) + r"\b", re.IGNORECASE)
    for k in OsPrimitiveConfig.FRENCH_KEYWORDS
]


# ======================================================================
# Internal helpers
# ======================================================================

def _is_windows() -> bool:
    return os.name == "nt"


def _is_32bit_on_64bit() -> bool:
    if os.name != "nt":
        return False
    try:
        return ctypes.sizeof(ctypes.c_void_p) == 4
    except Exception:
        return False


def _native_system32() -> str:
    """
    Return the true System32 path. On 32-bit Python running on
    64-bit Windows, the OS redirector maps System32 to SysWOW64;
    Sysnative reaches the real System32.
    """
    if _is_32bit_on_64bit():
        sysnative = os.path.join(
            OsPrimitiveConfig.SYSTEM_ROOT, "Sysnative")
        if os.path.isdir(sysnative):
            return sysnative
    return os.path.join(OsPrimitiveConfig.SYSTEM_ROOT, "System32")


def _is_elevated() -> bool:
    if not _is_windows():
        return True
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except Exception:
        return False


def _channel_log_path(channel_name: str) -> str:
    """
    Compute the on-disk path of a Windows event channel's .evtx file.
    The OS encodes '/' in the channel name as '%4'.
    """
    escaped = channel_name.replace("/", "%4")
    winevt = os.path.join(_native_system32(), "Winevt", "Logs")
    return os.path.join(winevt, escaped + ".evtx")


def _detect_encoding_from_head(path: str) -> str:
    """
    Read the first 4 bytes of the file and detect the encoding from
    the BOM. Returns 'utf-32-le', 'utf-32-be', 'utf-8',
    'utf-16-le', 'utf-16-be', or '' if no BOM is present.
    """
    try:
        with open(path, "rb") as f:
            head = f.read(4)
    except Exception:
        return ""
    if head.startswith(b'\xff\xfe\x00\x00'):
        return "utf-32-le"
    if head.startswith(b'\x00\x00\xfe\xff'):
        return "utf-32-be"
    if head.startswith(b'\xef\xbb\xbf'):
        return "utf-8"
    if head.startswith(b'\xff\xfe'):
        return "utf-16-le"
    if head.startswith(b'\xfe\xff'):
        return "utf-16-be"
    return ""


def _decode_bytes(data: bytes, encoding: str = "") -> str:
    """
    Decode bytes with the given encoding. If encoding is empty,
    fall through the standard list. The final fallback is cp1252
    with surrogateescape, which handles French Windows text without
    a BOM.
    """
    if not data:
        return ""
    if encoding:
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            pass
    for enc in ("utf-8", "utf-16-le", "utf-16-be"):
        try:
            return data.decode(enc)
        except UnicodeDecodeError:
            continue
    try:
        return data.decode("cp1252", errors="surrogateescape")
    except Exception:
        return data.decode("utf-8", errors="replace")


def _read_tail_sample(path: str, sample_bytes: int) -> bytes:
    try:
        size = os.path.getsize(path)
    except OSError:
        return b""
    if size <= 0:
        return b""
    start = max(0, size - sample_bytes)
    try:
        with open(path, "rb") as f:
            f.seek(start)
            return f.read(sample_bytes)
    except Exception:
        return b""


# ======================================================================
# Discovery preconditions
# ======================================================================

class OsPrimitivePreconditionChecks:
    """
    Discovery preconditions for Windows OS primitive sources.
    Return shape matches SensorPreconditionChecks.
    """

    @staticmethod
    def check_defender_capabilities() -> Dict[str, Any]:
        """
        Determine whether Windows Defender's Operational Event Log
        channel is accessible on this host.

        The channel's .evtx file is located via the same channel-to-
        filename mapping the OS uses. Access is verified by
        attempting to open the file for reading. This mirrors the
        reader's access requirement without a dependency on
        pywin32 or the modern event API.

        Result detail includes a 'note' field explaining that open
        success does not assert event presence. A silent channel is
        still a valid source.
        """
        result = {"status": "unknown", "method": None, "details": {}}

        if not _is_windows():
            result["status"] = "unavailable"
            result["details"]["error"] = "not Windows"
            return result

        channel = OsPrimitiveConfig.DEFENDER_CHANNEL
        path = _channel_log_path(channel)
        result["details"]["channel"] = channel
        result["details"]["channel_log"] = path

        if not os.path.isfile(path):
            result["status"] = "unavailable"
            result["details"]["error"] = (
                "Defender Operational channel is not present "
                "on this host")
            return result

        if not os.access(path, os.R_OK):
            result["status"] = "unavailable"
            result["details"]["error"] = (
                "access denied; elevation required to read "
                "the Defender Operational channel")
            return result

        # Verify the read side by opening the file. This is the
        # same read the reader would perform.
        try:
            with open(path, "rb") as f:
                f.read(1)
        except PermissionError:
            result["status"] = "unavailable"
            result["details"]["error"] = (
                "access denied; elevation required")
            return result
        except Exception as e:
            result["status"] = "unavailable"
            result["details"]["error"] = (
                f"cannot open Defender channel file: "
                f"{type(e).__name__}")
            return result

        result["status"] = "ready"
        result["method"] = "eventlog"
        result["details"]["event_ids"] = list(
            OsPrimitiveConfig.DEFENDER_EVENT_IDS)
        result["details"]["note"] = (
            "channel file opened for reading; event presence "
            "is not asserted")
        return result

    @staticmethod
    def check_firewall_capabilities() -> Dict[str, Any]:
        """
        Determine whether Windows Firewall dropped-connection
        logging is accessible on this host.

        Access is verified by opening the file and reading one byte.
        Firewall state is not queried.
        """
        result = {"status": "unknown", "method": None, "details": {}}

        if not _is_windows():
            result["status"] = "unavailable"
            result["details"]["error"] = "not Windows"
            return result

        path = OsPrimitiveConfig.FIREWALL_LOG_PATH
        log_dir = OsPrimitiveConfig.FIREWALL_LOG_DIR
        result["details"]["path"] = path

        try:
            with open(path, "rb") as f:
                f.read(1)
            result["status"] = "ready"
            result["method"] = "file"
            result["details"]["patterns"] = list(
                OsPrimitiveConfig.FIREWALL_PATTERNS)
            return result
        except FileNotFoundError:
            pass
        except PermissionError:
            result["status"] = "unavailable"
            result["details"]["error"] = (
                "access denied; elevation required to read the "
                "firewall log directory")
            return result
        except OSError as e:
            result["status"] = "unavailable"
            result["details"]["error"] = (
                f"cannot open firewall log: {type(e).__name__}")
            return result

        if os.path.isdir(log_dir):
            result["status"] = "pending"
            result["method"] = "file"
            result["details"]["patterns"] = list(
                OsPrimitiveConfig.FIREWALL_PATTERNS)
            result["details"]["info"] = (
                "log file will appear after the first dropped packet; "
                "firewall logging is enabled")
            return result

        if not _is_elevated():
            result["status"] = "unavailable"
            result["details"]["error"] = (
                "firewall log directory not visible to this token; "
                "elevation required, or logging has never been "
                "enabled on this host")
            return result

        result["status"] = "unavailable"
        result["details"]["error"] = (
            "firewall logging not enabled; enable with "
            "'netsh advfirewall set allprofiles logging "
            "droppedconnections enable'")
        return result


# ======================================================================
# Language classification
# ======================================================================

def classify_log_language(path: str) -> Dict[str, Any]:
    """
    Classify the language coverage of a text log by sampling its
    tail.

    Fixed to English and French. Not exhaustive. A log using other
    terms classifies as 'unknown'.

    The BOM is read from the file head separately, because the tail
    sample does not include byte 0.

    Returns:
        {
          "language":        "english" | "french" | "bilingual" | "unknown",
          "english_hits":    int,   # lines matching English keywords
          "french_hits":     int,   # lines matching French keywords
          "non_empty_lines": int,
          "sampled_bytes":   int,
        }

    Empty log (sampled_bytes == 0) and no-match log
    (sampled_bytes > 0, hits == 0) are distinguishable.

    Non-destructive. Never raises.
    """
    out = {
        "language": "unknown",
        "english_hits": 0,
        "french_hits": 0,
        "non_empty_lines": 0,
        "sampled_bytes": 0,
    }

    if not isinstance(path, str) or not os.path.isfile(path):
        return out

    encoding = _detect_encoding_from_head(path)
    data = _read_tail_sample(path, OsPrimitiveConfig.SAMPLE_BYTES)
    out["sampled_bytes"] = len(data)
    if not data:
        return out

    text = _decode_bytes(data, encoding)
    if not text:
        return out

    for line in text.splitlines():
        if not line.strip():
            continue
        out["non_empty_lines"] += 1

        if any(p.search(line) for p in _ENG_PATTERNS):
            out["english_hits"] += 1
        if any(p.search(line) for p in _FR_PATTERNS):
            out["french_hits"] += 1

    if out["english_hits"] > 0 and out["french_hits"] > 0:
        out["language"] = "bilingual"
    elif out["english_hits"] > 0:
        out["language"] = "english"
    elif out["french_hits"] > 0:
        out["language"] = "french"
    else:
        out["language"] = "unknown"

    return out


# ======================================================================
# Lifecycle entry point
# ======================================================================

class OsPrimitiveConfigEngine:
    """
    Optional module entry point, parallel to SensorConfigEngine.
    Returns every precondition result in one call.

    Not called by config.py. Not called by config_interactive.py.
    Available for direct invocation and for test harnesses.

    The pattern established by SensorConfigEngine is that the
    engine class is optional. Callers that need the results call
    OsPrimitivePreconditionChecks directly.
    """

    @classmethod
    def initialize(cls) -> Dict[str, Any]:
        return {
            "defender": OsPrimitivePreconditionChecks
                .check_defender_capabilities(),
            "firewall": OsPrimitivePreconditionChecks
                .check_firewall_capabilities(),
        }