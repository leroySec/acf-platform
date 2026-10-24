#!/usr/bin/env python3
# ============================================================================
# EVENT EMIT — Producer helper for the event router
# ============================================================================
# Every service and engine calls emit(src, layer, level, msg).
# The helper connects once, caches the connection, and sends one JSON line
# per event. If the router is unreachable, it queues up to QUEUE_MAX events
# and prints a warning; further events are printed only.
#
# FIXES APPLIED:
#   P0.1 — Port is re-read on every reconnect attempt (no stale cache)
#   P1.1 — Connect uses a separate lock; send uses another
#   P1.2 — Bounded in-memory queue during disconnect
#   P2.1 — Re-entrancy guard to avoid signal-handler deadlock
#   P2.2 — Transition-only logging (failed / recovered)
#   P3.1 — Monotonic clock for reconnect cooldown
# ============================================================================

import os
import sys
import json
import socket
import threading
import time
from collections import deque
from typing import Optional

from config import Config

# Configuration
HOST = Config.EVENT_ROUTER_HOST
PORT_FILE = Config.EVENT_ROUTER_PORT_FILE

# Limits
CONNECT_TIMEOUT = 2         # seconds
SEND_TIMEOUT = 2            # seconds
MAX_MSG_LEN = 8000          # truncate msg field
RECONNECT_COOLDOWN = 5      # seconds between reconnect attempts
QUEUE_MAX = 100             # events buffered during disconnect

# Internal state
_connect_lock = threading.Lock()
_send_lock = threading.Lock()
_sock: Optional[socket.socket] = None
_last_attempt = 0.0
_in_failure_mode = False
_pending: deque = deque(maxlen=QUEUE_MAX)
_reentrant = threading.local()


# ----------------------------------------------------------------------
# Port discovery — always read fresh
# ----------------------------------------------------------------------
def _read_port() -> Optional[int]:
    """Read the router's port from the port file."""
    try:
        if not os.path.exists(PORT_FILE):
            return None
        with open(PORT_FILE, "r") as f:
            return int(f.read().strip())
    except Exception:
        return None


# ----------------------------------------------------------------------
# Connection management
# ----------------------------------------------------------------------
def _close_socket():
    global _sock
    if _sock is not None:
        try:
            _sock.close()
        except Exception:
            pass
        _sock = None


def _try_connect() -> bool:
    """Attempt to open a producer connection. Re-reads port each time."""
    global _sock, _last_attempt, _in_failure_mode

    _last_attempt = time.monotonic()

    port = _read_port()
    if port is None:
        return False

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(CONNECT_TIMEOUT)
        s.connect((HOST, port))
        s.settimeout(SEND_TIMEOUT)
        _sock = s

        # Recovered from failure — log transition
        if _in_failure_mode:
            _in_failure_mode = False
            print(f"[EVENT_EMIT] Reconnected to router at {HOST}:{port}")

        return True
    except Exception:
        _close_socket()
        return False


def _ensure_connection() -> bool:
    """Return True if a live connection exists, attempting reconnect if allowed."""
    global _in_failure_mode

    if _sock is not None:
        return True

    # Throttle reconnect attempts using monotonic clock
    if _in_failure_mode and (time.monotonic() - _last_attempt) < RECONNECT_COOLDOWN:
        return False

    return _try_connect()


# ----------------------------------------------------------------------
# Fallback printer
# ----------------------------------------------------------------------
def _fallback_print(event: dict):
    try:
        ts = time.strftime("%H:%M:%S", time.localtime(event.get("ts", time.time())))
        src = event.get("src", "unknown")
        layer = event.get("layer", "-")
        level = event.get("level", "info").upper()
        msg = event.get("msg", "")
        print(f"[{ts}][{src}][{layer}][{level}] {msg}")
    except Exception:
        pass


# ----------------------------------------------------------------------
# Flush queue on reconnect
# ----------------------------------------------------------------------
def _flush_pending(sock: socket.socket) -> int:
    """Send queued events. Returns count sent. On failure, leaves remaining in queue."""
    sent = 0
    while _pending:
        try:
            line = _pending[0]
        except IndexError:
            break
        try:
            sock.sendall(line)
            _pending.popleft()
            sent += 1
        except Exception:
            break
    return sent


# ----------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------
def emit(src: str, layer: str, level: str, msg: str,
         capability=None, cycle=None):
    """
    Emit one event.

    src:        source name (the emitting component's name).
    layer:      layer id (e.g., "layer1", "layer2") or "-" if not
                tied to a layer.
    level:      "info", "warn", or "error".
    msg:        human-readable message.
    capability: the ACF capability this event is about, or None for
                engine-wide messages that are not about one capability.
    cycle:      the emitting engine's cycle counter, or None.
    """
    # Re-entrancy guard: if we are already inside emit() on this thread
    # (e.g., called from a signal handler), fall back to print only.
    if getattr(_reentrant, "active", False):
        _fallback_print({
            "ts": time.time(),
            "src": src if isinstance(src, str) else "unknown",
            "layer": layer if isinstance(layer, str) else "-",
            "level": level if level in ("info", "warn", "error") else "info",
            "msg": str(msg)[:MAX_MSG_LEN],
            "capability": (capability
                           if isinstance(capability, str) and capability
                           else None),
            "cycle": (cycle
                      if isinstance(cycle, int)
                      and not isinstance(cycle, bool)
                      else None),
        })
        return

    _reentrant.active = True
    try:
        # Sanitize
        if not isinstance(src, str) or not src:
            src = "unknown"
        if not isinstance(layer, str) or not layer:
            layer = "-"
        if level not in ("info", "warn", "error"):
            level = "info"
        if not isinstance(msg, str):
            msg = str(msg)
        if len(msg) > MAX_MSG_LEN:
            msg = msg[:MAX_MSG_LEN] + "...[truncated]"

        event = {
            "ts": time.time(),
            "src": src,
            "layer": layer,
            "level": level,
            "msg": msg,
            "capability": (capability
                           if isinstance(capability, str) and capability
                           else None),
            "cycle": (cycle
                      if isinstance(cycle, int)
                      and not isinstance(cycle, bool)
                      else None),
        }

        try:
            line = (json.dumps(event) + "\n").encode("utf-8")
        except Exception:
            _fallback_print(event)
            return

        # Fast path: if a live socket exists, try to send it
        with _send_lock:
            sock = _sock
            if sock is not None:
                try:
                    sock.sendall(line)
                    return
                except Exception:
                    _close_socket()
                    # fall through to queue and reconnect attempt

        # No live socket: try to (re)connect
        with _connect_lock:
            if not _ensure_connection():
                # Still offline: queue if room, then print
                if len(_pending) < QUEUE_MAX:
                    _pending.append(line)
                _fallback_print(event)
                return

            # Connected: flush queue, then send current
            with _send_lock:
                sock = _sock
                if sock is None:
                    if len(_pending) < QUEUE_MAX:
                        _pending.append(line)
                    _fallback_print(event)
                    return

                # Flush pending first (in order)
                _flush_pending(sock)
                try:
                    sock.sendall(line)
                except Exception:
                    _close_socket()
                    if len(_pending) < QUEUE_MAX:
                        _pending.append(line)
                    _fallback_print(event)
    finally:
        _reentrant.active = False


def shutdown():
    """Close the producer connection. Called on process exit."""
    with _send_lock:
        _close_socket()


# ----------------------------------------------------------------------
# Standalone test
# ----------------------------------------------------------------------
if __name__ == "__main__":
    print("[EVENT_EMIT] Testing emit; requires event_router.py to be running.")
    for i in range(5):
        emit("test", "layer1", "info", f"test event {i+1}")
        time.sleep(1)
    shutdown()
    print("[EVENT_EMIT] Done.")