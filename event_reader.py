#!/usr/bin/env python3
# ============================================================================
# EVENT READER — Subscriber helper for the event router
# ============================================================================
# The orchestrator (and later the console) uses this helper to receive
# events from the router. The reader runs in a background thread and calls
# a user-provided handler for each event.
#
# FIXES APPLIED:
#   P0   — _connect() returns leftover buffer after the ack (no event loss)
#   P1.1 — Warn if start_reader is called while already running
#   P1.2 — Lock around _sock accesses (reader thread vs stop_reader)
#   P2.1 — Preserve complete lines when buffer cap is exceeded
#   P2.2 — Guard against stop_reader being called from the handler
#   P3.1 — Validate port number range in _read_port()
# ============================================================================

import os
import sys
import json
import socket
import threading
import time
from typing import Callable, Optional, Tuple

from config import Config

# Configuration
HOST = Config.EVENT_ROUTER_HOST
PORT_FILE = Config.EVENT_ROUTER_PORT_FILE

# Limits
CONNECT_TIMEOUT = 2
RECV_TIMEOUT = 1
RECONNECT_COOLDOWN = 5
MAX_LINE_BYTES = 128 * 1024

# Internal state
_thread: Optional[threading.Thread] = None
_running = False
_last_attempt = 0.0
_sock: Optional[socket.socket] = None
_sock_lock = threading.Lock()


# ----------------------------------------------------------------------
# Port discovery
# ----------------------------------------------------------------------
def _read_port() -> Optional[int]:
    """Read the router's port from the port file. Never caches."""
    try:
        if not os.path.exists(PORT_FILE):
            return None
        with open(PORT_FILE, "r") as f:
            port = int(f.read().strip())
        if not (1 <= port <= 65535):
            return None
        return port
    except Exception:
        return None


# ----------------------------------------------------------------------
# Socket management (lock-protected)
# ----------------------------------------------------------------------
def _get_sock() -> Optional[socket.socket]:
    with _sock_lock:
        return _sock


def _set_sock(s: socket.socket):
    global _sock
    with _sock_lock:
        _sock = s


def _clear_sock():
    global _sock
    with _sock_lock:
        old = _sock
        _sock = None
    if old is not None:
        try:
            old.close()
        except Exception:
            pass


# ----------------------------------------------------------------------
# Connect as subscriber
# ----------------------------------------------------------------------
def _connect() -> Optional[Tuple[socket.socket, bytes]]:
    """
    Open a subscriber connection.
    Returns (socket, leftover_buffer) on success, or None on failure.
    The leftover buffer contains any bytes received after the ack line
    in the same recv() call — events sent immediately after subscription.
    """
    port = _read_port()
    if port is None:
        return None

    s = None
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(CONNECT_TIMEOUT)
        s.connect((HOST, port))
        s.sendall(b'{"role":"subscriber"}\n')

        # Wait for ack line
        s.settimeout(CONNECT_TIMEOUT)
        buffer = b""
        deadline = time.monotonic() + CONNECT_TIMEOUT
        while time.monotonic() < deadline:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            buffer += chunk
            if b"\n" in buffer:
                break

        if b"\n" not in buffer:
            try: s.close()
            except: pass
            return None

        first_line, leftover = buffer.split(b"\n", 1)
        if b'{"ack":"subscribed"}' not in first_line:
            try: s.close()
            except: pass
            return None

        s.settimeout(RECV_TIMEOUT)
        return (s, leftover)
    except Exception:
        if s is not None:
            try: s.close()
            except: pass
        return None


# ----------------------------------------------------------------------
# Reader loop
# ----------------------------------------------------------------------
def _reader_loop(handler: Callable[[dict], None]):
    global _last_attempt, _running

    buffer = b""

    while _running:
        sock = _get_sock()

        if sock is None:
            # Throttle reconnect attempts
            if (time.monotonic() - _last_attempt) < RECONNECT_COOLDOWN and _last_attempt > 0:
                time.sleep(0.5)
                continue

            _last_attempt = time.monotonic()
            result = _connect()
            if result is None:
                continue

            new_sock, leftover = result
            _set_sock(new_sock)
            buffer = leftover        # <-- P0 fix: seed with post-ack bytes
            print("[EVENT_READER] Connected")
            continue

        try:
            chunk = sock.recv(4096)
        except socket.timeout:
            continue
        except Exception:
            _clear_sock()
            continue

        if not chunk:
            _clear_sock()
            continue

        buffer += chunk

        # Process complete lines first
        while b"\n" in buffer:
            line, buffer = buffer.split(b"\n", 1)
            if not line.strip():
                continue
            try:
                event = json.loads(line.decode("utf-8", errors="replace"))
                if not isinstance(event, dict):
                    continue
            except Exception:
                continue

            try:
                handler(event)
            except Exception as e:
                print(f"[EVENT_READER] Handler error: {e}")

        # P2.1: cap the REMAINING partial line, not the whole buffer
        if len(buffer) > MAX_LINE_BYTES:
            buffer = b""


# ----------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------
def start_reader(handler: Callable[[dict], None]):
    """
    Start the subscriber in a background daemon thread.

    handler: called with one event dict per line.
             Must not block for long periods.
             Must not call stop_reader().
    """
    global _thread, _running

    if _running:
        print("[EVENT_READER] Warning: reader already running; new handler ignored")
        return

    _running = True
    _thread = threading.Thread(
        target=_reader_loop,
        args=(handler,),
        daemon=True,
        name="event_reader"
    )
    _thread.start()
    print("[EVENT_READER] Started")


def stop_reader():
    """Stop the reader and close the connection."""
    global _running, _thread

    # P2.2: guard against deadlock if called from inside the handler
    if _thread is not None and threading.current_thread() is _thread:
        print("[EVENT_READER] Warning: stop_reader called from handler; ignored")
        return

    _running = False
    _clear_sock()

    if _thread is not None:
        _thread.join(timeout=2)
        _thread = None

    print("[EVENT_READER] Stopped")


# ----------------------------------------------------------------------
# Standalone test
# ----------------------------------------------------------------------
if __name__ == "__main__":
    def print_handler(event: dict):
        ts = time.strftime("%H:%M:%S", time.localtime(event.get("ts", time.time())))
        src = event.get("src", "unknown")
        layer = event.get("layer", "-")
        level = event.get("level", "info").upper()
        msg = event.get("msg", "")
        print(f"[{ts}][{src}][{layer}][{level}] {msg}")

    print("[EVENT_READER] Subscribing. Press Ctrl+C to stop.")
    start_reader(print_handler)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_reader()