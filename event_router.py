#!/usr/bin/env python3
# ============================================================================
# EVENT ROUTER — TCP loopback listener for structured events
# ============================================================================
# Producers (services, engines, orchestrator) connect and send JSON lines.
# Subscribers (orchestrator now, console later) connect and receive all events.
#
# FIXES APPLIED:
#   P0.1 — Subscriber sockets have a 5-second send timeout
#   P0.2 — Per-subscriber drop tracking; slow subscribers are removed
#   P1.1 — Remaining buffer flushed when a producer disconnects
#   P1.2 — Port file write failure aborts router startup
# ============================================================================

import os
import sys
import json
import socket
import threading
import time
from typing import Dict, List, Any, Optional

from config import Config

# Configuration
HOST = Config.EVENT_ROUTER_HOST
PREFERRED_PORT = Config.EVENT_ROUTER_PORT
PORT_FILE = Config.EVENT_ROUTER_PORT_FILE

# Limits
MAX_MSG_SIZE = 64 * 1024                    # 64 KB cap per message
SUB_QUEUE_SIZE = 1000                       # per-subscriber queue size
SUB_SEND_TIMEOUT = 5                        # seconds before subscriber send times out
MAX_DROPS_BEFORE_UNREGISTER = 1000          # dropped events before removing a subscriber

# Internal state
_running = False
_server_socket: Optional[socket.socket] = None
_actual_port: Optional[int] = None
_subscribers: List[Dict] = []
_subscribers_lock = threading.Lock()


# ----------------------------------------------------------------------
# Port file
# ----------------------------------------------------------------------
def _write_port_file(port: int) -> bool:
    """Write the port file atomically. Returns True on success."""
    try:
        os.makedirs(os.path.dirname(PORT_FILE), exist_ok=True)
        tmp = PORT_FILE + ".tmp"
        with open(tmp, "w") as f:
            f.write(str(port))
        os.replace(tmp, PORT_FILE)
        return True
    except Exception as e:
        print(f"[EVENT_ROUTER] Failed to write port file: {e}")
        return False


def _remove_port_file():
    try:
        if os.path.exists(PORT_FILE):
            os.remove(PORT_FILE)
    except:
        pass


# ----------------------------------------------------------------------
# Bind socket with fallback
# ----------------------------------------------------------------------
def _bind_socket() -> Optional[socket.socket]:
    global _actual_port

    # Try preferred port
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PREFERRED_PORT))
        s.listen(50)
        _actual_port = PREFERRED_PORT
        print(f"[EVENT_ROUTER] Bound to {HOST}:{PREFERRED_PORT}")
        return s
    except OSError as e:
        print(f"[EVENT_ROUTER] Preferred port {PREFERRED_PORT} unavailable: {e}")
        try:
            s.close()
        except:
            pass

    # Fall back to random
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, 0))
        s.listen(50)
        _actual_port = s.getsockname()[1]
        print(f"[EVENT_ROUTER] Bound to fallback port {_actual_port}")
        return s
    except Exception as e:
        print(f"[EVENT_ROUTER] Failed to bind any port: {e}")
        return None


# ----------------------------------------------------------------------
# Subscriber management
# ----------------------------------------------------------------------
def _register_subscriber(sock, addr) -> Dict:
    # P0.1: send timeout so a slow subscriber cannot block forever
    try:
        sock.settimeout(SUB_SEND_TIMEOUT)
    except Exception:
        pass

    sub = {
        "sock": sock,
        "addr": addr,
        "queue": [],
        "lock": threading.Lock(),
        "running": True,
        "drops": 0
    }
    with _subscribers_lock:
        _subscribers.append(sub)
    print(f"[EVENT_ROUTER] Subscriber registered: {addr}")
    return sub


def _unregister_subscriber(sub: Dict):
    sub["running"] = False
    with _subscribers_lock:
        if sub in _subscribers:
            _subscribers.remove(sub)
    print(f"[EVENT_ROUTER] Subscriber removed: {sub['addr']}")


def _broadcast(event: Dict):
    """Send one event to all subscribers. Drop oldest on overflow."""
    with _subscribers_lock:
        subs = list(_subscribers)

    try:
        line = (json.dumps(event) + "\n").encode("utf-8")
    except Exception:
        return

    if len(line) > MAX_MSG_SIZE:
        event_copy = dict(event)
        event_copy["msg"] = str(event_copy.get("msg", ""))[:8000] + "...[truncated]"
        try:
            line = (json.dumps(event_copy) + "\n").encode("utf-8")
        except Exception:
            return

    for sub in subs:
        if not sub["running"]:
            continue
        with sub["lock"]:
            if len(sub["queue"]) >= SUB_QUEUE_SIZE:
                sub["queue"].pop(0)
                sub["drops"] += 1
                if sub["drops"] >= MAX_DROPS_BEFORE_UNREGISTER:
                    # P0.2: mark for removal; the writer thread will unregister
                    sub["running"] = False
                    print(f"[EVENT_ROUTER] Subscriber {sub['addr']} dropped {sub['drops']} events, removing")
                    continue
            sub["queue"].append(line)


def _subscriber_writer(sub: Dict):
    """Continuously drain the subscriber's queue and send lines."""
    try:
        while sub["running"] and _running:
            line = None
            with sub["lock"]:
                if sub["queue"]:
                    line = sub["queue"].pop(0)
            if line is None:
                time.sleep(0.05)
                continue
            try:
                sub["sock"].sendall(line)
            except socket.timeout:
                # P0.1: send timed out; subscriber is not reading
                print(f"[EVENT_ROUTER] Send timeout to {sub['addr']} (slow subscriber), removing")
                break
            except Exception as e:
                print(f"[EVENT_ROUTER] Send failed to {sub['addr']}: {e}")
                break
    except Exception as e:
        print(f"[EVENT_ROUTER] Subscriber writer error: {e}")
    finally:
        _unregister_subscriber(sub)
        try:
            sub["sock"].close()
        except:
            pass


# ----------------------------------------------------------------------
# Client handling
# ----------------------------------------------------------------------
def _handle_client(client_socket, addr):
    """Handle one connection. First message determines role."""
    client_socket.settimeout(None)
    buffer = b""
    first_msg = None

    while _running:
        try:
            chunk = client_socket.recv(4096)
        except:
            break
        if not chunk:
            break
        buffer += chunk
        if b"\n" in buffer:
            line, buffer = buffer.split(b"\n", 1)
            try:
                first_msg = json.loads(line.decode("utf-8", errors="replace"))
            except:
                pass
            break

    if first_msg is None:
        try:
            client_socket.close()
        except:
            pass
        return

    # Subscriber?
    if isinstance(first_msg, dict) and first_msg.get("role") == "subscriber":
        sub = _register_subscriber(client_socket, addr)
        try:
            client_socket.sendall(b'{"ack":"subscribed"}\n')
        except:
            pass
        _subscriber_writer(sub)
        return

    # Producer
    _handle_producer(client_socket, addr, buffer, first_msg)


def _handle_producer(client_socket, addr, buffer: bytes, first_msg: Dict):
    """Read events from a producer until it disconnects."""
    try:
        if isinstance(first_msg, dict) and "ts" in first_msg:
            _broadcast(first_msg)

        while _running:
            try:
                chunk = client_socket.recv(4096)
            except:
                break
            if not chunk:
                break
            buffer += chunk

            if len(buffer) > MAX_MSG_SIZE * 2:
                buffer = b""
                continue

            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                if not line.strip():
                    continue
                try:
                    msg = json.loads(line.decode("utf-8", errors="replace"))
                    if isinstance(msg, dict):
                        _broadcast(msg)
                except:
                    continue

        # P1.1: flush any remaining buffer (producer sent last line without newline)
        if buffer.strip():
            try:
                msg = json.loads(buffer.decode("utf-8", errors="replace"))
                if isinstance(msg, dict):
                    _broadcast(msg)
            except:
                pass

    except Exception as e:
        print(f"[EVENT_ROUTER] Producer handler error: {e}")
    finally:
        try:
            client_socket.close()
        except:
            pass


# ----------------------------------------------------------------------
# Main accept loop
# ----------------------------------------------------------------------
def _accept_loop():
    global _running
    while _running:
        try:
            client, addr = _server_socket.accept()
            t = threading.Thread(target=_handle_client, args=(client, addr), daemon=True)
            t.start()
        except OSError:
            break
        except Exception as e:
            print(f"[EVENT_ROUTER] Accept error: {e}")
            time.sleep(0.5)


# ----------------------------------------------------------------------
# Public API
# ----------------------------------------------------------------------
def start_router() -> Optional[int]:
    """Start the router in a background thread. Returns the chosen port, or None on failure."""
    global _running, _server_socket, _actual_port

    if _running:
        return _actual_port

    _server_socket = _bind_socket()
    if _server_socket is None:
        return None

    # P1.2: fail fast if port file cannot be written
    if not _write_port_file(_actual_port):
        print("[EVENT_ROUTER] Aborting: cannot write port file")
        try:
            _server_socket.close()
        except:
            pass
        _server_socket = None
        _actual_port = None
        return None

    _running = True

    t = threading.Thread(target=_accept_loop, daemon=True)
    t.start()

    print(f"[EVENT_ROUTER] Started on {HOST}:{_actual_port}")
    return _actual_port


def stop_router():
    """Stop the router."""
    global _running
    _running = False
    try:
        if _server_socket:
            _server_socket.close()
    except:
        pass
    with _subscribers_lock:
        for sub in _subscribers:
            sub["running"] = False
            try:
                sub["sock"].close()
            except:
                pass
        _subscribers.clear()
    _remove_port_file()
    print("[EVENT_ROUTER] Stopped")


# ----------------------------------------------------------------------
# Standalone test
# ----------------------------------------------------------------------
if __name__ == "__main__":
    port = start_router()
    if port is None:
        print("[EVENT_ROUTER] Failed to start")
        sys.exit(1)
    print(f"[EVENT_ROUTER] Running on port {port}. Press Ctrl+C to stop.")
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        stop_router()