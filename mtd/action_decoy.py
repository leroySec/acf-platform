#!/usr/bin/env python3
"""
mtd/action_decoy.py — Protocol-aware decoy listener MTD action.

Binds decoy listeners on capability-specific ports while the state
is ORANGE or RED, subject to a sustained-state gate. Presents a
protocol-plausible response, logs every accepted connection,
releases the ports cleanly.

LADDER GATE:
  ORANGE must be sustained for trigger_orange_seconds before the
  decoy binds. RED fires immediately. Duration is read through
  mtd/enabling.py — the action does not compute elapsed time
  itself.

Config key:
  capability_rules.<cap>.decoy.trigger_orange_seconds (default 60)

=====================================================================
WHAT AN ADMIN DOES MANUALLY (the formula)
=====================================================================

  1. Pick a port the real service is not using.
  2. Confirm nothing else is listening on it.
  3. Bind a listener on each chosen local address.
  4. Speak first or wait first, depending on the protocol.
  5. Read a bounded amount of what the client sends.
  6. Log source address, port, time, and a bounded prefix.
  7. Close the connection.
  8. Keep listening while the threat level is elevated.
  9. Stop listening and release the ports when the threat drops.

=====================================================================
SUPPORTED OPERATING SYSTEMS
=====================================================================

  Windows Server 2012 / Windows 8 and later, and any POSIX system.
  Standard library only. No subprocess calls. No localized parsing.
  Windows listeners use SO_EXCLUSIVEADDRUSE. POSIX uses SO_REUSEADDR.

ENGINE CONTRACT (mtd_engine.py must honor):
  E1. should_activate(state) is called exactly once per cycle.
  E2. Each capability's action object is constructed once, reused.
  E3. status() may be called from any thread at any time.
"""

import errno
import json
import os
import socket
import sys
import threading
import time
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
    from platform_utils import acquire_lock, release_lock
    _LOCK_AVAILABLE = True
except ImportError:
    _LOCK_AVAILABLE = False

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

_DEFAULT_DECOY_PORTS: Dict[str, int] = {
    "ssh":       2022,
    "sensor":    2023,
    "app_http":  8081,
    "app_smtp":  2525,
    "app_ftp":   2121,
    "app_mysql": 3307,
}

_DEFAULT_REAL_PORTS: Dict[str, Optional[int]] = {
    "ssh":       22,
    "sensor":    None,
    "app_http":  80,
    "app_smtp":  25,
    "app_ftp":   21,
    "app_mysql": 3306,
}

_DEFAULT_BANNERS: Dict[str, bytes] = {
    "ssh":       b"SSH-2.0-OpenSSH_9.5\r\n",
    "sensor":    b"",
    "app_http":  b"HTTP/1.1 200 OK\r\n"
                 b"Server: nginx/1.24.0\r\n"
                 b"Content-Length: 0\r\n"
                 b"Connection: close\r\n\r\n",
    "app_smtp":  b"220 mail.example.com ESMTP Postfix\r\n",
    "app_ftp":   b"220 FTP server ready\r\n",
    "app_mysql": b"\x0a\x00\x00\x00\x0a\x35\x2e\x37\x2e\x34\x34\x00",
}

_DEFAULT_DIRECTIONS: Dict[str, str] = {
    "ssh":       "server_first",
    "sensor":    "none",
    "app_http":  "client_first",
    "app_smtp":  "server_first",
    "app_ftp":   "server_first",
    "app_mysql": "server_first",
}

_DEFAULT_PAYLOAD_PREFIX_BYTES: Dict[str, int] = {
    "ssh":       64,
    "sensor":    64,
    "app_http":  0,
    "app_smtp":  0,
    "app_ftp":   0,
    "app_mysql": 0,
}

DEFAULT_BIND_HOSTS: Tuple[str, ...] = ("127.0.0.1",)
DEFAULT_READ_TIMEOUT = 5.0
DEFAULT_READ_MAX_BYTES = 1024
DEFAULT_PAYLOAD_PREFIX_BYTES = 0
DEFAULT_MAX_CONCURRENT = 4
DEFAULT_MAX_HISTORY = 100
DEFAULT_LISTEN_BACKLOG = 8
DEFAULT_BIND_RETRY_ATTEMPTS = 4
DEFAULT_BIND_RETRY_DELAY = 0.25
DEFAULT_BANNER_MAX_BYTES = 4096
DEFAULT_TRIGGER_ORANGE_SECONDS = 60

VALID_DIRECTIONS = ("server_first", "client_first", "none")

ACCEPT_POLL_INTERVAL = 0.5
ACCEPT_ERROR_BACKOFF = 0.2
ACCEPT_MAX_CONSECUTIVE_ERRORS = 20
THREAD_JOIN_TIMEOUT = 3.0

MIN_PORT = 1
MAX_PORT = 65535

_WSA_EADDRINUSE = 10048
_WSA_EACCES = 10013


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


def _coerce_optional_int(value: Any, default: Optional[int],
                         minimum: int, maximum: int
                         ) -> Optional[int]:
    if value is None:
        return default
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


def _coerce_bind_hosts(value: Any) -> List[str]:
    if value is None:
        return list(DEFAULT_BIND_HOSTS)
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return list(DEFAULT_BIND_HOSTS)
    hosts: List[str] = []
    for h in value:
        if isinstance(h, str) and h.strip():
            h_clean = h.strip()
            if h_clean not in hosts:
                hosts.append(h_clean)
    return hosts or list(DEFAULT_BIND_HOSTS)


def _coerce_banner(value: Any, default: bytes,
                   max_bytes: int) -> Tuple[bytes, str]:
    if value is None:
        candidate = default
    elif isinstance(value, bytes):
        candidate = value
    elif isinstance(value, str):
        candidate = value.encode("utf-8", errors="replace")
    else:
        return default, ""

    if len(candidate) > max_bytes:
        return candidate[:max_bytes], (
            f"banner truncated from {len(candidate)} to {max_bytes} bytes"
        )
    return candidate, ""


def _coerce_direction(value: Any, default: str) -> str:
    if isinstance(value, str):
        v = value.strip().lower()
        if v in VALID_DIRECTIONS:
            return v
    return default


def _resolve_decoy_config(capability: str) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "trigger_orange_seconds": DEFAULT_TRIGGER_ORANGE_SECONDS,
    }
    cfg = _load_system_config_cached()
    rules = cfg.get("capability_rules", {})
    if not isinstance(rules, dict):
        return out
    entry = rules.get(capability)
    if not isinstance(entry, dict):
        return out
    dec = entry.get("decoy")
    if not isinstance(dec, dict):
        return out
    if "trigger_orange_seconds" in dec:
        out["trigger_orange_seconds"] = _coerce_int(
            dec["trigger_orange_seconds"],
            out["trigger_orange_seconds"], 0, 86400)
    return out


def _prepare_socket(family: int, socktype: int, proto: int
                    ) -> Tuple[socket.socket, str]:
    s = socket.socket(family, socktype, proto)
    warning = ""
    if os.name == "nt":
        so_excl = getattr(socket, "SO_EXCLUSIVEADDRUSE", None)
        if so_excl is None:
            warning = ("SO_EXCLUSIVEADDRUSE unavailable; "
                       "port may be hijackable")
        else:
            try:
                s.setsockopt(socket.SOL_SOCKET, so_excl, 1)
            except OSError as e:
                warning = (f"SO_EXCLUSIVEADDRUSE failed: {e}; "
                           f"port may be hijackable")
    else:
        try:
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except OSError:
            pass
    return s, warning


def _shutdown_quiet(sock: socket.socket) -> None:
    try:
        sock.shutdown(socket.SHUT_RDWR)
    except Exception:
        pass


def _socket_errno_codes(e: BaseException) -> Tuple[int, ...]:
    codes: List[int] = []
    if isinstance(e, OSError):
        we = getattr(e, "winerror", None)
        if isinstance(we, int):
            codes.append(we)
        er = getattr(e, "errno", None)
        if isinstance(er, int):
            codes.append(er)
    return tuple(codes)


def _is_addr_in_use(codes: Tuple[int, ...]) -> bool:
    for c in codes:
        if c in (_WSA_EADDRINUSE, errno.EADDRINUSE):
            return True
    return False


class DecoyAction(MTDAction):
    name = "decoy"
    one_shot = False
    requires_admin = False

    @classmethod
    def supports(cls, capability: str, context: Dict[str, Any]) -> bool:
        return isinstance(capability, str) and bool(capability)

    def __init__(self, capability: str, context: Dict[str, Any]):
        super().__init__(capability, context)

        self._lock_key: str = f"decoy::{capability}"

        ctx: Dict[str, Any] = context if isinstance(context, dict) else {}

        default_decoy_port = _DEFAULT_DECOY_PORTS.get(capability, 0)
        self.decoy_port: int = _coerce_int(
            ctx.get("decoy_port"),
            default_decoy_port,
            MIN_PORT, MAX_PORT,
        )

        default_real_port = _DEFAULT_REAL_PORTS.get(capability)
        self.real_port: Optional[int] = _coerce_optional_int(
            ctx.get("real_port"),
            default_real_port,
            MIN_PORT, MAX_PORT,
        )

        self.bind_hosts: List[str] = _coerce_bind_hosts(
            ctx.get("bind_hosts")
        )
        self.expand_all_addresses: bool = _coerce_bool(
            ctx.get("expand_all_addresses"), False
        )

        self.banner_max_bytes: int = _coerce_int(
            ctx.get("banner_max_bytes"),
            DEFAULT_BANNER_MAX_BYTES,
            1, 65536,
        )
        banner, banner_warning = _coerce_banner(
            ctx.get("banner"),
            _DEFAULT_BANNERS.get(capability, b""),
            self.banner_max_bytes,
        )
        self.banner: bytes = banner
        self._banner_warning: str = banner_warning

        self.protocol_direction: str = _coerce_direction(
            ctx.get("protocol_direction"),
            _DEFAULT_DIRECTIONS.get(capability, "none"),
        )

        self.read_timeout: float = _coerce_float(
            ctx.get("read_timeout"),
            DEFAULT_READ_TIMEOUT, 0.1, 60.0,
        )
        self.read_max_bytes: int = _coerce_int(
            ctx.get("read_max_bytes"),
            DEFAULT_READ_MAX_BYTES, 1, 65536,
        )
        self.payload_prefix_bytes: int = _coerce_int(
            ctx.get("payload_prefix_bytes"),
            _DEFAULT_PAYLOAD_PREFIX_BYTES.get(
                capability, DEFAULT_PAYLOAD_PREFIX_BYTES),
            0, 1024,
        )
        self.max_concurrent: int = _coerce_int(
            ctx.get("max_concurrent"),
            DEFAULT_MAX_CONCURRENT, 1, 64,
        )
        self.max_history: int = _coerce_int(
            ctx.get("max_history"),
            DEFAULT_MAX_HISTORY, 1, 1000,
        )
        self.listen_backlog: int = _coerce_int(
            ctx.get("listen_backlog"),
            DEFAULT_LISTEN_BACKLOG, 1, 128,
        )
        self.bind_retry_attempts: int = _coerce_int(
            ctx.get("bind_retry_attempts"),
            DEFAULT_BIND_RETRY_ATTEMPTS, 0, 10,
        )
        self.bind_retry_delay: float = _coerce_float(
            ctx.get("bind_retry_delay"),
            DEFAULT_BIND_RETRY_DELAY, 0.0, 5.0,
        )

        decoy_cfg = _resolve_decoy_config(capability)
        self.trigger_orange_seconds: int = int(
            decoy_cfg.get("trigger_orange_seconds")
            or DEFAULT_TRIGGER_ORANGE_SECONDS)

        self._construction_warnings: List[str] = []
        if banner_warning:
            self._construction_warnings.append(banner_warning)
        if self.banner and self.protocol_direction == "none":
            self._construction_warnings.append(
                "banner set but protocol_direction is 'none'; "
                "banner will not be sent"
            )

        self._is_active = False
        self._bound_sockets: List[socket.socket] = []
        self._accept_threads: List[threading.Thread] = []
        self._stop_event: Optional[threading.Event] = None
        self._sem: Optional[threading.BoundedSemaphore] = None
        self._bound_targets: List[Dict[str, Any]] = []
        self._started_at = 0.0
        self._stopped_at = 0.0
        self._connections_total = 0
        self._connections_over_cap = 0
        self._workers_started = 0
        self._workers_failed_to_start = 0
        self._last_connection: Dict[str, Any] = {}
        self._connections: List[Dict[str, Any]] = []
        self._bind_failures: List[Dict[str, str]] = []
        self._accept_errors: List[Dict[str, Any]] = []
        self._socket_warnings: List[str] = []
        self._listener_exits: List[Dict[str, Any]] = []

        self._cached_targets: Optional[List[Dict[str, Any]]] = None
        self._cached_resolve_failures: List[Dict[str, str]] = []

        self._gate_reason: str = ""

    def _resolve_bind_targets(self
                              ) -> Tuple[List[Dict[str, Any]],
                                         List[Dict[str, str]]]:
        with _get_snapshot_lock(self._lock_key):
            if self._cached_targets is not None:
                return (list(self._cached_targets),
                        list(self._cached_resolve_failures))

        targets: List[Dict[str, Any]] = []
        failures: List[Dict[str, str]] = []
        seen = set()

        for host in self.bind_hosts:
            try:
                infos = socket.getaddrinfo(
                    host, self.decoy_port,
                    family=socket.AF_UNSPEC,
                    type=socket.SOCK_STREAM,
                    proto=0,
                    flags=0,
                )
            except socket.gaierror as e:
                failures.append({"host": host,
                                 "reason": f"resolve failed: {e}"})
                continue
            except Exception as e:
                failures.append({"host": host,
                                 "reason": f"resolve error: {e}"})
                continue

            if not infos:
                failures.append({"host": host,
                                 "reason": "no addresses returned"})
                continue

            if not self.expand_all_addresses:
                infos = infos[:1]

            for family, socktype, proto, _canon, sockaddr in infos:
                key = (family, str(sockaddr))
                if key in seen:
                    continue
                seen.add(key)
                targets.append({
                    "host": host,
                    "family": family,
                    "socktype": socktype,
                    "proto": proto,
                    "sockaddr": sockaddr,
                })

        with _get_snapshot_lock(self._lock_key):
            if self._cached_targets is None:
                self._cached_targets = list(targets)
                self._cached_resolve_failures = list(failures)
            return (list(self._cached_targets),
                    list(self._cached_resolve_failures))

    def _static_checks(self) -> Optional[str]:
        if not isinstance(self.capability, str) or not self.capability:
            return "invalid capability"
        if self.decoy_port < MIN_PORT or self.decoy_port > MAX_PORT:
            return f"decoy port {self.decoy_port} out of range"
        if (self.real_port is not None
                and self.real_port == self.decoy_port):
            return (f"decoy port {self.decoy_port} equals real port "
                    f"{self.real_port}")
        if not self.bind_hosts:
            return "no bind hosts"
        return None

    def preflight(self) -> Tuple[str, str, str]:
        err = self._static_checks()
        if err:
            return (STATUS_BLOCKED, "", err)

        targets, resolve_failures = self._resolve_bind_targets()
        if not targets:
            detail = "; ".join(
                f"{f['host']}: {f['reason']}" for f in resolve_failures
            ) or "no bind hosts resolved"
            return (STATUS_BLOCKED, "",
                    f"cannot resolve any bind host ({detail})")

        return (STATUS_READY, MODE_PRIMARY, "")

    def should_activate(self, state: str) -> bool:
        """
        Enabling check via mtd/enabling.py.

        ORANGE requires sustained duration. RED fires immediately.
        The enabling module reads the state and its duration from
        the Blackboard and evaluates the minimum.
        """
        enabled, reason = enabling.is_enabled(
            self.capability,
            state_minimums={
                "ORANGE": self.trigger_orange_seconds,
                "RED": 0,
            },
        )
        with _get_snapshot_lock(self._lock_key):
            self._gate_reason = reason
        return enabled

    def is_active(self) -> bool:
        with _get_snapshot_lock(self._lock_key):
            return self._is_active

    def activate(self) -> Tuple[bool, str]:
        with _get_mutation_lock(self._lock_key):
            with _get_snapshot_lock(self._lock_key):
                if self._is_active:
                    return True, ""

            err = self._static_checks()
            if err:
                return False, err

            with _get_snapshot_lock(self._lock_key):
                self._workers_started = 0
                self._workers_failed_to_start = 0
                self._accept_errors = []
                self._bind_failures = []
                self._socket_warnings = []
                self._listener_exits = []

            targets, resolve_failures = self._resolve_bind_targets()
            bind_failures: List[Dict[str, str]] = list(resolve_failures)

            bound: List[Tuple[socket.socket, Dict[str, Any]]] = []
            for t in targets:
                s, reason = self._bind_one_target(t)
                if s is None:
                    bind_failures.append({"host": t["host"],
                                          "reason": reason})
                else:
                    bound.append((s, t))

            if not bound:
                with _get_snapshot_lock(self._lock_key):
                    self._bind_failures = bind_failures
                return False, (
                    "could not bind any target: "
                    + "; ".join(f"{f['host']}: {f['reason']}"
                                for f in bind_failures)
                )

            stop_event = threading.Event()
            sem = threading.BoundedSemaphore(self.max_concurrent)

            started: List[Tuple[socket.socket, Dict[str, Any],
                                threading.Thread]] = []
            start_errors: List[str] = []

            for s, t in bound:
                tid = _next_thread_id()
                thread = threading.Thread(
                    target=self._accept_loop,
                    args=(s, t, stop_event, sem),
                    daemon=True,
                    name=f"decoy-{self.capability}-{tid}-"
                         f"{t['host']}:{self.decoy_port}",
                )
                try:
                    thread.start()
                    started.append((s, t, thread))
                except Exception as e:
                    start_errors.append(f"{t['host']}: {e}")
                    try:
                        _shutdown_quiet(s)
                    except Exception:
                        pass
                    try:
                        s.close()
                    except Exception:
                        pass

            if not started:
                with _get_snapshot_lock(self._lock_key):
                    self._bind_failures = bind_failures
                return False, (
                    "all accept threads failed to start: "
                    + "; ".join(start_errors)
                )

            with _get_snapshot_lock(self._lock_key):
                self._is_active = True
                self._started_at = time.time()
                self._stop_event = stop_event
                self._sem = sem
                self._bound_sockets = [s for s, _, _ in started]
                self._accept_threads = [th for _, _, th in started]
                self._bound_targets = [t for _, t, _ in started]
                self._bind_failures = bind_failures

            for w in self._construction_warnings:
                _safe_emit(self.capability, _LAYER, "warn", w)
            for e in start_errors:
                _safe_emit(self.capability, _LAYER, "warn",
                           f"accept thread failed to start: {e}")
            for f in bind_failures:
                _safe_emit(self.capability, _LAYER, "warn",
                           f"bind target failed: "
                           f"{f['host']}: {f['reason']}")

            _safe_emit(self.capability, _LAYER, "info",
                       f"decoy started on port {self.decoy_port} "
                       f"({len(started)} listener(s), "
                       f"direction={self.protocol_direction})")
            return True, ""

    def _bind_one_target(self, target: Dict[str, Any]
                         ) -> Tuple[Optional[socket.socket], str]:
        last_reason = ""
        attempts = self.bind_retry_attempts + 1
        for attempt in range(attempts):
            s, warning = _prepare_socket(
                target["family"], target["socktype"], target["proto"],
            )
            if warning:
                entry = f"{target['host']}: {warning}"
                with _get_snapshot_lock(self._lock_key):
                    if entry not in self._socket_warnings:
                        self._socket_warnings.append(entry)
            try:
                s.bind(target["sockaddr"])
                s.listen(self.listen_backlog)
                s.settimeout(ACCEPT_POLL_INTERVAL)
                return s, ""
            except OSError as e:
                codes = _socket_errno_codes(e)
                last_reason = f"{e} (codes={codes})"
                try:
                    _shutdown_quiet(s)
                except Exception:
                    pass
                try:
                    s.close()
                except Exception:
                    pass
                if _is_addr_in_use(codes) and attempt + 1 < attempts:
                    delay = self.bind_retry_delay * (2 ** attempt)
                    time.sleep(delay)
                    continue
                return None, last_reason
            except Exception as e:
                last_reason = str(e)
                try:
                    s.close()
                except Exception:
                    pass
                return None, last_reason
        return None, last_reason or "bind failed"

    def deactivate(self) -> Tuple[bool, str]:
        with _get_mutation_lock(self._lock_key):
            with _get_snapshot_lock(self._lock_key):
                if not self._is_active:
                    return True, ""
                stop_event = self._stop_event
                threads = list(self._accept_threads)
                sockets = list(self._bound_sockets)

            if stop_event is not None:
                stop_event.set()

            for s in sockets:
                _shutdown_quiet(s)
                try:
                    s.close()
                except Exception:
                    pass

            for t in threads:
                if t.is_alive():
                    t.join(timeout=THREAD_JOIN_TIMEOUT)

            alive = [t for t in threads if t.is_alive()]

            with _get_snapshot_lock(self._lock_key):
                self._is_active = False
                self._stopped_at = time.time()
                self._bound_sockets = []
                self._accept_threads = alive
                self._stop_event = None
                self._sem = None
                self._bound_targets = []

            if alive:
                _safe_emit(self.capability, _LAYER, "warn",
                           f"{len(alive)} accept thread(s) did not "
                           f"stop within {THREAD_JOIN_TIMEOUT}s")
            _safe_emit(self.capability, _LAYER, "info",
                       f"decoy on port {self.decoy_port} stopped "
                       f"({self._connections_total} connection(s) served)")
            return True, ""

    def _accept_loop(self, listener: socket.socket,
                     target: Dict[str, Any],
                     stop_event: threading.Event,
                     sem: threading.BoundedSemaphore) -> None:
        host = target["host"]
        consecutive_errors = 0
        exit_reason = ""

        try:
            while not stop_event.is_set():
                try:
                    client, addr = listener.accept()
                    consecutive_errors = 0
                except socket.timeout:
                    consecutive_errors = 0
                    continue
                except OSError as e:
                    if stop_event.is_set():
                        exit_reason = "stop_event"
                        break
                    consecutive_errors += 1
                    codes = _socket_errno_codes(e)
                    with _get_snapshot_lock(self._lock_key):
                        self._accept_errors.append({
                            "ts": time.time(),
                            "host": host,
                            "codes": list(codes),
                            "error": str(e)[:200],
                        })
                        if len(self._accept_errors) > self.max_history:
                            self._accept_errors = self._accept_errors[
                                -self.max_history:]
                    if consecutive_errors >= ACCEPT_MAX_CONSECUTIVE_ERRORS:
                        exit_reason = (
                            f"consecutive_errors={consecutive_errors}"
                        )
                        _safe_emit(self.capability, _LAYER, "error",
                                   f"accept loop on {host} exiting "
                                   f"after {consecutive_errors} "
                                   f"consecutive errors")
                        break
                    time.sleep(ACCEPT_ERROR_BACKOFF)
                    continue
                except Exception as e:
                    if stop_event.is_set():
                        exit_reason = "stop_event"
                        break
                    consecutive_errors += 1
                    with _get_snapshot_lock(self._lock_key):
                        self._accept_errors.append({
                            "ts": time.time(),
                            "host": host,
                            "codes": [],
                            "error": str(e)[:200],
                        })
                    if consecutive_errors >= ACCEPT_MAX_CONSECUTIVE_ERRORS:
                        exit_reason = (
                            f"consecutive_errors={consecutive_errors}"
                        )
                        break
                    time.sleep(ACCEPT_ERROR_BACKOFF)
                    continue

                if not sem.acquire(blocking=False):
                    self._record_connection(
                        addr, b"", over_cap=True, bound_host=host,
                    )
                    try:
                        client.close()
                    except Exception:
                        pass
                    continue

                worker_started = False
                try:
                    tid = _next_thread_id()
                    worker = threading.Thread(
                        target=self._handle_connection,
                        args=(client, addr, sem, host, stop_event),
                        daemon=True,
                        name=f"decoy-worker-{self.capability}-{tid}",
                    )
                    worker.start()
                    worker_started = True
                    with _get_snapshot_lock(self._lock_key):
                        self._workers_started += 1
                except Exception as e:
                    with _get_snapshot_lock(self._lock_key):
                        self._workers_failed_to_start += 1
                    self._record_connection(
                        addr, b"", over_cap=False, bound_host=host,
                        worker_start_failed=True,
                    )
                    _safe_emit(self.capability, _LAYER, "warn",
                               f"worker thread start failed: {e}")
                finally:
                    if not worker_started:
                        try:
                            sem.release()
                        except Exception:
                            pass
                        try:
                            client.close()
                        except Exception:
                            pass
        finally:
            if exit_reason and exit_reason != "stop_event":
                with _get_snapshot_lock(self._lock_key):
                    self._listener_exits.append({
                        "ts": time.time(),
                        "host": host,
                        "bound_port": self.decoy_port,
                        "reason": exit_reason,
                    })

    def _handle_connection(self, client: socket.socket,
                           addr: Tuple[str, int],
                           sem: threading.BoundedSemaphore,
                           bound_host: str,
                           stop_event: threading.Event) -> None:
        payload = b""
        try:
            client.settimeout(self.read_timeout)

            if self.protocol_direction == "server_first":
                if self.banner:
                    try:
                        client.sendall(self.banner)
                    except Exception:
                        pass
                payload = self._read_bounded(client)
            elif self.protocol_direction == "client_first":
                payload = self._read_bounded(client)
                if payload and self.banner:
                    try:
                        client.sendall(self.banner)
                    except Exception:
                        pass
            else:
                payload = self._read_bounded(client)
        except Exception:
            pass
        finally:
            try:
                client.close()
            except Exception:
                pass
            try:
                sem.release()
            except Exception:
                pass

        self._record_connection(addr, payload, over_cap=False,
                                bound_host=bound_host)

    def _read_bounded(self, client: socket.socket) -> bytes:
        chunks: List[bytes] = []
        remaining = self.read_max_bytes
        deadline = time.time() + self.read_timeout

        while remaining > 0:
            now = time.time()
            if now >= deadline:
                break
            try:
                client.settimeout(max(0.05, deadline - now))
            except Exception:
                pass
            try:
                chunk = client.recv(min(remaining, 4096))
            except socket.timeout:
                break
            except Exception:
                break
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)

        return b"".join(chunks)

    def _record_connection(self, addr: Any, payload: bytes,
                           over_cap: bool, bound_host: str,
                           worker_start_failed: bool = False) -> None:
        now = time.time()
        try:
            if isinstance(addr, (tuple, list)) and len(addr) >= 2:
                src_ip = str(addr[0])
                src_port = int(addr[1])
            else:
                src_ip, src_port = "?", 0
        except Exception:
            src_ip, src_port = "?", 0

        if self.payload_prefix_bytes > 0:
            payload_prefix: Optional[str] = payload[
                : self.payload_prefix_bytes].hex()
        else:
            payload_prefix = None

        entry: Dict[str, Any] = {
            "ts": now,
            "src_ip": src_ip,
            "src_port": src_port,
            "bound_host": bound_host,
            "bound_port": self.decoy_port,
            "direction": self.protocol_direction,
            "bytes_received": len(payload),
            "payload_prefix": payload_prefix,
            "over_cap": over_cap,
            "worker_start_failed": worker_start_failed,
        }

        with _get_snapshot_lock(self._lock_key):
            if over_cap:
                self._connections_over_cap += 1
            self._connections_total += 1
            self._last_connection = entry
            self._connections.append(entry)
            if len(self._connections) > self.max_history:
                self._connections = self._connections[-self.max_history:]

    def status(self) -> Dict[str, Any]:
        with _get_snapshot_lock(self._lock_key):
            return {
                "decoy": True,
                "decoy_port": self.decoy_port,
                "real_port": self.real_port,
                "bind_hosts": list(self.bind_hosts),
                "expand_all_addresses": self.expand_all_addresses,
                "bound_targets": [
                    {"host": t["host"],
                     "family": t["family"],
                     "sockaddr": str(t["sockaddr"])}
                    for t in self._bound_targets
                ],
                "bind_failures": list(self._bind_failures),
                "socket_warnings": list(self._socket_warnings),
                "banner_bytes": len(self.banner),
                "banner_warning": self._banner_warning,
                "construction_warnings":
                    list(self._construction_warnings),
                "protocol_direction": self.protocol_direction,
                "read_timeout": self.read_timeout,
                "read_max_bytes": self.read_max_bytes,
                "payload_prefix_bytes": self.payload_prefix_bytes,
                "max_concurrent": self.max_concurrent,
                "concurrency_scope": "global_across_targets",
                "trigger_orange_seconds": self.trigger_orange_seconds,
                "gate_reason": self._gate_reason,
                "active": self._is_active,
                "started_at": self._started_at,
                "stopped_at": self._stopped_at,
                "connections_total": self._connections_total,
                "connections_over_cap": self._connections_over_cap,
                "workers_started": self._workers_started,
                "workers_failed_to_start":
                    self._workers_failed_to_start,
                "accept_threads_alive":
                    sum(1 for t in self._accept_threads if t.is_alive()),
                "listener_exits": list(self._listener_exits),
                "accept_errors": list(self._accept_errors),
                "last_connection": dict(self._last_connection),
                "connections": list(self._connections),
                "backend": "socket",
            }