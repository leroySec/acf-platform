#!/usr/bin/env python3
# ============================================================================
# LAYER 1 EXTENSION: SENSOR SERVICE (Network, Processes, Files, Resources)
# ============================================================================
# PURPOSE: Collect local system telemetry and write to the shared Blackboard.
#
# ARCHITECTURE PATTERNS: Blackboard, Strategy, Template Method, Observer.
# DESIGN PRINCIPLES: Single Responsibility, Fail-Safe, Jitter.
# SECURITY ENGINEERING: Least Privilege, Atomic Writes, Audit Logging.
#
# Phase 3: All messages routed through emit() with source "sensor" and
#          layer "layer1", so the console can filter by capability.
# ============================================================================

import os
import sys
import json
import time
import socket
import random
import hashlib
import signal
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from typing import Dict, List, Set, Tuple

from platform_utils import acquire_lock, release_lock

from config import Config
from sensor_config import SensorConfig

# ----------------------------------------------------------------------
# Phase 3: event emitter (with fallback to print)
# ----------------------------------------------------------------------
try:
    from event_emit import emit
except ImportError:
    def emit(src, layer, level, msg, capability=None, cycle=None):
        ts = time.strftime("%H:%M:%S")
        print(f"[{ts}][{src}][{layer}][{level.upper()}] {msg}")


# ---------- Constants ----------
SRC = "sensor"
LAYER = "layer1"


# ----------------------------------------------------------------------
# Disable check (reads the dict shape of disabled_capabilities)
# ----------------------------------------------------------------------
def _is_disabled(capability, layer):
    """
    Return True if (capability, layer) is disabled in the Blackboard.

    disabled_capabilities shape: {capability: [layers]}. A "*" in the
    list means all layers of that capability are disabled. An old-format
    list of capability names is treated as fully disabled for that
    capability, for backward compatibility during transition.
    """
    try:
        with open(Config.BLACKBOARD_FILE, "r") as f:
            disabled = json.load(f).get("disabled_capabilities", {})
    except Exception:
        return False

    if isinstance(disabled, list):
        return capability in disabled
    if not isinstance(disabled, dict):
        return False

    entry = disabled.get(capability)
    if not entry or not isinstance(entry, list):
        return False
    if "*" in entry:
        return True
    return layer in entry


class SensorService:
    def __init__(self):
        # ========== P0 FIX: Validate Sensor Config ==========
        self._validate_config()

        # ========== CAPABILITIES DETECTION ==========
        self.method = self._detect_method()
        emit(SRC, LAYER, "info", f"Using collection method: {self.method}",
             capability="sensor")

        # ========== INTERNAL STATE ==========
        self.last_connections: Set[Tuple[str, int, str]] = set()
        self.last_processes: Set[str] = set()
        self.baseline_cpu = 0.0
        self.baseline_memory = 0.0
        self.file_hashes: Dict[str, str] = {}

        # ========== P3 FIX: Whitelist warning flag ==========
        self._whitelist_warned = False

        # ========== FILE INTEGRITY BASELINE ==========
        self._initialize_file_hashes()

        # ========== RUN LOOP STATE ==========
        self.running = True
        self.cycle_count = 0
        self.MAX_RETRIES = 5
        self.healthy = True

    # ------------------------------------------------------------------------
    # P0 FIX: Validate SensorConfig Constants
    # ------------------------------------------------------------------------
    def _validate_config(self):
        """Ensure all required SensorConfig constants exist. Fail-fast if missing."""
        required_attrs = [
            "INTERVAL_GREEN", "INTERVAL_YELLOW", "INTERVAL_ORANGE", "INTERVAL_RED",
            "CPU_SPIKE_THRESHOLD", "CPU_SPIKE_MULTIPLIER",
            "MEMORY_SPIKE_THRESHOLD", "MEMORY_SPIKE_MULTIPLIER",
            "BLACKBOARD_SECTION", "SENSOR_HEARTBEAT_FILE"
        ]
        missing = [attr for attr in required_attrs if not hasattr(SensorConfig, attr)]
        if missing:
            emit(SRC, LAYER, "error", f"CRITICAL: Missing SensorConfig constants: {missing}",
                 capability="sensor")
            emit(SRC, LAYER, "error", "Please ensure sensor_config.py is up to date.",
                 capability="sensor")
            sys.exit(1)
        emit(SRC, LAYER, "info", "SensorConfig validation passed.",
             capability="sensor")

    # ------------------------------------------------------------------------
    # 1. METHOD DETECTION (reads precondition from Blackboard)
    # ------------------------------------------------------------------------
    def _detect_method(self) -> str:
        """Read the sensor method from the preconditions set by sensor_config.py."""
        try:
            with open(Config.BLACKBOARD_FILE, "r") as f:
                data = json.load(f)
                method = data.get("preconditions", {}).get("layer_1_sensor", {}).get("method", "procfs")
                return method if method else "procfs"
        except Exception:
            return "procfs"

    # ------------------------------------------------------------------------
    # 2. FILE INTEGRITY (P4 FIX: Timeout for os.walk)
    # ------------------------------------------------------------------------
    def _initialize_file_hashes(self):
        """Hash critical system files with a 15-second timeout to prevent hangs."""
        hashes = {}
        critical_dirs = ["/bin", "/usr/sbin", "/usr/bin"]
        critical_files = ["/etc/passwd", "/etc/shadow", "/etc/ssh/sshd_config", "/etc/hosts.deny"]

        # Hash critical files
        for path in critical_files:
            if os.path.exists(path) and os.access(path, os.R_OK):
                hashes[path] = self._hash_file(path)

        # Hash executables with a timeout (P4)
        def timeout_handler(signum, frame):
            raise TimeoutError("os.walk() timed out")

        for dir_path in critical_dirs:
            if os.path.exists(dir_path) and os.access(dir_path, os.R_OK):
                try:
                    # Set alarm for 15 seconds
                    signal.signal(signal.SIGALRM, timeout_handler)
                    signal.alarm(15)

                    for root, dirs, files in os.walk(dir_path):
                        depth = root[len(dir_path):].count(os.sep)
                        if depth > 2:
                            continue
                        for f in files:
                            full_path = os.path.join(root, f)
                            if os.path.isfile(full_path) and os.access(full_path, os.X_OK) and not os.path.islink(full_path):
                                hashes[full_path] = self._hash_file(full_path)

                    # Cancel alarm
                    signal.alarm(0)
                except TimeoutError:
                    emit(SRC, LAYER, "warn", f"os.walk() timed out on {dir_path}. Skipping remaining files.",
                         capability="sensor")
                    signal.alarm(0)
                except PermissionError:
                    pass

        self.file_hashes = hashes
        emit(SRC, LAYER, "info", f"Initialized {len(hashes)} file hashes.",
             capability="sensor")

    def _hash_file(self, path: str) -> str:
        """SHA256 hash of the first 1MB."""
        try:
            with open(path, "rb") as f:
                data = f.read(1024 * 1024)
                return hashlib.sha256(data).hexdigest()
        except Exception:
            return ""

    # ------------------------------------------------------------------------
    # 3. TELEMETRY COLLECTION
    # ------------------------------------------------------------------------
    def get_telemetry(self) -> Dict:
        telemetry = {
            "active_connections": 0,
            "unknown_connection_count": 0,
            "process_count": 0,
            "new_process_count": 0,
            "file_change_count": 0,
            "cpu_percent": 0.0,
            "memory_percent": 0.0,
            "load_avg_1min": 0.0,
            "cpu_spike_detected": False,
            "memory_spike_detected": False,
            "sensor_healthy": True,
            "sensor_timestamp": time.time(),
            "method": self.method,
        }

        if self.method == "psutil":
            telemetry.update(self._collect_with_psutil())
        else:
            telemetry.update(self._collect_with_procfs())

        telemetry["file_change_count"] = self._check_file_changes()

        telemetry["cpu_spike_detected"] = (
            telemetry["cpu_percent"] > SensorConfig.CPU_SPIKE_THRESHOLD and
            telemetry["cpu_percent"] > self.baseline_cpu * SensorConfig.CPU_SPIKE_MULTIPLIER
        )
        telemetry["memory_spike_detected"] = (
            telemetry["memory_percent"] > SensorConfig.MEMORY_SPIKE_THRESHOLD and
            telemetry["memory_percent"] > self.baseline_memory * SensorConfig.MEMORY_SPIKE_MULTIPLIER
        )

        if self.baseline_cpu == 0:
            self.baseline_cpu = telemetry["cpu_percent"]
        else:
            self.baseline_cpu = self.baseline_cpu * 0.9 + telemetry["cpu_percent"] * 0.1

        if self.baseline_memory == 0:
            self.baseline_memory = telemetry["memory_percent"]
        else:
            self.baseline_memory = self.baseline_memory * 0.9 + telemetry["memory_percent"] * 0.1

        return telemetry

    # ------------------------------------------------------------------------
    # 4. PSUTIL COLLECTOR
    # ------------------------------------------------------------------------
    def _collect_with_psutil(self) -> Dict:
        try:
            import psutil
            result = {}

            connections = set()
            unknown = set()
            for conn in psutil.net_connections(kind="inet"):
                if conn.status in ["ESTABLISHED", "SYN_SENT"] and conn.raddr:
                    remote_ip, remote_port = conn.raddr
                    if remote_ip not in ("127.0.0.1", "0.0.0.0"):
                        conn_tuple = (remote_ip, remote_port, conn.status)
                        connections.add(conn_tuple)
                        if not self._is_known_connection(remote_ip, remote_port):
                            unknown.add(conn_tuple)

            result["active_connections"] = len(connections)
            result["unknown_connection_count"] = len(unknown)

            processes = set()
            for proc in psutil.process_iter(["name"]):
                try:
                    name = proc.info["name"]
                    if name:
                        processes.add(name.lower())
                except Exception:
                    pass
            result["process_count"] = len(processes)

            if self.last_processes:
                new_procs = processes - self.last_processes
                result["new_process_count"] = len(new_procs)
            else:
                result["new_process_count"] = 0
            self.last_processes = processes

            result["cpu_percent"] = psutil.cpu_percent(interval=0.5)
            result["memory_percent"] = psutil.virtual_memory().percent
            result["load_avg_1min"] = psutil.getloadavg()[0]

            return result
        except Exception as e:
            emit(SRC, LAYER, "error", f"psutil collection error: {e}",
                 capability="sensor")
            return self._collect_with_procfs()

    # ------------------------------------------------------------------------
    # 5. PROCFS COLLECTOR
    # ------------------------------------------------------------------------
    def _collect_with_procfs(self) -> Dict:
        result = {
            "active_connections": 0,
            "unknown_connection_count": 0,
            "process_count": 0,
            "new_process_count": 0,
            "cpu_percent": 0.0,
            "memory_percent": 0.0,
            "load_avg_1min": 0.0,
        }

        # Network
        try:
            connections = self._parse_proc_net_tcp("/proc/net/tcp")
            if os.path.exists("/proc/net/tcp6"):
                connections.extend(self._parse_proc_net_tcp("/proc/net/tcp6"))
            unknown = [c for c in connections if not self._is_known_connection(c[0], c[1])]
            result["active_connections"] = len(connections)
            result["unknown_connection_count"] = len(unknown)
        except Exception as e:
            emit(SRC, LAYER, "warn", f"/proc/net/tcp parsing failed: {e}",
                 capability="sensor")

        # Processes
        try:
            processes = set()
            for pid in os.listdir("/proc"):
                if pid.isdigit():
                    try:
                        with open(f"/proc/{pid}/comm", "r") as f:
                            name = f.read().strip().lower()
                            if name:
                                processes.add(name)
                    except Exception:
                        pass
            result["process_count"] = len(processes)
            if self.last_processes:
                new_procs = processes - self.last_processes
                result["new_process_count"] = len(new_procs)
            else:
                result["new_process_count"] = 0
            self.last_processes = processes
        except Exception as e:
            emit(SRC, LAYER, "warn", f"/proc process list failed: {e}",
                 capability="sensor")

        # Load average
        try:
            with open("/proc/loadavg", "r") as f:
                parts = f.read().split()
                result["load_avg_1min"] = float(parts[0])
        except Exception:
            pass

        # Memory
        try:
            with open("/proc/meminfo", "r") as f:
                mem_total = 0
                mem_available = 0
                for line in f:
                    if "MemTotal:" in line:
                        mem_total = float(line.split()[1])
                    elif "MemAvailable:" in line:
                        mem_available = float(line.split()[1])
                if mem_total > 0:
                    result["memory_percent"] = (1 - (mem_available / mem_total)) * 100
        except Exception:
            pass

        # CPU estimate
        if result["load_avg_1min"] > 0:
            result["cpu_percent"] = min(result["load_avg_1min"] * 50, 100)

        return result

    def _parse_proc_net_tcp(self, path: str) -> List[Tuple[str, int, str]]:
        connections = []
        state_map = {
            "01": "ESTABLISHED", "02": "SYN_SENT", "03": "SYN_RECV",
            "04": "FIN_WAIT1", "05": "FIN_WAIT2", "06": "TIME_WAIT",
            "07": "CLOSE", "08": "CLOSE_WAIT", "09": "LAST_ACK",
            "0A": "LISTEN", "0B": "CLOSING"
        }
        try:
            with open(path, "r") as f:
                lines = f.readlines()
            for line in lines[1:]:
                parts = line.split()
                if len(parts) < 10:
                    continue
                local_hex, local_port_hex = parts[1].split(":")
                rem_hex, rem_port_hex = parts[2].split(":")
                state_hex = parts[3]
                state = state_map.get(state_hex, "UNKNOWN")
                if state not in ["ESTABLISHED", "SYN_SENT", "SYN_RECV"]:
                    continue
                try:
                    rem_ip = socket.inet_ntoa(bytes.fromhex(f"{int(rem_hex,16):08x}")[::-1])
                    rem_port = int(rem_port_hex, 16)
                    connections.append((rem_ip, rem_port, state))
                except Exception:
                    pass
        except FileNotFoundError:
            emit(SRC, LAYER, "warn", f"{path} not found. Network connections will be 0.",
                 capability="sensor")
        except Exception as e:
            emit(SRC, LAYER, "warn", f"Error parsing {path}: {e}",
                 capability="sensor")
        return connections

    # ------------------------------------------------------------------------
    # 6. KNOWN CONNECTION CHECK
    # ------------------------------------------------------------------------
    def _is_known_connection(self, ip: str, port: int) -> bool:
        if ip.startswith(("192.168.", "10.", "172.")) or ip in ("127.0.0.1", "0.0.0.0"):
            return True
        try:
            with open(Config.WHITELIST_FILE, "r") as f:
                whitelist = json.load(f)
                for entry in whitelist:
                    if entry.get("ip") == ip and entry.get("expiry", 0) > time.time():
                        return True
        except FileNotFoundError:
            if not self._whitelist_warned:
                emit(SRC, LAYER, "warn", f"Whitelist file {Config.WHITELIST_FILE} not found. Skipping whitelist check.",
                     capability="sensor")
                self._whitelist_warned = True
        except Exception:
            pass
        if port in (53, 80, 443, 123, 22, 25, 110, 143, 993, 995):
            return True
        return False

    # ------------------------------------------------------------------------
    # 7. FILE CHANGE DETECTION
    # ------------------------------------------------------------------------
    def _check_file_changes(self) -> int:
        changes = 0
        for path, old_hash in list(self.file_hashes.items()):
            if not os.path.exists(path):
                changes += 1
                continue
            new_hash = self._hash_file(path)
            if new_hash and new_hash != old_hash:
                changes += 1
                self.file_hashes[path] = new_hash
        return changes

    # ------------------------------------------------------------------------
    # 8. PROPORTIONAL INTENSITY (M2)
    # ------------------------------------------------------------------------
    def _get_sleep_interval(self) -> float:
        try:
            with open(Config.BLACKBOARD_FILE, "r") as f:
                data = json.load(f)
                state = data.get("layer_3_state", {}).get("state", "GREEN")
        except Exception:
            state = "GREEN"

        if state == "RED":
            return SensorConfig.INTERVAL_RED + random.uniform(-0.3, 0.3)
        elif state == "ORANGE":
            return SensorConfig.INTERVAL_ORANGE + random.uniform(-0.5, 0.5)
        elif state == "YELLOW":
            return SensorConfig.INTERVAL_YELLOW + random.uniform(-1.0, 1.0)
        else:
            return SensorConfig.INTERVAL_GREEN + random.uniform(-2.0, 2.0)

    # ------------------------------------------------------------------------
    # 9. BLACKBOARD WRITER
    # ------------------------------------------------------------------------
    def _write_blackboard(self, telemetry: Dict):
        try:
            os.makedirs(os.path.dirname(Config.BLACKBOARD_FILE), exist_ok=True)
            with open(Config.BLACKBOARD_FILE, 'r+') as f:
                acquire_lock(f.fileno(), exclusive=True)
                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    data = {}

                if SensorConfig.BLACKBOARD_SECTION not in data:
                    data[SensorConfig.BLACKBOARD_SECTION] = {}

                for key, value in telemetry.items():
                    data[SensorConfig.BLACKBOARD_SECTION][key] = value

                data[SensorConfig.BLACKBOARD_SECTION]["source"] = "service_sensor"
                data[SensorConfig.BLACKBOARD_SECTION]["version"] = Config.SCHEMA_VERSION

                f.seek(0)
                json.dump(data, f, indent=2)
                f.truncate()
                release_lock(f.fileno())
        except Exception as e:
            emit(SRC, LAYER, "error", f"Blackboard write error: {e}",
                 capability="sensor")

    # ------------------------------------------------------------------------
    # 10. HEARTBEAT
    # ------------------------------------------------------------------------
    def _write_heartbeat(self):
        try:
            os.makedirs(os.path.dirname(SensorConfig.SENSOR_HEARTBEAT_FILE), exist_ok=True)
            with open(SensorConfig.SENSOR_HEARTBEAT_FILE, "w") as f:
                f.write(str(time.time()))
        except Exception as e:
            emit(SRC, LAYER, "warn", f"Heartbeat write error: {e}",
                 capability="sensor")

    # ------------------------------------------------------------------------
    # 11. AUDIT LOGGING & ROTATION
    # ------------------------------------------------------------------------
    def _log_cycle(self, telemetry: Dict):
        try:
            with open(Config.LOG_FILE, "a") as f:
                f.write(f"[SENSOR] {time.ctime()} | "
                        f"Conn: {telemetry['active_connections']} | "
                        f"Unknown: {telemetry['unknown_connection_count']} | "
                        f"Processes: {telemetry['process_count']} | "
                        f"New: {telemetry['new_process_count']} | "
                        f"Files changed: {telemetry['file_change_count']} | "
                        f"CPU: {telemetry['cpu_percent']:.1f}% | "
                        f"Mem: {telemetry['memory_percent']:.1f}%\n")
            self._rotate_log_if_needed()
        except Exception:
            pass

    def _rotate_log_if_needed(self):
        try:
            if os.path.exists(Config.LOG_FILE) and os.path.getsize(Config.LOG_FILE) > 5 * 1024 * 1024:
                timestamp = time.strftime("%Y-%m-%d_%H-%M-%S")
                backup_name = f"{Config.LOG_FILE}.{timestamp}"
                os.rename(Config.LOG_FILE, backup_name)

                log_dir = os.path.dirname(Config.LOG_FILE) or "."
                log_base = os.path.basename(Config.LOG_FILE)
                backups = sorted([
                    f for f in os.listdir(log_dir)
                    if f.startswith(log_base) and f != log_base
                ])
                while len(backups) > 5:
                    os.remove(os.path.join(log_dir, backups.pop(0)))
                emit(SRC, LAYER, "info", "Log rotated.",
                     capability="sensor")
        except Exception as e:
            emit(SRC, LAYER, "warn", f"Log rotation warning: {e}",
                 capability="sensor")

    # ------------------------------------------------------------------------
    # 12. MAIN LOOP
    # ------------------------------------------------------------------------
    def run(self):
        # Check if sensor is disabled at startup
        if _is_disabled(SRC, LAYER):
            emit(SRC, LAYER, "info", "Sensor is disabled. Exiting.",
                 capability="sensor")
            sys.exit(0)

        emit(SRC, LAYER, "info", "Starting sensor service...",
             capability="sensor")
        emit(SRC, LAYER, "info", f"Method: {self.method}",
             capability="sensor")
        emit(SRC, LAYER, "info",
             f"Intervals: GREEN={SensorConfig.INTERVAL_GREEN}s, "
             f"YELLOW={SensorConfig.INTERVAL_YELLOW}s, "
             f"ORANGE={SensorConfig.INTERVAL_ORANGE}s, "
             f"RED={SensorConfig.INTERVAL_RED}s",
             capability="sensor")

        retry_count = 0
        while retry_count < self.MAX_RETRIES:
            try:
                while self.running:
                    # Check again each cycle
                    if _is_disabled(SRC, LAYER):
                        emit(SRC, LAYER, "info", "Sensor disabled. Exiting.",
                             capability="sensor")
                        sys.exit(0)

                    self.cycle_count += 1
                    telemetry = self.get_telemetry()
                    self._write_blackboard(telemetry)
                    self._write_heartbeat()
                    self._log_cycle(telemetry)

                    interval = self._get_sleep_interval()

                    status = (f"Conn: {telemetry['active_connections']} | "
                              f"Unknown: {telemetry['unknown_connection_count']} | "
                              f"Procs: {telemetry['process_count']} | "
                              f"New: {telemetry['new_process_count']} | "
                              f"Changes: {telemetry['file_change_count']} | "
                              f"CPU: {telemetry['cpu_percent']:.1f}%")
                    if telemetry["cpu_spike_detected"]:
                        status += " CPU SPIKE"
                    if telemetry["memory_spike_detected"]:
                        status += " MEM SPIKE"

                    emit(SRC, LAYER, "info", f"Cycle {self.cycle_count} | {status}",
                         capability="sensor")

                    time.sleep(max(0.5, interval))

            except KeyboardInterrupt:
                emit(SRC, LAYER, "info", "Shutdown requested.",
                     capability="sensor")
                self.running = False
                return
            except Exception as e:
                emit(SRC, LAYER, "error", f"Loop error: {e}. Restarting...",
                     capability="sensor")
                retry_count += 1
                time.sleep(5)
                continue

            break

        emit(SRC, LAYER, "error", "Max retries reached. Exiting.",
             capability="sensor")


if __name__ == "__main__":
    service = SensorService()
    service.run()