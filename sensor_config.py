# ============================================================================
# SENSOR CONFIGURATION EXTENSION
# ============================================================================
# PURPOSE: Extend the ACF platform to support the Sensor (Network/Process/File/Resource)
#          telemetry collection WITHOUT modifying the core config.py.
# 
# ARCHITECTURE PATTERNS:
# - Blackboard Pattern: Merges sensor schema into the shared /tmp/acf_state.json.
# - Strategy Pattern: Preconditions choose between psutil (C-optimized) and /proc fallback.
# - Template Method: SensorConfigEngine orchestrates schema merge → preconditions → write.
#
# DESIGN PRINCIPLES:
# - Open/Closed: config.py is open for extension, closed for modification (3-line hook).
# - Single Responsibility: Preconditions, Schema, and Engine are strictly separated.
# - Fail-Safe (vs Fail-Fast): Sensor failure logs a WARNING, does NOT crash the system.
#
# SECURITY ENGINEERING:
# - Least Privilege: Checks file readability (os.access) before attempting opens.
# - Atomic Writes: Uses fcntl.flock (exclusive lock) for all Blackboard updates.
# - Input Validation: Validates that /proc files exist and are readable before parsing.
#
# LINUX SYSTEM PRINCIPLES:
# - Everything is a File: Uses /proc/stat, /proc/net/tcp, /proc/meminfo, /proc/loadavg.
# - Permission Checks: Uses os.access(path, os.R_OK) before reading.
# - Standard Tool Detection: Uses shutil.which() to find netstat/ss as fallbacks.
# ============================================================================

import os
import sys
import json
import time
import shutil
from typing import Dict, Any

# Import the core configuration (reuse paths, version, etc.)
from config import Config

from platform_utils import acquire_lock, release_lock



# ============================================================================
# 1. SENSOR-SPECIFIC CONSTANTS (Extends Config)
# ============================================================================
class SensorConfig:
    """Sensor-specific constants. Extends the main Config class."""

    # --- M2: PROPORTIONAL INTENSITY (Resource Efficiency) ---
    # These are specific to the Sensor because scanning /proc/net and process lists
    # is heavier than reading a single auth.log.
    INTERVAL_GREEN = 30.0    # Seconds between scans (safe state)
    INTERVAL_YELLOW = 15.0   # Seconds between scans (suspicious)
    INTERVAL_ORANGE = 5.0    # Seconds between scans (high risk)
    INTERVAL_RED = 2.0       # Seconds between scans (critical)

    # --- ANOMALY DETECTION THRESHOLDS (Layer 2) ---
    CPU_SPIKE_THRESHOLD = 70.0      # Percent CPU usage
    CPU_SPIKE_MULTIPLIER = 1.5      # Above baseline * multiplier
    MEMORY_SPIKE_THRESHOLD = 80.0   # Percent Memory usage
    MEMORY_SPIKE_MULTIPLIER = 1.5

    # --- BLACKBOARD SECTION NAME ---
    BLACKBOARD_SECTION = "layer_1_sensor_ext"
    
    SENSOR_HEARTBEAT_FILE = os.path.join(Config.TEMP_DIR, "acf_sensor.heartbeat")

    APP_LOG_SECTION = "layer_1_app_monitor"

    APP_LOG_SECTION_PATHS = [
        "/var/log/apache2/",
        "/var/log/nginx/",
        "/var/log/postgresql/",
        "/var/log/",
    ]

    APP_LOG_FILE_PATTERNS = [
        "access.log", "error.log", "mail.log", 
        "mail.err", "mail.warn", "vsftpd.log",
        "auth.log", "syslog", "daemon.log"
    ]

    APP_FAILURE_PATTERNS = [
        r"(?i)failed",
        r"(?i)authentication failure",
        r"(?i)login failed",
        r"(?i)invalid password",
        r"(?i)401 unauthorized",
        r"(?i)403 forbidden",
        r"(?i)error"
    ]


# ============================================================================
# 2. BLACKBOARD SCHEMA EXTENSION (Merges into the existing board)
# ============================================================================
class SensorBlackboardSchema:
    """
    Defines the structure of the Sensor's data section.
    This will be merged into the existing Blackboard without overwriting other layers.
    """

    @staticmethod
    def get_initial_sensor_section() -> Dict[str, Any]:
        """
        Returns the default structure for layer_1_sensor_ext.
        All fields are pre-initialized to safe defaults.
        """
        return {
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
            "sensor_healthy": False,
            "sensor_timestamp": 0.0,
            "method": "pending",          # 'psutil' or 'procfs'
            "source": "service_sensor",
            "version": Config.SCHEMA_VERSION
        }

    @staticmethod
    def merge_sensor_schema():
        """
        Atomically merges the Sensor schema into the shared Blackboard.
        Uses fcntl.flock to prevent corruption if config.py and sensor_config.py
        run simultaneously.
        """
        if not os.path.exists(Config.BLACKBOARD_FILE):
            print("[SENSOR_CONFIG] Blackboard not found. Skipping schema merge.")
            return

        try:
            with open(Config.BLACKBOARD_FILE, 'r+') as f:
                # ACQUIRE EXCLUSIVE LOCK (Atomic Write)
                acquire_lock(f.fileno(), exclusive=True)

                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    data = {}

                # Check if the sensor section already exists
                if SensorConfig.BLACKBOARD_SECTION not in data:
                    print("[SENSOR_CONFIG] Adding sensor section to Blackboard schema.")
                    data[SensorConfig.BLACKBOARD_SECTION] = SensorBlackboardSchema.get_initial_sensor_section()

                    # Also ensure the preconditions for the sensor exist
                    if "preconditions" not in data:
                        data["preconditions"] = {}
                    if "layer_1_sensor" not in data["preconditions"]:
                        data["preconditions"]["layer_1_sensor"] = {
                            "status": "pending",
                            "method": None,
                            "details": {}
                        }

                    # Write back to the file
                    f.seek(0)
                    json.dump(data, f, indent=2)
                    f.truncate()
                    print("[SENSOR_CONFIG] ✅ Sensor schema merged successfully.")
                else:
                    print("[SENSOR_CONFIG] ℹ️ Sensor section already exists in Blackboard.")

                # RELEASE LOCK
                release_lock(f.fileno())

        except PermissionError:
            print(f"[SENSOR_CONFIG] ❌ Permission denied to write to {Config.BLACKBOARD_FILE}. Run with sudo.")
        except Exception as e:
            print(f"[SENSOR_CONFIG] ❌ Failed to merge schema: {e}")


# ============================================================================
# 3. SENSOR PRECONDITION CHECKS (Linux System Probes)
# ============================================================================
class SensorPreconditionChecks:
    """
    Probes the Linux system to determine how the Sensor can collect telemetry.
    Order of Preference:
    1. psutil (C-optimized, highest performance)
    2. /proc filesystem (native Linux, no dependencies)
    3. netstat/ss (heavy subprocess, last resort)
    """

    @staticmethod
    def check_sensor_capabilities() -> Dict[str, Any]:
        """
        Check if the system can provide telemetry for the Sensor.
        Returns a structured result for the Blackboard preconditions.
        """
        result = {
            "status": "unknown",
            "method": None,
            "details": {}
        }

        # ---------- CHECK 1: psutil (Preferred) ----------
        try:
            import psutil
            # Test if it can actually read network connections (requires /proc/net access)
            psutil.net_connections()
            result["status"] = "ready"
            result["method"] = "psutil"
            result["details"]["psutil_version"] = psutil.__version__
            print("2. [SENSOR_CONFIG] ✅ Sensor: psutil available and functional.")
            return result
        except ImportError:
            print("[SENSOR_CONFIG] ⚠️ Sensor: psutil not installed.")
        except Exception as e:
            print(f"[SENSOR_CONFIG] ⚠️ Sensor: psutil error ({e}). Falling back.")

        # ---------- CHECK 2: /proc Filesystem (Native Linux) ----------
        try:
            # Linux Kernel exposes runtime data via procfs.
            # We check for the critical files the Sensor needs.
            proc_files = ["/proc/stat", "/proc/net/tcp", "/proc/meminfo", "/proc/loadavg"]
            missing = [f for f in proc_files if not os.path.exists(f)]

            if missing:
                result["details"]["proc_missing"] = missing
                result["status"] = "unavailable"
                result["details"]["error"] = f"Missing /proc files: {missing}"
                print(f"[SENSOR_CONFIG] ❌ Sensor: /proc files missing: {missing}")
                return result

            # Check readability (Linux permissions principle)
            # os.R_OK checks if the current user has read permission.
            unreadable = [f for f in proc_files if not os.access(f, os.R_OK)]
            if unreadable:
                result["status"] = "unavailable"
                result["details"]["error"] = f"/proc files exist but are not readable: {unreadable}"
                print(f"[SENSOR_CONFIG] ❌ Sensor: /proc not readable (permission denied).")
                return result

            # Test reading /proc/stat (CPU stats)
            with open("/proc/stat", "r") as f:
                f.read(100)

            result["status"] = "ready"
            result["method"] = "procfs"
            result["details"]["proc_available"] = True
            print("[SENSOR_CONFIG] ✅ Sensor: /proc filesystem available (fallback).")
            return result

        except PermissionError:
            result["status"] = "unavailable"
            result["details"]["error"] = "/proc exists but is not readable (permission denied)."
            print("[SENSOR_CONFIG] ❌ Sensor: /proc permission denied.")
            return result
        except Exception as e:
            result["status"] = "unavailable"
            result["details"]["error"] = str(e)
            print(f"[SENSOR_CONFIG] ❌ Sensor: /proc check failed: {e}")
            return result

    @staticmethod
    def check_network_tools() -> Dict[str, Any]:
        """
        Optional fallback check for netstat or ss.
        This is only used if psutil AND /proc/net fails (highly unlikely on standard Linux).
        """
        result = {"status": "unknown", "method": None, "details": {}}

        # shutil.which() respects the system $PATH
        netstat_path = shutil.which("netstat")
        ss_path = shutil.which("ss")

        if netstat_path:
            result["status"] = "ready"
            result["method"] = "netstat"
            result["details"]["path"] = netstat_path
            print(f"[SENSOR_CONFIG] ✅ Sensor: netstat available at {netstat_path}.")
            return result

        if ss_path:
            result["status"] = "ready"
            result["method"] = "ss"
            result["details"]["path"] = ss_path
            print(f"[SENSOR_CONFIG] ✅ Sensor: ss available at {ss_path}.")
            return result

        result["status"] = "unavailable"
        result["details"]["error"] = "No network tools (netstat/ss) found in PATH."
        print("[SENSOR_CONFIG] ⚠️ Sensor: No network tools (netstat/ss).")
        return result


# ============================================================================
# 4. SENSOR CONFIG ENGINE (Orchestrator)
# ============================================================================
class SensorConfigEngine:
    """
    Orchestrates the Sensor configuration process.
    This is called by the original config.py via a 3-line hook.
    """

    @classmethod
    def initialize(cls):
        """
        Main entry point. Called by ConfigEngine.validate() in config.py.
        """
        print("\n[SENSOR_CONFIG] =========================================")
        print("[SENSOR_CONFIG] SENSOR CONFIGURATION EXTENSION")
        print("[SENSOR_CONFIG] =========================================")

        # Step 1: Merge the Sensor's data structure into the shared Blackboard
        SensorBlackboardSchema.merge_sensor_schema()

        # Step 2: Run the Linux system probes
        results = cls._run_preconditions()

        # Step 3: Write the probe results back to the Blackboard
        cls._write_preconditions(results)

        # Step 4: Report status to the admin (human-readable)
        cls._report_status(results)

        print("[SENSOR_CONFIG] Sensor configuration complete.\n")

    @classmethod
    def _run_preconditions(cls) -> Dict[str, Any]:
        """Run all precondition checks."""
        print("[SENSOR_CONFIG] Running Linux system telemetry probes...")
        return {
            "sensor": SensorPreconditionChecks.check_sensor_capabilities(),
            "network_tools": SensorPreconditionChecks.check_network_tools()
        }

    @classmethod
    def _write_preconditions(cls, results: Dict[str, Any]):
        """
        Atomically write sensor preconditions to the Blackboard.
        Uses the SAME file lock as the original config.
        """
        try:
            with open(Config.BLACKBOARD_FILE, 'r+') as f:
                # ACQUIRE EXCLUSIVE LOCK
                acquire_lock(f.fileno(), exclusive=True)

                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    data = {}

                # Ensure the preconditions section exists
                if "preconditions" not in data:
                    data["preconditions"] = {}

                # Write sensor-specific preconditions
                data["preconditions"]["layer_1_sensor"] = {
                    "status": results["sensor"]["status"],
                    "method": results["sensor"]["method"],
                    "details": {
                        "sensor": results["sensor"]["details"],
                        "network_tools": results["network_tools"]["details"]
                    },
                    "timestamp": time.time()
                }

                # Write back
                f.seek(0)
                json.dump(data, f, indent=2)
                f.truncate()

                # RELEASE LOCK
                release_lock(f.fileno())

        except Exception as e:
            print(f"[SENSOR_CONFIG] Failed to write preconditions: {e}")

    @classmethod
    def _report_status(cls, results: Dict[str, Any]):
        """Human-readable report of the sensor's readiness."""
        sensor_status = results["sensor"]["status"]
        sensor_method = results["sensor"]["method"]

        if sensor_status == "ready":
            print(f"[SENSOR_CONFIG] ✅ Sensor is ready. Method: {sensor_method}")
        else:
            print(f"[SENSOR_CONFIG] ⚠️ Sensor is NOT ready. Status: {sensor_status}")

        # Warn if network tools are missing (only if procfs also failed)
        if results["network_tools"]["status"] != "ready":
            print("[SENSOR_CONFIG] ⚠️ Network tools (netstat/ss) missing. Sensor may be limited.")


# ============================================================================
# 5. ENTRY POINT (Standalone testing)
# ============================================================================
if __name__ == "__main__":
    # This allows you to run `python3 sensor_config.py` to test the extension
    # independently, without needing to run the full config.py.
    SensorConfigEngine.initialize()