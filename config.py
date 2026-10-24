# config.py
# ============================================================================
# ACF PLATFORM CONFIGURATION & BLACKBOARD SCHEMA
# ============================================================================
# Single source of truth for constants, Blackboard schema, and preconditions.
# ============================================================================

import os
import sys
import json
import time
import socket
import subprocess
from typing import Dict, Any, List, Optional
from platform_utils import get_temp_dir, acquire_lock, release_lock


class Config:
    # --- HYSTERESIS THRESHOLDS (Layer 3) ---
    GREEN_TO_YELLOW = 65
    YELLOW_TO_ORANGE = 80
    ORANGE_TO_RED = 90
    RED_TO_ORANGE = 80
    ORANGE_TO_YELLOW = 60
    YELLOW_TO_GREEN = 40

    # --- SAFETY MECHANISMS (Layer 4a) ---
    RED_TIMEOUT_SECONDS = 60

    # --- AIS CONFIGURATION (Layer 2) ---
    BASELINE_WINDOW = 10
    RISK_MULTIPLIER = 25
    ANOMALY_MULTIPLIER = 3.0

    # --- LOOP & TIMING (All Layers) ---
    LOOP_INTERVAL = 5

    # --- SECURITY (Layer 5 & Future) ---
    HMAC_SECRET = os.environ.get("ACF_SECRET")
    DASHBOARD_SECRET = os.environ.get("DASHBOARD_SECRET")
    DASHBOARD_HOST = "127.0.0.1"
    DASHBOARD_PORT = 8080

    # --- FILE PATHS ---
    TEMP_DIR = get_temp_dir()
    BLACKBOARD_FILE = os.path.join(TEMP_DIR, "acf_state.json")
    WHITELIST_FILE = os.path.join(TEMP_DIR, "acf_whitelist.json")
    HEARTBEAT_FILE = os.path.join(TEMP_DIR, "acf_monitor.heartbeat")
    LAYER_STATE_FILE = os.path.join(TEMP_DIR, "acf_layer_state.json")
    LAYER_COMMAND_FILE = os.path.join(TEMP_DIR, "acf_layer_command.json")
    LAYER_RESULT_FILE = os.path.join(TEMP_DIR, "acf_layer_result.json")
    EVENT_ROUTER_HOST = "127.0.0.1"
    EVENT_ROUTER_PORT = 8765
    EVENT_ROUTER_PORT_FILE = os.path.join(TEMP_DIR, "acf_event_router.port")
    LOG_FILE = "acf.log"

    USERS_FILE = "users.json"
    SYSTEM_CONFIG_FILE = "system_config.json"

    # --- LAYER 4a (Response) ---
    IPTABLES_CHAIN = "INPUT"
    FALLBACK_HOSTS_DENY = "/etc/hosts.deny"

    # --- LAYER 4c (MTD) ---
    SSH_CONFIG_PATH = "/etc/ssh/sshd_config"
    SSH_SERVICE_NAME = "ssh"

    # --- OPTIONAL LAYERS ---
    ENABLE_RECONFIG = False
    PANIC_TIMEOUT_SECONDS = 300

    SERVICE_MAP = {
        "ssh":     ["layer1", "layer2", "layer3", "layer4a", "layer4c", "layer5"],
        "sensor":  ["layer1", "layer2", "layer3", "layer4a", "layer4c", "layer5"],
    }

    ENGINE_MAP = {
        "layer1":  "monitor/monitor_engine.py",
        "layer2":  "ais/ais_engine.py",
        "layer3":  "state/state_engine.py",
        "layer4a": "response/response_engine.py",
        "layer4c": "mtd/mtd_engine.py",
        "layer5":  "feedback/feedback_engine.py",   # --- FEEDBACK ---
        "reader":  "monitor/reader.py",
    }

    # --- SUPERVISION POLICY ---
    # Units that must never be auto-disabled by layer_manager.
    NEVER_DISABLE = {"reader"}

    # Per-unit heartbeat timeouts (seconds).
    HEARTBEAT_TIMEOUTS = {
        "default": 30,
        "reader":  50,
        "layer5":  30,   # --- FEEDBACK ---
    }

    # --- RISK INPUTS (Layer 2, per Chapter 4.3.3) ---
    # Asset criticality per capability. A value in [0.0, 1.0] where
    # 0.5 is neutral. Applied as a linear factor:
    #   criticality_factor = 0.5 + criticality
    CAPABILITY_CRITICALITY = {
        "ssh":       0.8,
        "sensor":    0.6,
        "app_http":  0.6,
        "app_mysql": 0.9,
        "app_smtp":  0.5,
        "app_ftp":   0.4,
    }
    DEFAULT_CAPABILITY_CRITICALITY = 0.5

    # Resource-state amplification.
    #   resource_factor = 1.0 + RESOURCE_STRESS_AMPLIFIER * stress
    RESOURCE_STRESS_AMPLIFIER = 0.5

    # --- YELLOW POSTURE (Layer 2 sensitivity) ---
    YELLOW_SENSITIVITY_MULTIPLIER = 1.5

    # --- STATE DE-ESCALATION HOLDS (Layer 3) ---
    YELLOW_DE_ESCALATION_CYCLES = 2
    ORANGE_DE_ESCALATION_CYCLES = 2
    RED_DE_ESCALATION_CYCLES = 3

    # --- FEEDBACK (Layer 5) ---
    # Evaluation window: how many cycles feedback waits before judging
    # an action.
    FEEDBACK_EVAL_CYCLES = 30

    # History ring buffer size per capability (short-term, in Blackboard).
    FEEDBACK_HISTORY_MAX = 500

    # Medium-term aggregates file (daily pruned).
    FEEDBACK_AGGREGATES_FILE = os.path.join(
        get_temp_dir(), "acf_feedback_history.json"
    )

    # Bounded auto-adjustment (Stage 2 Supervised Auto).
    FEEDBACK_AUTO_SENSITIVITY_MIN = 1.0
    FEEDBACK_AUTO_SENSITIVITY_MAX = 2.0
    FEEDBACK_AUTO_SENSITIVITY_DELTA = 0.1

    FEEDBACK_AUTO_DETECTOR_WEIGHT_MIN = 0.5
    FEEDBACK_AUTO_DETECTOR_WEIGHT_MAX = 2.0
    FEEDBACK_AUTO_DETECTOR_WEIGHT_DELTA = 0.1

    # False-positive detection.
    FEEDBACK_FP_WINDOW_CYCLES = 100
    FEEDBACK_FP_CONFIDENCE_FLOOR = 20
    FEEDBACK_FP_REPEAT_THRESHOLD = 10

    # Recommendation bounds (recommend-only).
    FEEDBACK_RECOMMEND_THRESHOLD_MIN_DELTA = -10
    FEEDBACK_RECOMMEND_THRESHOLD_MAX_DELTA = 10

    # Section names.
    FEEDBACK_SECTION_PREFIX = "layer_5_feedback"
    FEEDBACK_GLOBAL_SECTION = "layer_5_feedback"

    FAIL2BAN_MAXRETRY = 5
    FAIL2BAN_FINDTIME = 600
    FAIL2BAN_BANTIME  = 3600
    FAIL2BAN_CONFIDENCE_THRESHOLD = 50
    FAIL2BAN_IGNOREIP = []

    FAIL2BAN_MIN_HITS = FAIL2BAN_MAXRETRY
    FAIL2BAN_BLOCK_DURATION = FAIL2BAN_BANTIME   

    SHUFFLE_ENABLED_DEFAULT = False
    SHUFFLE_TRIGGER_DISTINCT_ATTACKERS = 3
    SHUFFLE_TRIGGER_RED_SECONDS = 300
    SHUFFLE_RESTORE_AFTER_SECONDS = 1800 

    # ============================================================
    # BLACKBOARD SCHEMA VERSION
    # ============================================================
    SCHEMA_VERSION = "1.0"


# ============================================================================
# BLACKBOARD SCHEMA
# ============================================================================

class BlackboardSchema:

    @staticmethod
    def get_initial_blackboard() -> Dict[str, Any]:
        return {
            "version": Config.SCHEMA_VERSION,
            "timestamp": time.time(),
            # --- FEEDBACK: Layer 5 global aggregate section ---
            "layer_5_feedback": {
                "history": [],
                "history_max": Config.FEEDBACK_HISTORY_MAX,
                "aggregates": {
                    "risk_reduction_avg": 0.0,
                    "false_positive_rate": 0.0,
                    "response_time_avg": 0.0,
                    "capabilities_tracked": 0,
                    "mtd_switches": 0,
                },
                "ts": 0.0,
                "version": Config.SCHEMA_VERSION,
            },
            "orchestrator": {
                "start_time": 0.0,
                "health_checks": 0,
                "restarts": 0,
                "services_running": [],
                "source": "orchestrator",
                "version": Config.SCHEMA_VERSION,
            },
            "preconditions": {
                "layer_1":  {"status": "pending", "method": None, "details": {}},
                "layer_2":  {"status": "pending", "method": None, "details": {}},
                "layer_3":  {"status": "pending", "method": None, "details": {}},
                "layer_4a": {"status": "pending", "method": None, "details": {}},
                "layer_4c": {"status": "pending", "method": None, "details": {}},
                "layer_5":  {"status": "pending", "method": None, "details": {}},
            },
        }

    @staticmethod
    def initialize_blackboard():
        if os.path.exists(Config.BLACKBOARD_FILE):
            return
        print("[CONFIG] Initializing Blackboard with schema...")
        try:
            os.makedirs(os.path.dirname(Config.BLACKBOARD_FILE), exist_ok=True)
            initial_data = BlackboardSchema.get_initial_blackboard()
            with open(Config.BLACKBOARD_FILE, "w") as f:
                json.dump(initial_data, f, indent=2)
            print("[CONFIG] Blackboard initialized successfully.")
        except Exception as e:
            print(f"[CONFIG] CRITICAL: Failed to initialize Blackboard: {e}")
            sys.exit(1)


# ============================================================================
# PRECONDITION CHECKS
# ============================================================================

class PreconditionChecks:

    @staticmethod
    def check_layer_1() -> Dict[str, Any]:
        result = {"status": "unknown", "method": None, "details": {}}
        try:
            if os.path.exists("/var/log/auth.log"):
                subprocess.run(
                    ["sudo", "tail", "-n", "1", "/var/log/auth.log"],
                    capture_output=True, timeout=2.0, check=False,
                )
                result["status"] = "ready"
                result["method"] = "rsyslog"
                result["details"]["path"] = "/var/log/auth.log"
                print("[CONFIG] OK Layer 1: rsyslog available.")
                return result
        except Exception:
            pass
        try:
            check = subprocess.run(
                ["sudo", "journalctl", "-u", "ssh", "--no-pager", "-n", "1"],
                capture_output=True, timeout=2.0, check=False,
            )
            if check.returncode == 0:
                result["status"] = "ready"
                result["method"] = "journalctl"
                result["details"]["command"] = "journalctl -u ssh"
                print("[CONFIG] OK Layer 1: journalctl available.")
                return result
        except Exception:
            pass
        result["status"] = "unavailable"
        result["details"]["error"] = "No authentication log source found."
        print("[CONFIG] FAIL Layer 1: No log source available.")
        return result

    @staticmethod
    def check_layer_2() -> Dict[str, Any]:
        result = {"status": "unknown", "method": None, "details": {}}
        try:
            with open(Config.BLACKBOARD_FILE, "r") as f:
                data = json.load(f)
            if "last_failures" in data.get("layer_1_monitor", {}):
                result["status"] = "ready"
                result["details"]["last_failures"] = data["layer_1_monitor"]["last_failures"]
                print("[CONFIG] OK Layer 2: Monitor data available.")
                return result
        except Exception:
            pass
        result["status"] = "pending"
        result["details"]["info"] = "Waiting for monitor data."
        print("[CONFIG] PENDING Layer 2: Waiting for monitor data.")
        return result

    @staticmethod
    def check_layer_3() -> Dict[str, Any]:
        result = {"status": "unknown", "method": None, "details": {}}
        try:
            with open(Config.BLACKBOARD_FILE, "r") as f:
                data = json.load(f)
            if "risk" in data.get("layer_2_ais", {}):
                result["status"] = "ready"
                result["details"]["risk"] = data["layer_2_ais"]["risk"]
                print("[CONFIG] OK Layer 3: Risk data available.")
                return result
        except Exception:
            pass
        result["status"] = "pending"
        result["details"]["info"] = "Waiting for risk data."
        print("[CONFIG] PENDING Layer 3: Waiting for risk data.")
        return result

    @staticmethod
    def check_layer_4a() -> Dict[str, Any]:
        result = {"status": "unknown", "method": None, "details": {}}
        try:
            subprocess.run(
                ["sudo", "iptables", "--version"],
                capture_output=True, timeout=2.0, check=True,
            )
            result["status"] = "ready"
            result["method"] = "iptables"
            result["details"]["tool"] = "iptables"
            print("[CONFIG] OK Layer 4a: iptables available.")
            return result
        except Exception:
            pass
        try:
            subprocess.run(
                ["sudo", "ip6tables", "--version"],
                capture_output=True, timeout=2.0, check=True,
            )
            result["status"] = "ready"
            result["method"] = "ip6tables"
            result["details"]["tool"] = "ip6tables"
            print("[CONFIG] OK Layer 4a: ip6tables available.")
            return result
        except Exception:
            pass
        try:
            if os.path.exists(Config.FALLBACK_HOSTS_DENY):
                result["status"] = "ready"
                result["method"] = "hosts.deny"
                result["details"]["file"] = Config.FALLBACK_HOSTS_DENY
                print("[CONFIG] OK Layer 4a: hosts.deny available.")
                return result
        except Exception:
            pass
        result["status"] = "unavailable"
        result["details"]["error"] = "No blocking mechanism available."
        print("[CONFIG] FAIL Layer 4a: No blocking mechanism available.")
        return result

    @staticmethod
    def check_layer_4c() -> Dict[str, Any]:
        result = {"status": "unknown", "method": None, "details": {}}
        if not os.path.exists(Config.SSH_CONFIG_PATH):
            result["status"] = "unavailable"
            result["details"]["error"] = f"SSH config not found at {Config.SSH_CONFIG_PATH}"
            print(f"[CONFIG] FAIL Layer 4c: {Config.SSH_CONFIG_PATH} not found.")
            return result
        result["details"]["config_path"] = Config.SSH_CONFIG_PATH
        try:
            service_check = subprocess.run(
                ["sudo", "systemctl", "status", Config.SSH_SERVICE_NAME],
                capture_output=True, timeout=2.0, check=False,
            )
            if "Active: active" in service_check.stdout:
                result["details"]["service_status"] = "running"
                print("[CONFIG] OK Layer 4c: SSH service is running.")
            else:
                result["details"]["service_status"] = "not running"
                print("[CONFIG] PENDING Layer 4c: SSH service not running, but config exists.")
        except Exception:
            result["details"]["service_status"] = "unknown"
            print("[CONFIG] WARN Layer 4c: Cannot check SSH service.")
        try:
            import re
            with open(Config.SSH_CONFIG_PATH, "r") as f:
                for line in f:
                    match = re.match(r'^#?\s*Port\s+(\d+)', line)
                    if match:
                        result["details"]["current_port"] = int(match.group(1))
                        break
            if "current_port" not in result["details"]:
                result["details"]["current_port"] = 22
                print("[CONFIG] WARN Layer 4c: No Port found, defaulting to 22.")
        except Exception:
            result["details"]["current_port"] = 22
        result["status"] = "ready"
        print(f"[CONFIG] OK Layer 4c: SSH port {result['details']['current_port']} detected.")
        return result

    @staticmethod
    def check_layer_5() -> Dict[str, Any]:
        """
        Layer 5 = Feedback (Research Doc Ch 4.3.7).
        Checks that the temp directory is writable and the Blackboard
        exists. No Flask dependency; no Dashboard secret requirement.
        """
        result = {"status": "unknown", "method": None, "details": {}}

        try:
            os.makedirs(Config.TEMP_DIR, exist_ok=True)
            probe = os.path.join(Config.TEMP_DIR, ".acf_feedback_probe")
            with open(probe, "w") as f:
                f.write("ok")
            os.remove(probe)
            result["details"]["temp_writable"] = True
        except Exception as e:
            result["status"] = "unavailable"
            result["details"]["error"] = f"Temp not writable: {e}"
            print(f"[CONFIG] FAIL Layer 5: temp dir not writable: {e}")
            return result

        if not os.path.exists(Config.BLACKBOARD_FILE):
            result["status"] = "pending"
            result["details"]["info"] = "Blackboard not yet created."
            print("[CONFIG] PENDING Layer 5: waiting for Blackboard.")
            return result

        result["status"] = "ready"
        result["method"] = "blackboard"
        result["details"]["aggregates_file"] = Config.FEEDBACK_AGGREGATES_FILE
        print("[CONFIG] OK Layer 5: Feedback ready.")
        return result


# ============================================================================
# MAIN CONFIG ENGINE
# ============================================================================

class ConfigEngine:

    @classmethod
    def initialize(cls):
        BlackboardSchema.initialize_blackboard()
        cls.run_preconditions()

    @classmethod
    def run_preconditions(cls) -> Dict[str, Any]:
        print("\n[CONFIG] Running precondition checks...")
        results = {
            "layer_1":  PreconditionChecks.check_layer_1(),
            "layer_2":  PreconditionChecks.check_layer_2(),
            "layer_3":  PreconditionChecks.check_layer_3(),
            "layer_4a": PreconditionChecks.check_layer_4a(),
            "layer_4c": PreconditionChecks.check_layer_4c(),
            "layer_5":  PreconditionChecks.check_layer_5(),
        }
        try:
            with open(Config.BLACKBOARD_FILE, "r+") as f:
                acquire_lock(f.fileno(), exclusive=True)
                try:
                    data = json.load(f)
                except Exception:
                    data = BlackboardSchema.get_initial_blackboard()
                data["preconditions"] = results
                data["timestamp"] = time.time()
                f.seek(0)
                json.dump(data, f, indent=2)
                f.truncate()
                release_lock(f.fileno())
        except Exception as e:
            print(f"[CONFIG] Failed to write preconditions to Blackboard: {e}")
        print("[CONFIG] Precondition checks complete.\n")
        return results

    @classmethod
    def validate(cls):
        print("\n[CONFIG] =========================================")
        print("[CONFIG] ACF SYSTEM VALIDATION")
        print("[CONFIG] =========================================")
        cls.initialize()
        results = cls.run_preconditions()

        errors = []
        warnings = []

        if results["layer_1"]["status"] == "unavailable":
            errors.append("Layer 1 (Monitor): No log source available.")
        if results["layer_4a"]["status"] == "unavailable":
            errors.append("Layer 4a (Response): No blocking mechanism available.")
        if results["layer_4c"]["status"] == "unavailable":
            errors.append("Layer 4c (MTD): SSH config not found.")
        if results["layer_5"]["status"] == "unavailable":
            errors.append("Layer 5 (Feedback): not ready.")

        if results["layer_1"]["status"] == "pending":
            warnings.append("Layer 1 (Monitor): Awaiting log source.")
        if results["layer_2"]["status"] == "pending":
            warnings.append("Layer 2 (AIS): Awaiting monitor data.")
        if results["layer_3"]["status"] == "pending":
            warnings.append("Layer 3 (State): Awaiting risk data.")
        if results["layer_4c"].get("details", {}).get("service_status") == "not running":
            warnings.append("Layer 4c (MTD): SSH service is not running.")
        if results["layer_5"]["status"] == "pending":
            warnings.append("Layer 5 (Feedback): awaiting Blackboard.")

        if errors:
            print("\n[CONFIG] CRITICAL ERRORS (System cannot start):")
            for e in errors:
                print(f"  - {e}")
            print("\n[CONFIG] System validation failed. Exiting.")
            sys.exit(1)

        if warnings:
            print("\n[CONFIG] WARNINGS (System will start but may be degraded):")
            for w in warnings:
                print(f"  - {w}")

        try:
            from sensor_config import SensorConfigEngine
            print("\n[CONFIG] Loading Sensor Configuration Extension...")
            SensorConfigEngine.initialize()
        except ImportError:
            print("[CONFIG] Sensor configuration not found. Skipping.")
        except Exception as e:
            print(f"[CONFIG] Sensor config error (non-critical): {e}")

        print("\n[CONFIG] All critical validations passed. System is ready.")
        return True


if __name__ == "__main__":
    ConfigEngine.validate()