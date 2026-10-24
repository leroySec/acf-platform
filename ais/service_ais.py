# service_ais.py
# ============================================================================
# LAYER 2: THREAT ANALYSIS (AIS) - UPDATED FOR BLACKBOARD SCHEMA v1.0
# ============================================================================
# PURPOSE: Detect anomalies and calculate Risk Score (0–100).
# PRINCIPLE FAMILY: Immune-Inspired Detection
# PRINCIPLES: Self/Nonself Discrimination, Negative Selection, Clonal Selection,
#             Immune Memory
# OPERATIONAL RULES: T1 (Self/Nonself), T2 (Adaptive Detection), T3 (Threat Memory)
# REQUIREMENTS: R4 (Adaptive Self-Management), R5 (Rapid Protection)
# ============================================================================
# TRACEABILITY:
# - T1: Compares failures to baseline (Self/Nonself).
# - T2: Baseline updates over time (Clonal Selection - simplified).
# - T3: Retains attacker IP and logs it.
# - R4: Adapts baseline without human input.
# - R5: Calculates risk every cycle (rapid).
# ============================================================================

import json
import time
import os
import random
import sys
import fcntl
from collections import deque
from config import Config


class AISService:
    def __init__(self):
        self.failure_history = deque(maxlen=Config.BASELINE_WINDOW)
        self.baseline = 1.0
        self.risk = 0
        self.last_attacker_ip = "0.0.0.0"
        self.running = True
        self.cycle_count = 0
        self.MAX_RETRIES = 5
        self.risk_multiplier = getattr(Config, 'RISK_MULTIPLIER', 25)

        self._validate_blackboard_section()

    def _validate_blackboard_section(self):
        """Ensure the Blackboard has the required section for reading."""
        try:
            with open(Config.BLACKBOARD_FILE, "r") as f:
                data = json.load(f)
            # Ensure layer_2_ais exists
            if "layer_2_ais" not in data:
                data["layer_2_ais"] = {
                    "risk": 0,
                    "attacker_ip": "0.0.0.0",
                    "ais_healthy": False,
                    "source": "service_ais",
                    "version": Config.SCHEMA_VERSION
                }
                with open(Config.BLACKBOARD_FILE, "w") as f:
                    json.dump(data, f, indent=2)
        except:
            # File may not exist; will be created on first write
            pass

    def is_whitelisted(self, ip):
        """Check if IP is whitelisted (F1: Continuous Learning)."""
        if ip == "0.0.0.0":
            return False
        try:
            with open(Config.WHITELIST_FILE, "r") as f:
                whitelist = json.load(f)
            for entry in whitelist:
                if entry["ip"] == ip and entry["expiry"] > time.time():
                    return True
        except:
            pass
        return False

    def read_monitor_data(self):
        """Read telemetry from the Monitor section of the Blackboard (Schema v1.0)."""
        try:
            with open(Config.BLACKBOARD_FILE, "r") as f:
                data = json.load(f)

            monitor = data.get("layer_1_monitor", {})
            failures = monitor.get("last_failures", -1)
            attacker_ip = monitor.get("last_attacker_ip", "0.0.0.0")
            monitor_healthy = monitor.get("monitor_healthy", False)

            return failures, attacker_ip, monitor_healthy
        except Exception as e:
            print(f"[AIS] Error reading Blackboard: {e}")
            return -1, "0.0.0.0", False

    def calculate_risk(self, failures, attacker_ip, monitor_healthy):
        """Calculate risk with whitelist check."""
        # FIX: Whitelist check (closes the feedback loop)
        if self.is_whitelisted(attacker_ip):
            print(f"[AIS] IP {attacker_ip} is whitelisted. Ignoring.")
            return 0

        # Fail-Secure: If Monitor is unhealthy, force RED
        if not monitor_healthy or failures == -1:
            self.risk = 100
            return 100

        # Update historical baseline (Clonal Selection - simplified)
        self.failure_history.append(failures)
        if len(self.failure_history) > 0:
            self.baseline = sum(self.failure_history) / len(self.failure_history)

        # Prevent division by zero
        if self.baseline == 0:
            self.baseline = 0.1

        # Calculate anomaly ratio
        anomaly_ratio = failures / self.baseline

        # Risk proportional to how far above baseline we are
        raw_risk = min(anomaly_ratio * self.risk_multiplier, 100)

        # If failures are extremely high, force RED
        if failures > 20:
            raw_risk = min(raw_risk + 30, 100)

        self.risk = int(raw_risk)
        return self.risk

    def write_blackboard(self, risk, attacker_ip, healthy=True):
        """Atomic write to the dedicated AIS section (Schema v1.0)."""
        try:
            os.makedirs(os.path.dirname(Config.BLACKBOARD_FILE), exist_ok=True)

            with open(Config.BLACKBOARD_FILE, 'r+') as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)

                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    data = {}

                # Ensure the AIS section exists
                if "layer_2_ais" not in data:
                    data["layer_2_ais"] = {}

                data["layer_2_ais"]["risk"] = risk
                data["layer_2_ais"]["attacker_ip"] = attacker_ip
                data["layer_2_ais"]["ais_timestamp"] = time.time()
                data["layer_2_ais"]["ais_healthy"] = healthy
                data["layer_2_ais"]["baseline"] = self.baseline
                # Store failure history (for diagnostics)
                data["layer_2_ais"]["failure_history"] = list(self.failure_history)
                data["layer_2_ais"]["source"] = "service_ais"
                data["layer_2_ais"]["version"] = Config.SCHEMA_VERSION

                f.seek(0)
                json.dump(data, f, indent=2)
                f.truncate()

                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

            # Audit Logging (Command Pattern)
            with open(Config.LOG_FILE, "a") as f:
                f.write(f"[AIS] {time.ctime()} | Risk: {risk} | Attacker: {attacker_ip}\n")

        except FileNotFoundError:
            # Create file if it doesn't exist
            with open(Config.BLACKBOARD_FILE, 'w') as f:
                data = {
                    "layer_2_ais": {
                        "risk": risk,
                        "attacker_ip": attacker_ip,
                        "ais_healthy": healthy,
                        "source": "service_ais",
                        "version": Config.SCHEMA_VERSION
                    }
                }
                json.dump(data, f, indent=2)
        except Exception as e:
            print(f"[AIS] Error writing to Blackboard: {e}")

    def run(self):
        """Main loop with self-recovery and jitter."""
        print("[AIS] Service started. Waiting for monitor data...")

        retry_count = 0
        while retry_count < self.MAX_RETRIES:
            try:
                print("[AIS] Main loop starting...")
                while self.running:
                    try:
                        self.cycle_count += 1

                        failures, attacker_ip, monitor_healthy = self.read_monitor_data()
                        risk = self.calculate_risk(failures, attacker_ip, monitor_healthy)
                        self.write_blackboard(risk, attacker_ip, monitor_healthy)

                        if monitor_healthy:
                            status = f"Failures: {failures} | Risk: {risk} | Baseline: {self.baseline:.2f}"
                        else:
                            status = "⚠️ Monitor UNHEALTHY → Risk: 100 (RED)"

                        print(f"[AIS] Cycle {self.cycle_count} | {status} | Attacker: {attacker_ip}")

                        jitter = random.uniform(-0.5, 0.5)
                        sleep_time = max(0.5, Config.LOOP_INTERVAL + jitter)
                        time.sleep(sleep_time)

                    except KeyboardInterrupt:
                        print("\n[AIS] Shutdown requested.")
                        self.running = False
                        return
                    except Exception as e:
                        print(f"[AIS] Loop error: {e}. Restarting...")
                        time.sleep(5)
                break

            except Exception as fatal:
                retry_count += 1
                print(f"[AIS] FATAL CRASH ({retry_count}/{self.MAX_RETRIES}): {fatal}")
                if retry_count >= self.MAX_RETRIES:
                    print("[AIS] Max retries reached. Exiting.")
                    break
                time.sleep(30)


if __name__ == "__main__":
    service = AISService()
    service.run()