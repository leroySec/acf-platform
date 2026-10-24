# service_state.py
# ============================================================================
# LAYER 3: DECISION ENGINE - UPDATED FOR BLACKBOARD SCHEMA v1.0
# ============================================================================
# PURPOSE: Assess risk, apply Hysteresis, manage Security State (GREEN/YELLOW/ORANGE/RED).
# PRINCIPLE FAMILY: Closed-Loop Adaptation
# PRINCIPLES: Feedback Control, State Transition, Graded Response
# OPERATIONAL RULES: D1 (Autonomous Decision-Making), D2 (State-Based Response),
#                    D3 (Resource-Aware Escalation), D4 (Hysteresis)
# REQUIREMENTS: R1, R2, R5
# ============================================================================
# TRACEABILITY:
# - D1: Operates without human intervention.
# - D2: State transitions based on risk thresholds.
# - D3: Escalation is proportional (no jumps from GREEN to RED).
# - D4: Hysteresis prevents oscillation (different thresholds for up/down).
# - R1: Fully autonomous decision-making.
# - R2: Hysteresis prevents resource-wasting oscillation.
# - R5: Rapid transitions enable immediate response.
# ============================================================================

import json
import time
import os
import random
import sys
import fcntl
from config import Config


class StateEngine:
    """
    Encapsulates the state transition logic.
    Strategy Pattern: The transition algorithm can be swapped at runtime.
    SRP: Only handles state transitions.
    """

    def __init__(self):
        self.current_state = "GREEN"
        self._validate_config()

    def _validate_config(self):
        """Prevent misconfigured hysteresis (e.g., thresholds crossing)."""
        if Config.GREEN_TO_YELLOW <= Config.YELLOW_TO_GREEN:
            print("[STATE] WARNING: Escalation threshold (GREEN→YELLOW) <= de-escalation threshold (YELLOW→GREEN)")
            print("[STATE] This may cause thrashing. Please adjust Config.")

    def compute_state(self, risk):
        """
        Apply Hysteresis logic (D4) from Chapter 4.
        Escalation: 65 (GREEN→YELLOW), 80 (YELLOW→ORANGE), 90 (ORANGE→RED)
        De-escalation: 40 (YELLOW→GREEN), 60 (ORANGE→YELLOW), 80 (RED→ORANGE)
        """
        if self.current_state == "GREEN" and risk > Config.GREEN_TO_YELLOW:
            return "YELLOW"
        elif self.current_state == "YELLOW" and risk > Config.YELLOW_TO_ORANGE:
            return "ORANGE"
        elif self.current_state == "ORANGE" and risk > Config.ORANGE_TO_RED:
            return "RED"
        elif self.current_state == "RED" and risk < Config.RED_TO_ORANGE:
            return "ORANGE"
        elif self.current_state == "ORANGE" and risk < Config.ORANGE_TO_YELLOW:
            return "YELLOW"
        elif self.current_state == "YELLOW" and risk < Config.YELLOW_TO_GREEN:
            return "GREEN"
        return self.current_state

    def recover_state(self):
        """Recover state from Blackboard on restart (State Persistence)."""
        try:
            with open(Config.BLACKBOARD_FILE, "r") as f:
                data = json.load(f)
            saved_state = data.get("layer_3_state", {}).get("state", "GREEN")
            if saved_state in ["GREEN", "YELLOW", "ORANGE", "RED"]:
                self.current_state = saved_state
                print(f"[STATE] Recovered state: {saved_state}")
                return True
        except:
            pass
        return False


class Blackboard:
    """
    Encapsulates all Blackboard operations.
    SRP: Only handles file I/O.
    Loose Coupling: Abstracts file operations; can be replaced with Redis later.
    """

    def __init__(self, filepath):
        self.filepath = filepath
        self.pid = os.getpid()

    def read_risk(self):
        """
        Read Risk Score from Blackboard (Schema v1.0).
        Fail-Secure: Unknown → 100 (RED).
        """
        try:
            with open(self.filepath, "r") as f:
                data = json.load(f)
            risk = data.get("layer_2_ais", {}).get("risk", 100)

            # Sanitize: Unknown (-1) or non-numeric → 100 (RED)
            if not isinstance(risk, (int, float)) or risk < 0:
                return 100
            if risk > 100:
                return 100
            return int(risk)

        except Exception:
            return 100  # Fail-Secure: missing Blackboard → RED

    def read_state(self):
        """Read the currently saved state from Blackboard (for recovery)."""
        try:
            with open(self.filepath, "r") as f:
                data = json.load(f)
            state = data.get("layer_3_state", {}).get("state", "GREEN")
            if state in ["GREEN", "YELLOW", "ORANGE", "RED"]:
                return state
            return None
        except:
            return None

    def write_state(self, state, risk, old_state):
        """
        Atomic write to the dedicated State section (Schema v1.0).
        """
        try:
            os.makedirs(os.path.dirname(self.filepath), exist_ok=True)

            with open(self.filepath, 'r+') as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)

                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    data = {}

                # Ensure the State section exists
                if "layer_3_state" not in data:
                    data["layer_3_state"] = {}

                data["layer_3_state"]["state"] = state
                data["layer_3_state"]["previous_state"] = old_state
                data["layer_3_state"]["risk"] = risk
                data["layer_3_state"]["state_timestamp"] = time.time()
                data["layer_3_state"]["source"] = "service_state"
                data["layer_3_state"]["version"] = Config.SCHEMA_VERSION

                f.seek(0)
                json.dump(data, f, indent=2)
                f.truncate()

                fcntl.flock(f.fileno(), fcntl.LOCK_UN)

            return True

        except FileNotFoundError:
            # Create file if it doesn't exist
            with open(self.filepath, 'w') as f:
                data = {
                    "layer_3_state": {
                        "state": state,
                        "previous_state": old_state,
                        "risk": risk,
                        "source": "service_state",
                        "version": Config.SCHEMA_VERSION
                    }
                }
                json.dump(data, f, indent=2)
            return True
        except Exception as e:
            print(f"[BLACKBOARD] Write error: {e}")
            return False


class AuditLogger:
    """
    Encapsulates all audit logging.
    SRP: Only handles logging.
    """

    def __init__(self, log_file):
        self.log_file = log_file

    def log(self, message, level="INFO"):
        try:
            with open(self.log_file, "a") as f:
                f.write(f"[{level}] [STATE] {time.ctime()} | {message}\n")
        except Exception as e:
            print(f"[AUDIT] Failed to write log: {e}", file=sys.stderr)

    def log_transition(self, old_state, new_state, risk):
        self.log(f"Transition: {old_state} → {new_state} (Risk: {risk})", level="TRANSITION")

    def log_error(self, error_message):
        self.log(error_message, level="ERROR")


class StateService:
    """
    Decision Engine Layer Service.
    SRP: Orchestrates the components; does not implement I/O, logic, or logging.
    """

    def __init__(self):
        self.blackboard = Blackboard(Config.BLACKBOARD_FILE)
        self.logger = AuditLogger(Config.LOG_FILE)
        self.engine = StateEngine()

        # Recover previous state on restart (State Persistence)
        if self.engine.recover_state():
            self.logger.log(f"Recovered state: {self.engine.current_state}")
        else:
            print("[STATE] No previous state found. Starting at GREEN.")

        self.running = True
        self.cycle_count = 0
        self.MAX_RETRIES = 5
        self.current_state = self.engine.current_state

    def run(self):
        """Main loop with self-recovery."""
        print("[STATE] Service started. Waiting for risk data...")
        print(f"[STATE] Starting state: {self.engine.current_state}")
        print("[STATE] Principles: Feedback Control, State Transition, Graded Response")
        print("[STATE] Rules: D1, D2, D3, D4 (Hysteresis)")
        self.logger.log("Service started")

        retry_count = 0
        while retry_count < self.MAX_RETRIES:
            try:
                print("[STATE] Main loop starting...")
                while self.running:
                    try:
                        self.cycle_count += 1

                        # Step 1: Read Risk from Blackboard (with sanitization)
                        risk = self.blackboard.read_risk()

                        # Step 2: Compute State (Hysteresis Logic)
                        old_state = self.engine.current_state
                        new_state = self.engine.compute_state(risk)

                        # Step 3: If state changed, log it
                        if new_state != old_state:
                            print(f"[STATE] ⚡ Transition: {old_state} → {new_state} (Risk: {risk})")
                            self.logger.log_transition(old_state, new_state, risk)

                        self.engine.current_state = new_state
                        self.current_state = new_state

                        # Step 4: Write State to Blackboard
                        success = self.blackboard.write_state(new_state, risk, old_state)
                        if not success:
                            self.logger.log_error("Failed to write state to Blackboard")

                        print(f"[STATE] Cycle {self.cycle_count} | Risk: {risk} | State: {new_state}")

                        # Jitter: Prevents thundering herd (R2)
                        jitter = random.uniform(-0.5, 0.5)
                        sleep_time = max(0.5, Config.LOOP_INTERVAL + jitter)
                        time.sleep(sleep_time)

                    except KeyboardInterrupt:
                        print("\n[STATE] Shutdown requested.")
                        self.logger.log("Shutdown requested")
                        self.running = False
                        return
                    except Exception as e:
                        print(f"[STATE] Loop error: {e}")
                        self.logger.log_error(f"Loop error: {e}")
                        time.sleep(5)
                break

            except Exception as fatal:
                retry_count += 1
                print(f"[STATE] FATAL CRASH ({retry_count}/{self.MAX_RETRIES}): {fatal}")
                self.logger.log_error(f"FATAL CRASH ({retry_count}/{self.MAX_RETRIES}): {fatal}")
                if retry_count >= self.MAX_RETRIES:
                    print("[STATE] Max retries reached. Exiting.")
                    self.logger.log_error("Max retries reached. Exiting.")
                    break
                time.sleep(30)


if __name__ == "__main__":
    service = StateService()
    service.run()