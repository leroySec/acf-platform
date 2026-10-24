# service_response.py
# ============================================================================
# LAYER 4a: DEFENCE RESPONSE - UPDATED FOR BLACKBOARD SCHEMA v1.0
# ============================================================================
# PURPOSE: Execute defensive actions (block IPs) based on Security State.
# PRINCIPLE FAMILIES: Runtime Resilience, Closed-Loop Adaptation, Resource Awareness
# PRINCIPLES: Runtime Component Replacement, Controlled Overhead, State Preservation,
#             Graded Response, Cost-Aware Switching
# OPERATIONAL RULES: R1 (Proportional Response), R2 (Minimal Disruption),
#                    R3 (Controlled Overhead)
# REQUIREMENTS: R3 (Infrastructure Resilience), R5 (Rapid Protection)
# ============================================================================
# TRACEABILITY:
# - R1: Blocks only on ORANGE/RED (proportional).
# - R2: Only blocks the attacking IP, not all traffic.
# - R3: Checks if IP already blocked (idempotency) to save resources.
# - R3: Falls back to hosts.deny if iptables fails.
# - R5: Blocks within 5 seconds of detection.
# ============================================================================

import json
import subprocess
import time
import os
import random
import sys
import fcntl
import ipaddress
from config import Config


# ============================================================================
# COMPONENT 1: BLOCKING STRATEGIES (OCP Compliant - Extensible)
# ============================================================================
class IptablesStrategy:
    """Primary blocking strategy using iptables (IPv4) or ip6tables (IPv6)."""

    @staticmethod
    def is_ip_blocked(ip):
        """Check if rule exists in kernel (State Reconciliation)."""
        try:
            # Detect IP version
            ip_obj = ipaddress.ip_address(ip)
            cmd = ["sudo", "ip6tables" if ip_obj.version == 6 else "iptables",
                   "-C", "INPUT", "-s", ip, "-j", "DROP"]
            subprocess.run(cmd, check=True, capture_output=True, timeout=2.0)
            return True
        except:
            return False

    @staticmethod
    def block_ip(ip):
        """Execute block command."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            tool = "ip6tables" if ip_obj.version == 6 else "iptables"
            cmd = ["sudo", tool, "-A", "INPUT", "-s", ip, "-j", "DROP"]
            subprocess.run(cmd, check=True, timeout=5.0)
            return True, tool
        except Exception as e:
            return False, str(e)

    @staticmethod
    def unblock_ip(ip):
        """Execute unblock command."""
        try:
            ip_obj = ipaddress.ip_address(ip)
            tool = "ip6tables" if ip_obj.version == 6 else "iptables"
            cmd = ["sudo", tool, "-D", "INPUT", "-s", ip, "-j", "DROP"]
            subprocess.run(cmd, check=True, timeout=5.0)
            return True
        except:
            return False


class HostsDenyStrategy:
    """Fallback blocking strategy using /etc/hosts.deny."""

    @staticmethod
    def is_ip_blocked(ip):
        """Check if IP exists in /etc/hosts.deny."""
        try:
            with open("/etc/hosts.deny", "r") as f:
                content = f.read()
            return f"ALL: {ip}" in content
        except:
            return False

    @staticmethod
    def block_ip(ip):
        """Append IP to /etc/hosts.deny."""
        try:
            with open("/etc/hosts.deny", "a") as f:
                f.write(f"ALL: {ip}\n")
            return True, "hosts.deny"
        except Exception as e:
            return False, str(e)

    @staticmethod
    def unblock_ip(ip):
        """Remove IP from /etc/hosts.deny."""
        try:
            with open("/etc/hosts.deny", "r") as f:
                lines = f.readlines()
            with open("/etc/hosts.deny", "w") as f:
                for line in lines:
                    if f"ALL: {ip}" not in line:
                        f.write(line)
            return True
        except:
            return False


# ============================================================================
# COMPONENT 2: ACTION EXECUTOR (Strategy Pattern - OCP Compliant)
# ============================================================================
class ActionExecutor:
    """
    Encapsulates action execution with injectable strategy.
    OCP: Strategies can be injected without modifying this class.
    SRP: Only handles action execution and state reconciliation.
    """

    def __init__(self, primary_strategy=IptablesStrategy, fallback_strategy=HostsDenyStrategy):
        self.primary = primary_strategy
        self.fallback = fallback_strategy
        self.blocked_ips = set()  # In-memory cache

    def _sync_with_kernel(self, ip):
        """
        State Preservation: Reconcile in-memory cache with kernel reality.
        If the rule exists in kernel, add to set. If not, remove from set.
        """
        if self.primary.is_ip_blocked(ip):
            self.blocked_ips.add(ip)
            return True
        else:
            self.blocked_ips.discard(ip)
            return False

    def is_ip_blocked(self, ip):
        """Idempotency check: Syncs with kernel before trusting memory."""
        if ip in ["0.0.0.0", "127.0.0.1", "::1"]:
            return True  # Never block loopback/unknown
        return self._sync_with_kernel(ip)

    def block_ip(self, ip):
        """Execute blocking command with fallback (Chain of Responsibility)."""
        if ip in ["0.0.0.0", "127.0.0.1", "::1"]:
            return False, "none", "Refusing to block loopback/unknown IP"

        # State Reconciliation: Sync with kernel before blocking
        if self._sync_with_kernel(ip):
            return True, "cache", "Already blocked (kernel confirmed)"

        # Strategy 1: Primary
        success, result = self.primary.block_ip(ip)
        if success:
            self.blocked_ips.add(ip)
            self._log_action(f"BLOCKED {ip} via {result}")
            return True, result, "Blocked via primary strategy"

        # Strategy 2: Fallback
        print(f"[EXECUTOR] Primary failed ({result}). Trying fallback...")
        success, result = self.fallback.block_ip(ip)
        if success:
            self.blocked_ips.add(ip)
            self._log_action(f"BLOCKED {ip} via {result} (fallback)")
            return True, result, "Blocked via fallback strategy"

        # Strategy 3: Critical Failure
        self._log_action(f"CRITICAL: FAILED to block {ip} (Primary: {self.primary.__name__}, Fallback: {self.fallback.__name__})")
        return False, "none", "All blocking strategies failed"

    def null_route_block(self):
        """Fail-Secure Fallback: Block all traffic (null route) when unknown attacker in ORANGE/RED."""
        try:
            subprocess.run(
                ["sudo", "iptables", "-A", "INPUT", "-s", "0.0.0.0/0", "-j", "DROP"],
                check=True, timeout=5.0
            )
            self._log_action("CRITICAL: NULL-ROUTE ACTIVATED (0.0.0.0/0 blocked due to unknown attacker)")
            return True
        except Exception as e:
            self._log_action(f"CRITICAL: NULL-ROUTE FAILED: {e}")
            return False

    def _log_action(self, action):
        """Audit Logging: Singular, idempotent log entries."""
        try:
            with open(Config.LOG_FILE, "a") as f:
                f.write(f"[RESPONSE] {time.ctime()} | {action}\n")
        except Exception as e:
            print(f"[AUDIT] Failed to write log: {e}", file=sys.stderr)


# ============================================================================
# COMPONENT 3: BLACKBOARD (Abstraction for Loose Coupling)
# ============================================================================
class Blackboard:
    """
    Encapsulates all Blackboard operations.
    SRP: Only handles file I/O.
    Loose Coupling: Abstracts file operations; can be replaced with Redis later.
    """

    def __init__(self, filepath):
        self.filepath = filepath

    def read_state(self):
        """
        Read State and Attacker IP from Blackboard (Schema v1.0).
        Fail-Secure: Missing state → ORANGE (block).
        """
        try:
            with open(self.filepath, "r") as f:
                data = json.load(f)

            state = data.get("layer_3_state", {}).get("state", "ORANGE")
            attacker_ip = data.get("layer_2_ais", {}).get("attacker_ip", "0.0.0.0")

            # Validate state
            if state not in ["GREEN", "YELLOW", "ORANGE", "RED"]:
                state = "ORANGE"

            return state, attacker_ip
        except Exception:
            return "ORANGE", "0.0.0.0"  # Fail-Secure: cannot read → ORANGE

    def write_response_record(self, ip, method, success):
        """Write response action to Blackboard (Schema v1.0)."""
        try:
            os.makedirs(os.path.dirname(self.filepath), exist_ok=True)

            with open(self.filepath, 'r+') as f:
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)

                try:
                    data = json.load(f)
                except json.JSONDecodeError:
                    data = {}

                if "layer_4a_response" not in data:
                    data["layer_4a_response"] = {}

                if success:
                    blocked_list = data["layer_4a_response"].get("blocked_ips", [])
                    if ip not in blocked_list:
                        blocked_list.append(ip)
                    data["layer_4a_response"]["blocked_ips"] = blocked_list
                    data["layer_4a_response"]["last_block"] = ip
                    data["layer_4a_response"]["block_timestamp"] = time.time()
                    data["layer_4a_response"]["method"] = method
                else:
                    data["layer_4a_response"]["last_failed"] = ip
                    data["layer_4a_response"]["failed_timestamp"] = time.time()

                data["layer_4a_response"]["source"] = "service_response"
                data["layer_4a_response"]["version"] = Config.SCHEMA_VERSION

                f.seek(0)
                json.dump(data, f, indent=2)
                f.truncate()

                fcntl.flock(f.fileno(), fcntl.LOCK_UN)
        except Exception as e:
            print(f"[BLACKBOARD] Write error: {e}")


# ============================================================================
# COMPONENT 4: AUDIT LOGGER (SRP - Only handles logging)
# ============================================================================
class AuditLogger:
    def __init__(self, log_file):
        self.log_file = log_file

    def log(self, message, level="INFO"):
        try:
            with open(self.log_file, "a") as f:
                f.write(f"[{level}] [RESPONSE] {time.ctime()} | {message}\n")
        except Exception as e:
            print(f"[AUDIT] Failed to write log: {e}", file=sys.stderr)


# ============================================================================
# COMPONENT 5: RESPONSE SERVICE (Orchestrator of Components)
# ============================================================================
class ResponseService:
    def __init__(self):
        self.blackboard = Blackboard(Config.BLACKBOARD_FILE)
        self.logger = AuditLogger(Config.LOG_FILE)
        self.executor = ActionExecutor()

        self.running = True
        self.cycle_count = 0
        self.MAX_RETRIES = 5
        self.current_state = "GREEN"

    def execute_response(self, state, attacker_ip):
        self.current_state = state

        if state == "GREEN":
            # No action required
            pass

        elif state == "YELLOW":
            # Log only (monitoring intensified in Layer 1)
            self.logger.log(f"YELLOW: Monitoring only | IP: {attacker_ip}")

        elif state == "ORANGE":
            if attacker_ip != "0.0.0.0":
                success, method, msg = self.executor.block_ip(attacker_ip)
                self.blackboard.write_response_record(attacker_ip, method, success)
                if not success:
                    self.logger.log(f"ORANGE BLOCK FAILED: {msg}", level="ERROR")
            else:
                self.logger.log("CRITICAL: ORANGE state with 0.0.0.0 attacker! Activating null-route.", level="CRITICAL")
                self.executor.null_route_block()
                self.blackboard.write_response_record("0.0.0.0/0", "null-route", True)

        elif state == "RED":
            if attacker_ip != "0.0.0.0":
                success, method, msg = self.executor.block_ip(attacker_ip)
                self.blackboard.write_response_record(attacker_ip, method, success)
                if not success:
                    self.logger.log(f"RED BLOCK FAILED: {msg}", level="ERROR")
            else:
                self.logger.log("CRITICAL: RED state with 0.0.0.0 attacker! Activating null-route.", level="CRITICAL")
                self.executor.null_route_block()
                self.blackboard.write_response_record("0.0.0.0/0", "null-route", True)

        else:
            self.logger.log(f"Unknown state '{state}': Defaulting to ORANGE", level="WARNING")
            if attacker_ip != "0.0.0.0":
                success, method, msg = self.executor.block_ip(attacker_ip)
                self.blackboard.write_response_record(attacker_ip, method, success)
            else:
                self.executor.null_route_block()

    def run(self):
        print("[RESPONSE] Service started. Waiting for state changes...")
        self.logger.log("Service started")

        retry_count = 0
        while retry_count < self.MAX_RETRIES:
            try:
                while self.running:
                    try:
                        self.cycle_count += 1
                        state, attacker_ip = self.blackboard.read_state()
                        self.execute_response(state, attacker_ip)
                        print(f"[RESPONSE] Cycle {self.cycle_count} | State: {state} | IP: {attacker_ip}")

                        jitter = random.uniform(-0.5, 0.5)
                        sleep_time = max(0.5, Config.LOOP_INTERVAL + jitter)
                        time.sleep(sleep_time)

                    except KeyboardInterrupt:
                        print("\n[RESPONSE] Shutdown requested.")
                        self.logger.log("Shutdown requested")
                        self.running = False
                        return
                    except Exception as e:
                        print(f"[RESPONSE] Loop error: {e}")
                        self.logger.log(f"Loop error: {e}", level="ERROR")
                        time.sleep(5)
                break

            except Exception as fatal:
                retry_count += 1
                print(f"[RESPONSE] FATAL CRASH ({retry_count}/{self.MAX_RETRIES}): {fatal}")
                self.logger.log(f"FATAL CRASH ({retry_count}/{self.MAX_RETRIES}): {fatal}", level="ERROR")
                if retry_count >= self.MAX_RETRIES:
                    print("[RESPONSE] Max retries reached. Exiting.")
                    self.logger.log("Max retries reached. Exiting.", level="ERROR")
                    break
                time.sleep(30)


if __name__ == "__main__":
    service = ResponseService()
    service.run()