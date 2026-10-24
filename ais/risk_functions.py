#!/usr/bin/env python3
# ais/risk_functions.py – Risk functions for each capability

import json
from config import Config

def risk_from_failures(engine, failures, attacker_ip, monitor_healthy):
    """
    Risk calculation for failure‑count based monitors (SSH, HTTP, MySQL).
    This is the exact logic from the original service_ais.py.
    """
    # Whitelist check
    if engine.is_whitelisted(attacker_ip):
        print(f"[{engine.capability}-AIS] IP {attacker_ip} is whitelisted. Ignoring.")
        return 0

    # Fail-Secure: if monitor is unhealthy or failures invalid, force RED
    if not monitor_healthy or failures == -1:
        engine.risk = 100
        return 100

    # Update baseline (moving average)
    engine.failure_history.append(failures)
    if len(engine.failure_history) > 0:
        engine.baseline = sum(engine.failure_history) / len(engine.failure_history)

    if engine.baseline == 0:
        engine.baseline = 0.1

    anomaly_ratio = failures / engine.baseline
    raw_risk = min(anomaly_ratio * engine.risk_multiplier, 100)

    # Extra penalty if failures are extremely high
    if failures > 20:
        raw_risk = min(raw_risk + 30, 100)

    engine.risk = int(raw_risk)
    return engine.risk

def risk_from_sensor(engine, failures, attacker_ip, monitor_healthy):
    """
    Risk calculation for Sensor (multi‑metric).
    """
    # Read the sensor data directly from the blackboard
    try:
        with open(Config.BLACKBOARD_FILE, "r") as f:
            data = json.load(f)
        sensor_data = data.get(engine.monitor_section, {})
    except:
        sensor_data = {}

    risk = 0
    if sensor_data.get("new_process_count", 0) > 2:
        risk += 20
    if sensor_data.get("unknown_connection_count", 0) > 0:
        risk += 30
    if sensor_data.get("cpu_spike_detected", False):
        risk += 25
    if sensor_data.get("memory_spike_detected", False):
        risk += 15
    if sensor_data.get("file_change_count", 0) > 2:
        risk += 10

    # Cap at 100
    risk = min(risk, 100)
    engine.risk = risk
    return risk