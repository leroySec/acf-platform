#!/usr/bin/env python3
"""
response/response_engine.py — Layer 4a defence response engine.
One process. Many capabilities. Uniform output.

--- GRADED ESCALATION LADDER ---
RED does not fire the strongest action immediately. The response
escalates in stages:

  Stage 1  RED entered. Block the attacker IP on the service port.
  Stage 2  Attacker rotates IPs. Fail2ban continues to block each
           new IP as it crosses the confidence and hit thresholds.
  Stage 3  RED persists for RED_PERSISTENCE_BEFORE_ISOLATION seconds,
           OR the number of distinct blocked attackers reaches
           RED_DISTINCT_ATTACKERS_BEFORE_ISOLATION. The service port
           is then blocked for everyone. The host stays up.
  Stage 4  On de-escalation below RED, or on the panic timeout,
           every rule created during this cycle is released.

--- FAIL2BAN-STYLE DYNAMIC BLOCKING ---
On every cycle each worker reads the AIS known_threats list for its
capability. Any IP whose confidence and hit count cross the
thresholds is blocked on the capability's service ports for a
bounded duration.

--- SOURCE-SCOPED ACTIONS ---
Every rule created by this engine is scoped with remoteip=<attacker>.

--- SCOPED RULES ---
No host-wide profile-policy writes. Capability identity lives in the
rule name.

--- DISTRIBUTED RESPONSE (Item 5) ---
A separate responsibility, owned by DistributedResponse, runs after
each worker. Lifecycle is owned by ResponseEngine.

--- RELIABILITY FIXES ---
R1: _release_expired and _fail2ban_sweep run before the
    same-cycle early return.
R2: A blocked-IP entry is retained in blocked_ips when its rule
    deletion fails, so the next cycle retries.
R3: Partial rule creation is rolled back so no orphan rule is left.
R4: Persisted state is loaded before the orphan sweep.
R5: attacker_ip from the AIS section is only used when that section
    is fresh.
R6: A worker is rebuilt when its resolved config changes. The
    signature is computed by a module-level helper, NOT by
    constructing a probe ResponseWorker.

--- PRIMARY-INSTANCE GUARD ---
The orchestrator spawns this engine once per capability assigned to
layer4a. Only one instance is the "primary" and runs the engine loop.
The primary is the instance whose sys.argv[1] matches the first
capability (alphabetically) in the current layer4a assignment.
All other instances sleep in a light loop. If the primary dies, the
orchestrator respawns it and it re-takes the primary role. If the
config changes and a different capability becomes alphabetically
first, the matching running instance takes over on its next cycle.
"""
import os
import sys
import json
import time
import signal
import ipaddress
import subprocess
import threading
from typing import Dict, List, Any, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config
from platform_utils import acquire_lock, release_lock, get_temp_dir
from response.distributed_response import DistributedResponse

try:
    from event_emit import emit
except ImportError:
    def emit(src, layer, level, msg, capability=None, cycle=None):
        ts = time.strftime("%H:%M:%S")
        print(f"[{ts}][{src}][{layer}][{level.upper()}] {msg}")

SRC = "response_engine"
LAYER = "layer4a"

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SYSTEM_CONFIG_FILE = os.path.join(ROOT, "system_config.json")
BLACKBOARD_FILE = Config.BLACKBOARD_FILE
HEARTBEAT_FILE = os.path.join(
    get_temp_dir(), "acf_response_engine.heartbeat"
)

BASE_CYCLE_SECONDS = 10
MIN_CYCLE_SECONDS = 3
MAX_CYCLE_SECONDS = 30
WATCHDOG_MULTIPLIER = 20

UPSTREAM_FRESH_SECONDS = 30
READER_FRESH_SECONDS = 30

SEVERITY_WEIGHT = {"low": 5, "medium": 15, "high": 35, "critical": 60}
DEFAULT_SEVERITY_WEIGHT = 15

MAX_SYNTHETIC_DETECTIONS = 50

STATE_RANK = {"GREEN": 0, "YELLOW": 1, "ORANGE": 2, "RED": 3}

GREEN_TO_YELLOW = Config.GREEN_TO_YELLOW
YELLOW_TO_ORANGE = Config.YELLOW_TO_ORANGE
ORANGE_TO_RED = Config.ORANGE_TO_RED
RED_TO_ORANGE = Config.RED_TO_ORANGE
ORANGE_TO_YELLOW = Config.ORANGE_TO_YELLOW
YELLOW_TO_GREEN = Config.YELLOW_TO_GREEN

MANAGEMENT_PORT = getattr(Config, "MANAGEMENT_PORT", 8080)
MANAGEMENT_HOST = getattr(Config, "MANAGEMENT_HOST", "127.0.0.1")

BLOCK_CEILING_SECONDS = getattr(
    Config, "RESPONSE_BLOCK_CEILING_SECONDS",
    12 * (BASE_CYCLE_SECONDS * 10),
)
RED_PERSISTENCE_BEFORE_ISOLATION_SECONDS = getattr(
    Config, "RED_PERSISTENCE_BEFORE_ISOLATION_SECONDS", 300)
RED_DISTINCT_ATTACKERS_BEFORE_ISOLATION = getattr(
    Config, "RED_DISTINCT_ATTACKERS_BEFORE_ISOLATION", 3)

FAIL2BAN_CONFIDENCE_THRESHOLD = getattr(
    Config, "FAIL2BAN_CONFIDENCE_THRESHOLD", 50)
FAIL2BAN_MIN_HITS = getattr(Config, "FAIL2BAN_MIN_HITS",
                             getattr(Config, "FAIL2BAN_MAXRETRY", 5))
FAIL2BAN_BLOCK_DURATION = getattr(Config, "FAIL2BAN_BLOCK_DURATION",
                                   getattr(Config, "FAIL2BAN_BANTIME", 3600))

ACTION_TIMEOUT_SECONDS = 5
ACTION_RETRY_DELAY_SECONDS = 0

MAX_ACTION_HISTORY = 100
MAX_BLOCKED_IPS = 500

_DEFAULT_SERVICE_PORTS: Dict[str, List[int]] = {
    "ssh": [22],
    "app_http": [80, 443],
    "app_smtp": [25, 465, 587],
    "app_ftp": [21, 990],
    "app_mysql": [3306],
}

_RULE_PREFIX_TEMPLATE = "ACF_capability_{cap}_"

_BENIGN_DELETE_MESSAGES = (
    "no rules match",
    "aucune règle ne correspond",
    "aucune regle ne correspond",
    "le jeu de règles spécifié est introuvable",
)

UPSTREAM_SECTIONS = {
    "sensor": ["layer_1_sensor_ext", "layer_1_monitor_sensor"],
}

_running = True
_last_cycle_time = time.time()


# ----------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------
def _safe_int(v: Any, default: int = 0) -> int:
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _safe_float(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _safe_str(v: Any, default: str = "") -> str:
    if isinstance(v, str):
        return v
    if v is None:
        return default
    return str(v)


def _clamp_risk(v: Any) -> int:
    return min(100, max(0, _safe_int(v, 0)))


def _validate_thresholds() -> List[str]:
    errors = []
    if not (GREEN_TO_YELLOW > YELLOW_TO_GREEN):
        errors.append("GREEN_TO_YELLOW must be > YELLOW_TO_GREEN")
    if not (YELLOW_TO_ORANGE > ORANGE_TO_YELLOW):
        errors.append("YELLOW_TO_ORANGE must be > ORANGE_TO_YELLOW")
    if not (ORANGE_TO_RED > RED_TO_ORANGE):
        errors.append("ORANGE_TO_RED must be > RED_TO_ORANGE")
    return errors


def _is_safe_ip(ip_str: str) -> bool:
    if not isinstance(ip_str, str) or not ip_str:
        return False
    if ip_str == "0.0.0.0" or ip_str == "::":
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if (ip.is_private or ip.is_loopback or ip.is_multicast
            or ip.is_unspecified or ip.is_reserved or ip.is_link_local):
        return False
    return True


def _is_blockable_by_fail2ban(ip_str: str) -> bool:
    if not isinstance(ip_str, str) or not ip_str:
        return False
    if ip_str == "0.0.0.0" or ip_str == "::":
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if ip.is_loopback or ip.is_multicast or ip.is_unspecified:
        return False
    return True


def _is_benign_delete(err: str) -> bool:
    if not isinstance(err, str) or not err:
        return False
    low = err.lower()
    return any(p in low for p in _BENIGN_DELETE_MESSAGES)


# ----------------------------------------------------------------------
# Blackboard I/O
# ----------------------------------------------------------------------
def _bb_read() -> Dict:
    last_err = None
    for attempt in range(4):
        try:
            with open(BLACKBOARD_FILE, 'r', encoding='utf-8') as f:
                return json.load(f)
        except json.JSONDecodeError as e:
            last_err = e
            time.sleep(0.05 * (attempt + 1))
        except FileNotFoundError:
            return {}
        except Exception:
            return {}
    return {}


def _bb_read_section(section: str) -> Dict:
    data = _bb_read()
    s = data.get(section, {})
    return s if isinstance(s, dict) else {}


def _bb_update(section: str, updates: Dict) -> bool:
    try:
        with open(BLACKBOARD_FILE, 'r+') as f:
            acquire_lock(f.fileno(), exclusive=True)
            try:
                data = json.load(f)
            except json.JSONDecodeError:
                data = {}
            if section not in data or not isinstance(data[section], dict):
                data[section] = {}
            data[section].update(updates)
            f.seek(0)
            json.dump(data, f, indent=2)
            f.truncate()
            release_lock(f.fileno())
        return True
    except Exception as e:
        emit(SRC, LAYER, "error", f"Blackboard update for {section}: {e}")
        return False


def load_config() -> Dict:
    try:
        with open(SYSTEM_CONFIG_FILE, 'r') as f:
            return json.load(f)
    except Exception as e:
        emit(SRC, LAYER, "error", f"config load failed: {e}")
        return {}


def _read_disabled_map() -> Dict[str, List[str]]:
    try:
        with open(BLACKBOARD_FILE, 'r') as f:
            disabled = json.load(f).get("disabled_capabilities", {})
    except Exception:
        return {}
    if isinstance(disabled, list):
        return {cap: ["*"] for cap in disabled}
    if isinstance(disabled, dict):
        out = {}
        for cap, layers in disabled.items():
            if isinstance(layers, list):
                out[cap] = layers
            elif layers is True:
                out[cap] = ["*"]
        return out
    return {}


def _pair_disabled(disabled_map: Dict, capability: str, layer: str) -> bool:
    entry = disabled_map.get(capability)
    if not entry:
        return False
    if "*" in entry:
        return True
    return layer in entry


def _capabilities_for_layer(config: Dict, layer: str) -> List[str]:
    capability_layers = config.get("capability_layers", {})
    if not isinstance(capability_layers, dict):
        return []
    return [
        name for name, layers in capability_layers.items()
        if isinstance(layers, list) and layer in layers
    ]


def _layer1_candidates(capability: str) -> List[str]:
    if capability in UPSTREAM_SECTIONS:
        return list(UPSTREAM_SECTIONS[capability])
    return [f"layer_1_monitor_{capability}"]


def _weighted_sum(detections: List[Dict]) -> int:
    total = 0
    for d in detections:
        if not isinstance(d, dict):
            continue
        sev = d.get("severity", "medium")
        total += SEVERITY_WEIGHT.get(sev, DEFAULT_SEVERITY_WEIGHT)
    return total


def _make_detection(capability: str, ts: float, cls: str, severity: str,
                     detail_value: Any, src_ip: str = "0.0.0.0") -> Dict:
    return {
        "ts": ts, "source": capability, "class": cls, "severity": severity,
        "src_ip": src_ip,
        "detail": f"{cls}={detail_value}", "raw": f"{cls}={detail_value}",
    }


def _synthesize_detections(capability: str, failures: int,
                            attacker_ip: str, ts: float) -> List[Dict]:
    if failures <= 0:
        return []
    n = min(int(failures), MAX_SYNTHETIC_DETECTIONS)
    if failures <= 3:
        sev = "low"
    elif failures <= 10:
        sev = "medium"
    elif failures <= 30:
        sev = "high"
    else:
        sev = "critical"
    ip = attacker_ip if isinstance(attacker_ip, str) else "0.0.0.0"
    return [{
        "ts": ts, "source": capability, "class": "log_match",
        "severity": sev, "src_ip": ip,
        "detail": f"{failures} failures (from reader count)", "raw": "",
    } for _ in range(n)]


def _detections_from_sensor_section(capability: str, section: Dict,
                                     ts: float) -> List[Dict]:
    detections: List[Dict] = []
    if section.get("cpu_spike_detected") is True:
        detections.append(_make_detection(
            capability, ts, "cpu_spike", "high",
            _safe_float(section.get("cpu_percent"), 0.0)))
    if section.get("memory_spike_detected") is True:
        detections.append(_make_detection(
            capability, ts, "memory_spike", "high",
            _safe_float(section.get("memory_percent"), 0.0)))
    unknown = _safe_int(section.get("unknown_connection_count"), 0)
    if unknown > 0:
        detections.append(_make_detection(
            capability, ts, "unknown_connection", "high", unknown))
    changes = _safe_int(section.get("file_change_count"), 0)
    if changes > 0:
        detections.append(_make_detection(
            capability, ts, "file_change", "high", changes))
    new_procs = _safe_int(section.get("new_process_count"), 0)
    if new_procs > 0:
        detections.append(_make_detection(
            capability, ts, "process_new", "low", new_procs))
    return detections


def _derive_risk(detections: List[Dict]) -> int:
    return min(100, _weighted_sum(detections))


def _transition(current: str, risk: int) -> Tuple[str, str]:
    current = current if current in STATE_RANK else "GREEN"

    if current == "GREEN":
        if risk > GREEN_TO_YELLOW:
            return "YELLOW", "GREEN_TO_YELLOW"
    elif current == "YELLOW":
        if risk > YELLOW_TO_ORANGE:
            return "ORANGE", "YELLOW_TO_ORANGE"
        if risk < YELLOW_TO_GREEN:
            return "GREEN", "YELLOW_TO_GREEN"
    elif current == "ORANGE":
        if risk > ORANGE_TO_RED:
            return "RED", "ORANGE_TO_RED"
        if risk < ORANGE_TO_YELLOW:
            return "YELLOW", "ORANGE_TO_YELLOW"
    elif current == "RED":
        if risk < RED_TO_ORANGE:
            return "ORANGE", "RED_TO_ORANGE"

    return current, "none"


# ----------------------------------------------------------------------
# External command runners
# ----------------------------------------------------------------------
def _run_command(cmd: List[str], retry: bool = True) -> Tuple[bool, str]:
    attempts = 2 if retry else 1
    last_err = ""
    for attempt in range(attempts):
        try:
            result = subprocess.run(
                cmd, capture_output=True, text=True,
                timeout=ACTION_TIMEOUT_SECONDS, check=False,
                errors="replace",
            )
            if result.returncode == 0:
                return True, ""
            last_err = (result.stderr or result.stdout or "").strip()[:200]
        except subprocess.TimeoutExpired:
            last_err = "timeout"
        except FileNotFoundError as e:
            return False, f"command not found: {e}"
        except Exception as e:
            last_err = str(e)[:200]
        if attempt + 1 < attempts:
            time.sleep(ACTION_RETRY_DELAY_SECONDS)
    return False, last_err or "unknown error"


def _run_ps(script: str, timeout: float = 15.0) -> Tuple[bool, str, str]:
    try:
        r = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive",
             "-Command", script],
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
        return r.returncode == 0, r.stdout or "", r.stderr or ""
    except Exception as e:
        return False, "", str(e)


# ----------------------------------------------------------------------
# Service-port resolution
# ----------------------------------------------------------------------
def _resolve_service_ports(capability: str, config: Dict) -> List[int]:
    rules = config.get("capability_rules", {})
    if isinstance(rules, dict):
        entry = rules.get(capability)
        if isinstance(entry, dict):
            raw = entry.get("service_ports")
            if isinstance(raw, list):
                cleaned: List[int] = []
                for p in raw:
                    try:
                        n = int(p)
                    except (TypeError, ValueError):
                        continue
                    if 1 <= n <= 65535 and n not in cleaned:
                        cleaned.append(n)
                if cleaned:
                    return cleaned
    return list(_DEFAULT_SERVICE_PORTS.get(capability, []))


# ----------------------------------------------------------------------
# Fail2ban parameter resolution
# ----------------------------------------------------------------------
def _resolve_fail2ban_config(capability: str, config: Dict) -> Dict[str, Any]:
    defaults: Dict[str, Any] = {
        "maxretry": _safe_int(
            getattr(Config, "FAIL2BAN_MAXRETRY",
                    getattr(Config, "FAIL2BAN_MIN_HITS", 5)), 5),
        "findtime": _safe_int(
            getattr(Config, "FAIL2BAN_FINDTIME", 600), 600),
        "bantime": _safe_int(
            getattr(Config, "FAIL2BAN_BANTIME",
                    getattr(Config, "FAIL2BAN_BLOCK_DURATION", 3600)),
            3600),
        "confidence": _safe_int(
            getattr(Config, "FAIL2BAN_CONFIDENCE_THRESHOLD", 50), 50),
        "ignoreip": list(getattr(Config, "FAIL2BAN_IGNOREIP", []) or []),
    }

    rules = config.get("capability_rules", {})
    if not isinstance(rules, dict):
        return defaults
    entry = rules.get(capability)
    if not isinstance(entry, dict):
        return defaults
    fb = entry.get("fail2ban")
    if not isinstance(fb, dict):
        return defaults

    for key in ("maxretry", "findtime", "bantime", "confidence"):
        if key in fb:
            try:
                v = int(fb[key])
                if v >= 0:
                    defaults[key] = v
            except (TypeError, ValueError):
                pass

    ip_list = fb.get("ignoreip")
    if isinstance(ip_list, list):
        cleaned = [ip.strip() for ip in ip_list
                   if isinstance(ip, str) and ip.strip()]
        if cleaned:
            defaults["ignoreip"] = cleaned

    return defaults


def _config_signature_for(name: str, config: Dict) -> Tuple:
    service_ports = _resolve_service_ports(name, config)
    fail2ban = _resolve_fail2ban_config(name, config)
    return (
        tuple(sorted(service_ports)),
        fail2ban.get("maxretry"),
        fail2ban.get("bantime"),
        fail2ban.get("confidence"),
        tuple(sorted(fail2ban.get("ignoreip") or [])),
    )


# ----------------------------------------------------------------------
# Rule naming and sweep
# ----------------------------------------------------------------------
def _cap_prefix(capability: str) -> str:
    return _RULE_PREFIX_TEMPLATE.format(cap=capability)


def _rule_name_block_in(capability: str, ip: str, port: int) -> str:
    return f"{_cap_prefix(capability)}BLOCK_{ip}_IN_{port}_{int(time.time() * 1000)}"


def _rule_name_block_out(capability: str, ip: str, port: int) -> str:
    return f"{_cap_prefix(capability)}BLOCK_{ip}_OUT_{port}_{int(time.time() * 1000)}"


def _rule_name_block_in_all(capability: str, ip: str) -> str:
    return f"{_cap_prefix(capability)}BLOCK_{ip}_IN_ALL_{int(time.time() * 1000)}"


def _rule_name_block_out_all(capability: str, ip: str) -> str:
    return f"{_cap_prefix(capability)}BLOCK_{ip}_OUT_ALL_{int(time.time() * 1000)}"


def _rule_name_iso_in(capability: str, port: int) -> str:
    return f"{_cap_prefix(capability)}ISO_IN_{port}_{int(time.time() * 1000)}"


def _rule_name_iso_out(capability: str, port: int) -> str:
    return f"{_cap_prefix(capability)}ISO_OUT_{port}_{int(time.time() * 1000)}"


def _sweep_orphan_rules(capability: str,
                        keep_names: Optional[List[str]] = None) -> None:
    keep = set(keep_names or [])
    prefix = _cap_prefix(capability)
    prefix_esc = prefix.replace("'", "''")
    ps = (
        f"Get-NetFirewallRule -ErrorAction SilentlyContinue | "
        f"Where-Object {{ $_.Name -like '{prefix_esc}*' }} | "
        f"Select-Object -ExpandProperty Name"
    )
    ok, out, err = _run_ps(ps)
    if not ok:
        if err:
            emit(SRC, LAYER, "warn",
                 f"sweep for {capability}: {err.strip()[:200]}",
                 capability=capability)
        return
    for line in (out or "").splitlines():
        name = line.strip()
        if not name:
            continue
        if name in keep:
            continue
        ok2, err2 = _run_command(
            ["netsh", "advfirewall", "firewall", "delete", "rule",
             f"name={name}"],
            retry=False)
        if not ok2 and not _is_benign_delete(err2):
            emit(SRC, LAYER, "warn",
                 f"sweep delete failed for {name}: {err2}",
                 capability=capability)


# ----------------------------------------------------------------------
# Actions
# ----------------------------------------------------------------------
def _action_block_ip_on_ports(ip: str, capability: str, ports: List[int]
                               ) -> Tuple[bool, str, List[str]]:
    rule_names: List[str] = []
    errors: List[str] = []

    for port in ports:
        in_name = _rule_name_block_in(capability, ip, port)
        out_name = _rule_name_block_out(capability, ip, port)

        ok, err = _run_command([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={in_name}",
            "dir=in", "action=block", "protocol=TCP",
            f"remoteip={ip}", f"localport={port}", "profile=any",
        ])
        if ok:
            rule_names.append(in_name)
        else:
            errors.append(f"{in_name}: {err}")

        ok, err = _run_command([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={out_name}",
            "dir=out", "action=block", "protocol=TCP",
            f"remoteip={ip}", f"localport={port}", "profile=any",
        ])
        if ok:
            rule_names.append(out_name)
        else:
            errors.append(f"{out_name}: {err}")

    if errors:
        for name in rule_names:
            _run_command(
                ["netsh", "advfirewall", "firewall", "delete", "rule",
                 f"name={name}"],
                retry=False)
        return False, "; ".join(errors)[:200], []
    return True, "", rule_names


def _action_block_ip(ip: str, capability: str
                      ) -> Tuple[bool, str, List[str]]:
    rule_names: List[str] = []
    errors: List[str] = []

    in_name = _rule_name_block_in_all(capability, ip)
    out_name = _rule_name_block_out_all(capability, ip)

    ok, err = _run_command([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={in_name}",
        "dir=in", "action=block",
        f"remoteip={ip}", "profile=any",
    ])
    if ok:
        rule_names.append(in_name)
    else:
        errors.append(f"{in_name}: {err}")

    ok, err = _run_command([
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={out_name}",
        "dir=out", "action=block",
        f"remoteip={ip}", "profile=any",
    ])
    if ok:
        rule_names.append(out_name)
    else:
        errors.append(f"{out_name}: {err}")

    if errors:
        for name in rule_names:
            _run_command(
                ["netsh", "advfirewall", "firewall", "delete", "rule",
                 f"name={name}"],
                retry=False)
        return False, "; ".join(errors)[:200], []
    return True, "", rule_names


def _action_release_rules_by_name(names: List[str]) -> Tuple[bool, str]:
    if not names:
        return True, ""
    failures: List[str] = []
    for name in names:
        cmd = ["netsh", "advfirewall", "firewall", "delete", "rule",
               f"name={name}"]
        ok, err = _run_command(cmd, retry=False)
        if not ok and not _is_benign_delete(err):
            failures.append(f"{name}: {err}")
    if failures:
        return False, "; ".join(failures)[:200]
    return True, ""


def _action_isolate_service(capability: str, ports: List[int]
                             ) -> Tuple[bool, str, List[str]]:
    if not ports:
        return True, "", []
    rule_names: List[str] = []
    errors: List[str] = []

    for port in ports:
        in_name = _rule_name_iso_in(capability, port)
        out_name = _rule_name_iso_out(capability, port)

        ok, err = _run_command([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={in_name}",
            "dir=in", "action=block", "protocol=TCP",
            f"localport={port}", "profile=any",
        ])
        if ok:
            rule_names.append(in_name)
        else:
            errors.append(f"{in_name}: {err}")

        ok, err = _run_command([
            "netsh", "advfirewall", "firewall", "add", "rule",
            f"name={out_name}",
            "dir=out", "action=block", "protocol=TCP",
            f"localport={port}", "profile=any",
        ])
        if ok:
            rule_names.append(out_name)
        else:
            errors.append(f"{out_name}: {err}")

    if errors:
        for name in rule_names:
            _run_command(
                ["netsh", "advfirewall", "firewall", "delete", "rule",
                 f"name={name}"],
                retry=False)
        return False, "; ".join(errors)[:200], []
    return True, "", rule_names


# ----------------------------------------------------------------------
# PRIMARY INSTANCE GUARD
# ----------------------------------------------------------------------

def _is_primary_instance(layer_name: str) -> bool:
    """
    Only one instance per layer runs the engine loop. The orchestrator
    spawns this engine once per capability in SERVICE_MAP assigned to
    the layer. The primary is the instance whose sys.argv[1] matches
    the first such capability (alphabetically). If started without an
    argument, act as primary.

    The election is restricted to SERVICE_MAP capabilities because
    those are the only ones the orchestrator ever spawns. Custom
    capabilities (defender, pfirewall) are processed by those
    instances as part of their layer's assignment; they do not get
    their own process.

    Recomputed every cycle so a change in the layer's capability set
    is picked up automatically.
    """
    if len(sys.argv) < 2:
        return True
    my_cap = sys.argv[1]
    try:
        config = load_config()
    except Exception:
        return True
    caps = _capabilities_for_layer(config, layer_name)
    if not caps:
        return True
    spawnable = [c for c in caps if c in Config.SERVICE_MAP]
    if not spawnable:
        return True
    return my_cap == sorted(spawnable)[0]

# ----------------------------------------------------------------------
# Worker
# ----------------------------------------------------------------------
class ResponseWorker:
    def __init__(self, name: str, disabled_map: Dict,
                 config: Optional[Dict] = None):
        self.name = name
        self.state_section = f"layer_3_state_{name}"
        self.ais_section = f"layer_2_ais_{name}"
        self.reader_section = f"reader_{name}"
        self.response_section = f"layer_4a_response_{name}"
        self.layer1_candidates = _layer1_candidates(name)
        self.disabled_map = disabled_map

        if config is None:
            config = load_config()
        self.service_ports = _resolve_service_ports(name, config)
        self.fail2ban = _resolve_fail2ban_config(name, config)

        self.state_input = "GREEN"
        self.risk_input = 0
        self.actions: List[Dict] = []
        self.blocked_ips: List[Dict] = []
        self.last_block = ""
        self.block_timestamp = 0.0
        self.method = "observe"

        self.isolation_active: bool = False
        self.isolation_rule_names: List[str] = []
        self.isolation_ports: List[int] = []
        self.isolation_started_at: float = 0.0
        self.escalation_reason: str = ""

        self.cycle_count = 0
        self.last_processed_key: Optional[Tuple[str, float]] = None
        self._reader_cumulative_seen: Optional[int] = None

        self._load_persisted_state()
        keep = []
        for entry in self.blocked_ips:
            keep.extend(entry.get("rule_names") or [])
        keep.extend(self.isolation_rule_names or [])
        _sweep_orphan_rules(name, keep_names=keep)

    def config_signature(self) -> Tuple:
        return (
            tuple(sorted(self.service_ports)),
            self.fail2ban.get("maxretry"),
            self.fail2ban.get("bantime"),
            self.fail2ban.get("confidence"),
            tuple(sorted(self.fail2ban.get("ignoreip") or [])),
        )

    def _load_persisted_state(self) -> None:
        section = _bb_read_section(self.response_section)

        s = section.get("state_input")
        if isinstance(s, str) and s in STATE_RANK:
            self.state_input = s

        self.risk_input = _clamp_risk(section.get("risk_input"))

        acts = section.get("actions")
        if isinstance(acts, list):
            cleaned = []
            for a in acts:
                if not isinstance(a, dict):
                    continue
                a.setdefault("risk_at_action", 0)
                a.setdefault("state_at_action", "GREEN")
                a.setdefault("false_positive", False)
                a.setdefault("fp_source", "")
                cleaned.append(a)
            self.actions = cleaned[-MAX_ACTION_HISTORY:]

        blocked = section.get("blocked_ips")
        if isinstance(blocked, list):
            cleaned = []
            for b in blocked:
                if not isinstance(b, dict) or not isinstance(b.get("ip"), str):
                    continue
                names = b.get("rule_names")
                if not isinstance(names, list):
                    single = b.get("rule_name")
                    names = [single] if isinstance(single, str) and single else []
                entry = {
                    "ip": b["ip"],
                    "rule_names": [n for n in names if isinstance(n, str)],
                    "installed_at": _safe_float(b.get("installed_at"), 0.0),
                    "expires_at": _safe_float(b.get("expires_at"), 0.0),
                }
                src = b.get("source")
                if isinstance(src, str) and src:
                    entry["source"] = src
                cleaned.append(entry)
            self.blocked_ips = cleaned[:MAX_BLOCKED_IPS]

        self.last_block = _safe_str(section.get("last_block"), "")
        self.block_timestamp = _safe_float(
            section.get("block_timestamp"), 0.0)
        self.method = _safe_str(section.get("method"), "observe")

        self.isolation_active = section.get("isolation_active") is True
        names = section.get("isolation_rule_names")
        if isinstance(names, list):
            self.isolation_rule_names = [
                _safe_str(n) for n in names if isinstance(n, str)
            ]
        ports = section.get("isolation_ports")
        if isinstance(ports, list):
            self.isolation_ports = [
                _safe_int(p) for p in ports if isinstance(p, (int, float))
            ]
        v = section.get("isolation_started_at")
        if isinstance(v, (int, float)) and v > 0:
            self.isolation_started_at = float(v)
        else:
            self.isolation_started_at = 0.0
        self.escalation_reason = _safe_str(
            section.get("escalation_reason"), "")

        persisted = section.get("last_processed_key")
        if (isinstance(persisted, list) and len(persisted) == 2
                and isinstance(persisted[0], str)):
            self.last_processed_key = (
                persisted[0],
                _safe_float(persisted[1], 0.0),
            )

        v = section.get("_reader_cumulative_seen")
        if isinstance(v, (int, float)):
            self._reader_cumulative_seen = int(v)
        else:
            self._reader_cumulative_seen = None

    def _read_state(self) -> Optional[Tuple[str, int, str, float]]:
        section = _bb_read_section(self.state_section)
        if section:
            ts = _safe_float(section.get("state_timestamp"), 0.0)
            if ts > 0.0 and (time.time() - ts) <= UPSTREAM_FRESH_SECONDS:
                if section.get("state_healthy") is True:
                    s = section.get("state")
                    if (isinstance(s, str)
                            and s.strip().upper() in STATE_RANK):
                        return (s.strip().upper(),
                                _clamp_risk(section.get("risk_input")),
                                "layer_3_state", ts)

        section = _bb_read_section(self.ais_section)
        if section:
            ts = _safe_float(section.get("ais_timestamp"), 0.0)
            if ts > 0.0 and (time.time() - ts) <= UPSTREAM_FRESH_SECONDS:
                if section.get("ais_healthy") is True:
                    risk = _clamp_risk(section.get("risk"))
                    state, _ = _transition(self.state_input, risk)
                    return state, risk, "layer_2_ais", ts

        for section_name in self.layer1_candidates:
            sec = _bb_read_section(section_name)
            if not sec:
                continue
            ts = _safe_float(sec.get("monitoring_timestamp"), 0.0)
            if ts <= 0.0:
                ts = _safe_float(sec.get("sensor_timestamp"), 0.0)
            if ts <= 0.0 or (time.time() - ts) > UPSTREAM_FRESH_SECONDS:
                continue
            healthy = sec.get("monitor_healthy")
            if healthy is None:
                healthy = sec.get("sensor_healthy")
            if healthy is not True:
                continue
            detections = sec.get("detections")
            if isinstance(detections, list) and detections:
                risk = _derive_risk(detections)
            elif section_name == "layer_1_sensor_ext":
                risk = _derive_risk(
                    _detections_from_sensor_section(self.name, sec, ts))
            else:
                risk = 0
            state, _ = _transition(self.state_input, risk)
            return state, risk, section_name, ts

        section = _bb_read_section(self.reader_section)
        if section:
            ts = section.get("reading_timestamp")
            if ts is None:
                ts = section.get("monitoring_timestamp", 0.0)
            ts = _safe_float(ts, 0.0)
            if ts > 0.0 and (time.time() - ts) <= READER_FRESH_SECONDS:
                if section.get("reader_ready") is True:
                    cumulative = _safe_int(
                        section.get("last_failures_cumulative"), 0)
                    ip = _safe_str(
                        section.get("last_attacker_ip"),
                        "0.0.0.0") or "0.0.0.0"
                    seen = self._reader_cumulative_seen
                    if seen is None:
                        failures = cumulative
                    elif cumulative < seen:
                        failures = 0
                    else:
                        failures = cumulative - seen
                    self._reader_cumulative_seen = cumulative
                    risk = _derive_risk(_synthesize_detections(
                        self.name, failures, ip, ts))
                    state, _ = _transition(self.state_input, risk)
                    return state, risk, "reader", ts

        return None

    def _read_fresh_attacker_ip(self) -> Optional[str]:
        section = _bb_read_section(self.ais_section)
        if not section:
            return None
        ts = _safe_float(section.get("ais_timestamp"), 0.0)
        if ts <= 0.0:
            return None
        if (time.time() - ts) > UPSTREAM_FRESH_SECONDS:
            return None
        if section.get("ais_healthy") is not True:
            return None
        ip = _safe_str(section.get("attacker_ip"), "")
        return ip or None

    def _red_elapsed_seconds(self, now: float) -> float:
        sec = _bb_read_section(self.state_section)
        entered = _safe_float(sec.get("state_entered_at"), 0.0)
        if entered <= 0:
            return 0.0
        return max(0.0, now - entered)

    def _should_escalate_to_isolation(self, now: float
                                       ) -> Tuple[bool, str]:
        if not self.service_ports:
            return False, "no_service_ports"
        elapsed = self._red_elapsed_seconds(now)
        if elapsed >= RED_PERSISTENCE_BEFORE_ISOLATION_SECONDS:
            return True, f"escalated_after_seconds={int(elapsed)}"
        distinct = len(self.blocked_ips)
        if distinct >= RED_DISTINCT_ATTACKERS_BEFORE_ISOLATION:
            return True, f"escalated_after_attackers={distinct}"
        return False, ""

    def _record_action(self, now: float, action: str, target: str,
                        method: str, error: str = "", **fields) -> None:
        entry = {
            "ts": now,
            "action": action,
            "target": target,
            "method": method,
            "risk_at_action": _clamp_risk(self.risk_input),
            "state_at_action": self.state_input,
            "false_positive": False,
            "fp_source": "",
        }
        for k, v in fields.items():
            if isinstance(v, str) and len(v) > 200:
                v = v[:200]
            entry[k] = v
        if error:
            entry["error"] = error[:200]
        self.actions.append(entry)
        if len(self.actions) > MAX_ACTION_HISTORY:
            self.actions = self.actions[-MAX_ACTION_HISTORY:]

    def _bounded_blocked_ips(self) -> None:
        if len(self.blocked_ips) > MAX_BLOCKED_IPS:
            self.blocked_ips.sort(
                key=lambda e: _safe_float(e.get("installed_at"), 0.0))
            dropped = self.blocked_ips[
                :len(self.blocked_ips) - MAX_BLOCKED_IPS]
            for d in dropped:
                names = d.get("rule_names") or []
                if names:
                    _action_release_rules_by_name(names)
            self.blocked_ips = self.blocked_ips[-MAX_BLOCKED_IPS:]

    def _is_ignored(self, ip: str) -> bool:
        for entry in self.fail2ban.get("ignoreip", []) or []:
            if entry == ip:
                return True
        return False

    def _fail2ban_sweep(self, now: float) -> None:
        ais = _bb_read_section(self.ais_section)
        threats = ais.get("known_threats")
        if not isinstance(threats, list):
            return

        for threat in threats:
            if not isinstance(threat, dict):
                continue
            ip = threat.get("ip")
            if not isinstance(ip, str) or not ip:
                continue

            if self._is_ignored(ip):
                continue
            if not _is_blockable_by_fail2ban(ip):
                continue

            confidence = _safe_int(threat.get("confidence"), 0)
            hits = _safe_int(threat.get("hits"), 0)

            if confidence < self.fail2ban["confidence"]:
                continue
            if hits < self.fail2ban["maxretry"]:
                continue
            if any(b.get("ip") == ip for b in self.blocked_ips):
                continue

            if self.service_ports:
                ok, err, names = _action_block_ip_on_ports(
                    ip, self.name, self.service_ports)
            else:
                ok, err, names = _action_block_ip(ip, self.name)

            self._record_action(
                now, "fail2ban_block", ip,
                "netsh" if ok else "netsh_failed", err,
                confidence=confidence, hits=hits)

            if ok:
                self.blocked_ips.append({
                    "ip": ip,
                    "rule_names": names,
                    "installed_at": now,
                    "expires_at": now + self.fail2ban["bantime"],
                    "source": "fail2ban",
                })
                self.last_block = ip
                self.block_timestamp = now
                if self.method == "observe":
                    self.method = "netsh"
                self._bounded_blocked_ips()

    def _release_expired(self, now: float, current_state: str) -> None:
        rank = STATE_RANK.get(current_state, 0)
        release_all = rank < STATE_RANK["ORANGE"]
        release_isolation_only = (
            rank == STATE_RANK["ORANGE"]
            and self.isolation_active
        )

        ceiling = getattr(Config, "PANIC_TIMEOUT_SECONDS", 300)
        try:
            ceiling = float(ceiling)
        except (TypeError, ValueError):
            ceiling = 300.0
        if ceiling < 0:
            ceiling = 300.0

        ceiling_hit = False
        if self.isolation_active:
            if self.isolation_started_at <= 0:
                self.isolation_started_at = now
            elif (now - self.isolation_started_at) > ceiling:
                ceiling_hit = True

        survivors: List[Dict] = []
        for entry in self.blocked_ips:
            ip = entry.get("ip", "")
            names = entry.get("rule_names") or []
            expires_at = _safe_float(entry.get("expires_at"), 0.0)
            entry_ceiling = expires_at > 0 and now >= expires_at

            # Fail2ban blocks honour their own bantime and must not
            # be released simply because state dropped below ORANGE.
            # State-path blocks release on de-escalation; fail2ban
            # blocks release only when their expires_at arrives.
            source = entry.get("source", "")
            is_fail2ban = source == "fail2ban"

            if entry_ceiling or (release_all and not is_fail2ban):
                ok = True
                err = ""
                if names:
                    ok, err = _action_release_rules_by_name(names)
                if ok:
                    self._record_action(
                        now, "release_ip", ip,
                        "netsh", "")
                    continue
                entry["last_release_error"] = err[:200]
                entry["last_release_attempt"] = now
                self._record_action(
                    now, "release_ip_failed", ip,
                    "netsh_failed", err)
                survivors.append(entry)
                continue
            survivors.append(entry)
        self.blocked_ips = survivors

        if self.isolation_active and (
                release_all or release_isolation_only or ceiling_hit):
            ok, err = _action_release_rules_by_name(
                self.isolation_rule_names)
            self._record_action(
                now, "release_isolation", "-",
                "netsh" if ok else "netsh_failed",
                err if not ok else "")
            if ok:
                self.isolation_active = False
                self.isolation_rule_names = []
                self.isolation_ports = []
                self.isolation_started_at = 0.0
                self.escalation_reason = ""

    

    def _apply_ip_block(self, now: float, attacker_ip: str) -> None:
        if self.service_ports:
            ok, err, names = _action_block_ip_on_ports(
                attacker_ip, self.name, self.service_ports)
        else:
            ok, err, names = _action_block_ip(attacker_ip, self.name)

        self._record_action(
            now, "block_ip", attacker_ip,
            "netsh" if ok else "netsh_failed", err)

        if ok:
            self.blocked_ips.append({
                "ip": attacker_ip,
                "rule_names": names,
                "installed_at": now,
                "expires_at": now + BLOCK_CEILING_SECONDS,
            })
            self.last_block = attacker_ip
            self.block_timestamp = now
            self.method = "netsh"
        else:
            self.method = "netsh_failed"

    def _execute_for_state(self, state: str, now: float,
                            attacker_ip: str) -> None:
        if state == "GREEN" or state == "YELLOW":
            self.method = "observe"
            return

        if state == "ORANGE":
            if attacker_ip and _is_safe_ip(attacker_ip):
                if not any(b.get("ip") == attacker_ip
                           for b in self.blocked_ips):
                    self._apply_ip_block(now, attacker_ip)
                else:
                    self.method = "netsh"
            else:
                self.method = "observe"
            self._bounded_blocked_ips()
            return

        if state == "RED":
            if attacker_ip and _is_safe_ip(attacker_ip):
                if not any(b.get("ip") == attacker_ip
                           for b in self.blocked_ips):
                    self._apply_ip_block(now, attacker_ip)

            if not self.isolation_active and self.service_ports:
                should, reason = self._should_escalate_to_isolation(now)
                if should:
                    ok, err, names = _action_isolate_service(
                        self.name, self.service_ports)
                    self._record_action(
                        now, "isolate_service", "-",
                        "netsh" if ok else "netsh_failed", err,
                        escalation_reason=reason)
                    if ok:
                        self.isolation_active = True
                        self.isolation_rule_names = names
                        self.isolation_ports = list(self.service_ports)
                        self.isolation_started_at = now
                        self.escalation_reason = reason
                        self.method = "netsh"
                    else:
                        self.method = "netsh_failed"
            self._bounded_blocked_ips()
            return

    def run_cycle(self) -> None:
        self.cycle_count += 1
        if _pair_disabled(self.disabled_map, self.name, "layer4a"):
            return

        now = time.time()
        read = self._read_state()

        if read is None:
            self._fail2ban_sweep(now)
            self._release_expired(now, self.state_input)
            _bb_update(self.response_section, {
                "source": self.name,
                "response_timestamp": now,
                "response_healthy": False,
                "state_input": self.state_input,
                "risk_input": self.risk_input,
                "actions": self.actions,
                "blocked_ips": self.blocked_ips,
                "last_block": self.last_block,
                "block_timestamp": self.block_timestamp,
                "method": "no_input",
                "isolation_active": self.isolation_active,
                "isolation_rule_names": self.isolation_rule_names,
                "isolation_ports": self.isolation_ports,
                "isolation_started_at": self.isolation_started_at,
                "escalation_reason": self.escalation_reason,
                "service_ports": self.service_ports,
                "fail2ban": self.fail2ban,
                "last_processed_key": (
                    list(self.last_processed_key)
                    if self.last_processed_key else None
                ),
                "detail": {
                    "input_source": "none",
                    "management_port": MANAGEMENT_PORT,
                    "block_ceiling_seconds": BLOCK_CEILING_SECONDS,
                },
                "version": Config.SCHEMA_VERSION,
                "_reader_cumulative_seen": self._reader_cumulative_seen,
            })
            emit(SRC, LAYER, "warn",
                 f"Cycle {self.cycle_count} | no input; observing",
                 capability=self.name)
            return

        state, risk, source, source_id = read
        new_key = (source, source_id)

        self._fail2ban_sweep(now)
        self._release_expired(now, state)

        if new_key == self.last_processed_key:
            _bb_update(self.response_section, {
                "response_timestamp": now,
                "response_healthy": True,
                "isolation_started_at": self.isolation_started_at,
                "blocked_ips": self.blocked_ips,
                "actions": self.actions,
                "method": self.method,
                "_reader_cumulative_seen": self._reader_cumulative_seen,
            })
            return

        self.last_processed_key = new_key
        old_state = self.state_input
        self.state_input = state
        self.risk_input = risk

        attacker_ip = self._read_fresh_attacker_ip()
        if attacker_ip is None:
            attacker_ip = self.last_block or "0.0.0.0"

        self._execute_for_state(state, now, attacker_ip)

        _bb_update(self.response_section, {
            "source": self.name,
            "response_timestamp": now,
            "response_healthy": True,
            "state_input": self.state_input,
            "risk_input": self.risk_input,
            "actions": self.actions,
            "blocked_ips": self.blocked_ips,
            "last_block": self.last_block,
            "block_timestamp": self.block_timestamp,
            "method": self.method,
            "isolation_active": self.isolation_active,
            "isolation_rule_names": self.isolation_rule_names,
            "isolation_ports": self.isolation_ports,
            "isolation_started_at": self.isolation_started_at,
            "escalation_reason": self.escalation_reason,
            "service_ports": self.service_ports,
            "fail2ban": self.fail2ban,
            "last_processed_key": list(self.last_processed_key),
            "detail": {
                "input_source": source,
                "management_port": MANAGEMENT_PORT,
                "block_ceiling_seconds": BLOCK_CEILING_SECONDS,
                "state_transition": f"{old_state}->{state}",
            },
            "version": Config.SCHEMA_VERSION,
            "_reader_cumulative_seen": self._reader_cumulative_seen,
        })

        try:
            with open(Config.LOG_FILE, "a") as f:
                f.write(f"[{self.name}-RESP] {time.ctime()} | "
                        f"State: {state} | Risk: {risk} | "
                        f"Method: {self.method} | "
                        f"Blocks: {len(self.blocked_ips)} | "
                        f"Isolated: {self.isolation_active} | "
                        f"Source: {source}\n")
        except Exception:
            pass

        emit(SRC, LAYER, "info",
             f"Cycle {self.cycle_count} | source={source} state={state} "
             f"risk={risk} method={self.method} "
             f"blocks={len(self.blocked_ips)} "
             f"isolated={self.isolation_active}",
             capability=self.name)

    def release_all(self) -> None:
        now = time.time()
        survivors: List[Dict] = []
        for entry in self.blocked_ips:
            names = entry.get("rule_names") or []
            ok = True
            err = ""
            if names:
                ok, err = _action_release_rules_by_name(names)
            if ok:
                continue
            entry["last_release_error"] = err[:200]
            entry["last_release_attempt"] = now
            survivors.append(entry)
        self.blocked_ips = survivors

        if self.isolation_active:
            ok, err = _action_release_rules_by_name(
                self.isolation_rule_names)
            self._record_action(
                now, "release_isolation", "-",
                "netsh" if ok else "netsh_failed", err)
            if ok:
                self.isolation_active = False
                self.isolation_rule_names = []
                self.isolation_ports = []
                self.isolation_started_at = 0.0
                self.escalation_reason = ""

        _bb_update(self.response_section, {
            "blocked_ips": self.blocked_ips,
            "isolation_active": self.isolation_active,
            "isolation_rule_names": self.isolation_rule_names,
            "isolation_ports": self.isolation_ports,
            "isolation_started_at": self.isolation_started_at,
            "escalation_reason": self.escalation_reason,
            "actions": self.actions,
            "method": "released_on_shutdown"
            if not self.blocked_ips and not self.isolation_active
            else self.method,
        })


# ----------------------------------------------------------------------
# Engine
# ----------------------------------------------------------------------
class ResponseEngine:
    def __init__(self):
        self.workers: Dict[str, ResponseWorker] = {}
        self.distributed: Dict[str, DistributedResponse] = {}
        self.cycle_count = 0
        self._no_workers_warned_at = 0.0

    def _rebuild_workers(self, disabled_map: Dict):
        config = load_config()
        if not config:
            emit(SRC, LAYER, "error", "config empty; no workers")
            return
        names = _capabilities_for_layer(config, "layer4a")
        if not names:
            return

        for name in list(self.workers.keys()):
            if name not in names:
                emit(SRC, LAYER, "info",
                     f"{name} no longer assigned to layer4a; dropping",
                     capability=name)
                self.workers[name].release_all()
                del self.workers[name]
                dr = self.distributed.pop(name, None)
                if dr is not None:
                    dr.release_all()

        for name in names:
            existing = self.workers.get(name)
            if existing is None:
                continue
            wanted_sig = _config_signature_for(name, config)
            if existing.config_signature() == wanted_sig:
                existing.disabled_map = disabled_map
                continue
            emit(SRC, LAYER, "info",
                 f"{name} config changed; rebuilding worker",
                 capability=name)
            existing.release_all()
            del self.workers[name]
            dr = self.distributed.pop(name, None)
            if dr is not None:
                dr.release_all()

        for name in names:
            if name in self.workers:
                continue
            worker = ResponseWorker(name, disabled_map, config=config)
            self.workers[name] = worker
            emit(SRC, LAYER, "info",
                 f"worker attached (service_ports="
                 f"{worker.service_ports or 'none'}, "
                 f"fail2ban maxretry="
                 f"{worker.fail2ban['maxretry']} "
                 f"bantime={worker.fail2ban['bantime']}s)",
                 capability=name)
            if worker.service_ports:
                self.distributed[name] = DistributedResponse(
                    name, worker.service_ports, protocol="TCP")
                emit(SRC, LAYER, "info",
                     "distributed response attached",
                     capability=name)
            else:
                emit(SRC, LAYER, "info",
                     "no service ports; distributed response skipped",
                     capability=name)

    def _run_all(self):
        for name, worker in self.workers.items():
            try:
                worker.run_cycle()
            except Exception as e:
                emit(SRC, LAYER, "error", f"worker error: {e}",
                     capability=name)
        for name, dr in self.distributed.items():
            try:
                dr.update()
            except Exception as e:
                emit(SRC, LAYER, "error",
                     f"distributed response error: {e}",
                     capability=name)

    def _warn_no_workers(self):
        now = time.time()
        if now - self._no_workers_warned_at < 60.0:
            return
        self._no_workers_warned_at = now
        emit(SRC, LAYER, "warn",
             "no capabilities assigned to layer4a")

    def _release_all_workers(self):
        for worker in self.workers.values():
            try:
                worker.release_all()
            except Exception as e:
                emit(SRC, LAYER, "error",
                     f"release_all error: {e}",
                     capability=worker.name)
        for dr in self.distributed.values():
            try:
                dr.release_all()
            except Exception as e:
                emit(SRC, LAYER, "error",
                     f"distributed release_all error: {e}",
                     capability=dr.capability)

    def run(self):
        global _running, _last_cycle_time
        signal.signal(signal.SIGINT, _shutdown)
        signal.signal(signal.SIGTERM, _shutdown)
        emit(SRC, LAYER, "info",
             f"Response engine starting "
             f"(escalation ladder, "
             f"red_persist={RED_PERSISTENCE_BEFORE_ISOLATION_SECONDS}s, "
             f"distinct_attackers={RED_DISTINCT_ATTACKERS_BEFORE_ISOLATION})")
        threading.Thread(target=watchdog, daemon=True,
                          name="response_watchdog").start()
        try:
            while _running:
                if not _is_primary_instance(LAYER):
                    time.sleep(BASE_CYCLE_SECONDS)
                    continue
                _last_cycle_time = time.time()
                self.cycle_count += 1
                disabled_map = _read_disabled_map()
                try:
                    self._rebuild_workers(disabled_map)
                    self._run_all()
                except Exception as e:
                    emit(SRC, LAYER, "error",
                         f"engine cycle error: {e}")
                if not self.workers:
                    self._warn_no_workers()
                self._write_heartbeat()
                sleep_total = self._cycle_sleep()
                slept = 0.0
                while _running and slept < sleep_total:
                    time.sleep(0.5)
                    slept += 0.5
        finally:
            self._release_all_workers()
            self._remove_heartbeat()
            emit(SRC, LAYER, "info", "Response engine stopped")

    def _write_heartbeat(self):
        try:
            os.makedirs(os.path.dirname(HEARTBEAT_FILE), exist_ok=True)
            with open(HEARTBEAT_FILE, "w") as f:
                f.write(str(time.time()))
        except Exception:
            pass

    def _remove_heartbeat(self):
        try:
            if os.path.exists(HEARTBEAT_FILE):
                os.remove(HEARTBEAT_FILE)
        except Exception:
            pass

    def _cycle_sleep(self) -> float:
        data = _bb_read()
        states: List[str] = []
        for cap in self.workers.keys():
            sec = data.get(f"layer_3_state_{cap}")
            if isinstance(sec, dict):
                s = sec.get("state")
                if isinstance(s, str):
                    s_norm = s.strip().upper()
                    if s_norm in STATE_RANK:
                        states.append(s_norm)
        state = (max(states, key=lambda s: STATE_RANK[s])
                 if states else "GREEN")
        if state == "RED":
            return MIN_CYCLE_SECONDS
        if state == "ORANGE":
            return max(MIN_CYCLE_SECONDS, BASE_CYCLE_SECONDS // 2)
        if state == "YELLOW":
            return max(MIN_CYCLE_SECONDS,
                       int(BASE_CYCLE_SECONDS * 0.75))
        return min(MAX_CYCLE_SECONDS, BASE_CYCLE_SECONDS)


def watchdog():
    threshold = BASE_CYCLE_SECONDS * WATCHDOG_MULTIPLIER
    global _running
    while _running:
        time.sleep(threshold / 2)
        if not _running:
            return
        if time.time() - _last_cycle_time > threshold:
            emit(SRC, LAYER, "error",
                 f"watchdog: no progress in {threshold}s, "
                 f"requesting shutdown")
            _running = False
            return


def _shutdown(sig, frame):
    global _running
    emit(SRC, LAYER, "info", f"shutdown signal {sig}")
    _running = False


def main():
    if not os.path.exists(SYSTEM_CONFIG_FILE):
        emit(SRC, LAYER, "error",
             f"config not found at {SYSTEM_CONFIG_FILE}")
        sys.exit(1)
    if not os.path.exists(BLACKBOARD_FILE):
        emit(SRC, LAYER, "error",
             f"blackboard not found at {BLACKBOARD_FILE}")
        sys.exit(1)

    errors = _validate_thresholds()
    if errors:
        emit(SRC, LAYER, "error", "invalid hysteresis thresholds:")
        for e in errors:
            emit(SRC, LAYER, "error", f"  - {e}")
        sys.exit(1)

    if os.name != "nt":
        emit(SRC, LAYER, "warn",
             "response actions require Windows; "
             "engine will observe only")

    emit(SRC, LAYER, "info",
         f"config loaded from {SYSTEM_CONFIG_FILE}")
    engine = ResponseEngine()
    engine.run()


if __name__ == "__main__":
    main()