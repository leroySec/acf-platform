#!/usr/bin/env python3
"""
response/distributed_response.py — Layer 4a distributed response.

Layer 2 determines that a distributed behavior exists.
Layer 4a determines how that behavior can be represented by the
available enforcement primitive.

The enforcement primitive is a single Windows Firewall block rule
whose remoteip condition contains all participating source
addresses. The rule is scoped to the capability's service ports,
so the block follows the same capability-scoping rule the response
engine uses.

Responsibilities:
  - read distributed evidence (cross_source_by_user)
  - validate the behavior (must be user_attacked_from_many_sources)
  - validate freshness of that evidence
  - build the enforcement set (valid, deduplicated source IPs)
  - resolve capability scope (protocol, service ports)
  - create or update one logical rule per (capability, actor)
  - verify the rule exists on Windows
  - reconcile persisted state with actual firewall state on startup
  - expire and release rules according to response lifetime
  - publish into layer_4a_response_<cap>.distributed_actions

Not responsibilities:
  - classify behaviors
  - compute risk
  - map state to GREEN/YELLOW/ORANGE/RED
  - process raw events
  - cross-capability correlation

Rule identity is logical: capability + shared_actor.
    ACF_distributed_<cap>_<actor>_<hash8>

The hash suffix is derived from the raw actor string. Two actor
strings that sanitize to the same value cannot map to the same
rule.

The source set changes over time. The rule is updated in place,
not duplicated.

Persistence is reconciled with actual Windows Firewall state on
every startup. A persisted record is a claim of ownership, not
proof that the rule exists. The module verifies before assuming.

Freshness: the Layer 2 window is bounded (300 seconds). This
module refuses to act on evidence older than
MAX_DISTRIBUTED_EVIDENCE_AGE seconds.

Address family: a rule operates on one family. The first valid
source determines the family; sources of a different family are
dropped from the enforcement set rather than mixed into one rule.
"""
import hashlib
import ipaddress
import json
import os
import subprocess
import sys
import time
from typing import Any, Dict, List, Optional, Tuple

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from config import Config
from platform_utils import acquire_lock, release_lock, get_temp_dir

try:
    from event_emit import emit
except ImportError:
    def emit(src, layer, level, msg):
        ts = time.strftime("%H:%M:%S")
        print(f"[{ts}][{src}][{layer}][{level.upper()}] {msg}")

SRC = "distributed_response"
LAYER = "layer4a"

REQUIRED_BEHAVIOR = "user_attacked_from_many_sources"

DISTRIBUTED_SOURCE_THRESHOLD = 3

DISTRIBUTED_BLOCK_SECONDS = 3600

MAX_DISTRIBUTED_EVIDENCE_AGE = 60

MAX_SOURCES_PER_RULE = 64

MAX_DISTRIBUTED_ACTIONS = 200

_RULE_NAME_TEMPLATE = "ACF_distributed_{cap}_{actor}_{hash8}"

BLACKBOARD_FILE = Config.BLACKBOARD_FILE


# ----------------------------------------------------------------------
# Small helpers
# ----------------------------------------------------------------------
def _safe_str(v: Any, default: str = "") -> str:
    if isinstance(v, str):
        return v
    if v is None:
        return default
    return str(v)


def _safe_float(v: Any, default: float = 0.0) -> float:
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _sanitize_rule_component(s: str) -> str:
    out = []
    for c in s:
        if c.isalnum() or c in "._-":
            out.append(c)
        else:
            out.append("_")
    return "".join(out)[:40] or "x"


def _actor_hash8(actor: str) -> str:
    """Stable short hash of the raw actor string."""
    return hashlib.sha1(actor.encode("utf-8", errors="replace")).hexdigest()[:8]


def _rule_name_for(capability: str, actor: str) -> str:
    return _RULE_NAME_TEMPLATE.format(
        cap=_sanitize_rule_component(capability),
        actor=_sanitize_rule_component(actor),
        hash8=_actor_hash8(actor),
    )


def _address_family(ip_str: str) -> Optional[int]:
    """Return 4 or 6 for a parsable IP; None otherwise."""
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return None
    return ip.version


def _is_blockable_source(ip_str: str) -> bool:
    """Reject addresses that must never be blocked: loopback,
    unspecified, multicast, reserved. Private ranges are allowed on
    purpose; internal distributed activity is a valid case."""
    if not isinstance(ip_str, str) or not ip_str:
        return False
    if ip_str in ("0.0.0.0", "::"):
        return False
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    if ip.is_loopback or ip.is_multicast or ip.is_unspecified:
        return False
    if ip.is_reserved:
        return False
    return True


def _validate_and_dedupe(sources: List[Any]
                          ) -> Tuple[List[str], int, Optional[int]]:
    """
    Validate and deduplicate sources.

    Address-family check: the first valid source establishes the
    family for the enforcement set. Subsequent sources of a
    different family are dropped. This prevents building a single
    remoteip list that mixes IPv4 and IPv6.

    Returns (validated_sources, dropped_count, family) where family
    is 4 or 6, or None when no valid source exists.
    """
    seen = set()
    out: List[str] = []
    dropped = 0
    family: Optional[int] = None

    for s in sources:
        if not isinstance(s, str):
            continue
        if s in seen:
            continue
        if not _is_blockable_source(s):
            continue
        fam = _address_family(s)
        if fam is None:
            continue
        if family is None:
            family = fam
        elif fam != family:
            dropped += 1
            continue
        seen.add(s)
        out.append(s)

    return out, dropped, family


# ----------------------------------------------------------------------
# Blackboard I/O
# ----------------------------------------------------------------------
def _bb_read_section(section: str) -> Dict:
    try:
        with open(BLACKBOARD_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
    except Exception:
        return {}
    s = data.get(section, {})
    return s if isinstance(s, dict) else {}


def _bb_update(section: str, updates: Dict) -> bool:
    try:
        with open(BLACKBOARD_FILE, "r+", encoding="utf-8") as f:
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
        emit(SRC, LAYER, "error",
             f"Blackboard update for {section}: {e}")
        return False


# ----------------------------------------------------------------------
# Windows Firewall primitives
# ----------------------------------------------------------------------
def _run_netsh(args: List[str]) -> Tuple[bool, str]:
    try:
        r = subprocess.run(
            args, capture_output=True, text=True, timeout=15,
            encoding="utf-8", errors="replace", check=False,
        )
        if r.returncode == 0:
            return True, ""
        text = (r.stderr or r.stdout or "").strip()
        return False, text[:200]
    except Exception as e:
        return False, f"{type(e).__name__}: {e}"


def _run_ps(script: str, timeout: float = 15.0
            ) -> Tuple[bool, str, str]:
    try:
        r = subprocess.run(
            ["powershell.exe", "-NoProfile", "-NonInteractive",
             "-Command", script],
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
        return r.returncode == 0, (r.stdout or "").strip(), (r.stderr or "").strip()
    except Exception as e:
        return False, "", f"{type(e).__name__}: {e}"


def _check_rule_exists(rule_name: str) -> Optional[bool]:
    """
    Return True if present, False if absent, None if the state could
    not be determined. Queries by -Name, which is the stable
    machine-generated identity this module controls.
    """
    esc = rule_name.replace("'", "''")
    ps = (
        f"$r = Get-NetFirewallRule -Name '{esc}' "
        f"-ErrorAction SilentlyContinue; "
        f"if ($r) {{ 'FOUND' }} else {{ 'MISSING' }}"
    )
    ok, out, err = _run_ps(ps)
    if not ok:
        return None
    if "FOUND" in out:
        return True
    if "MISSING" in out:
        return False
    return None


def _build_add_rule_args(rule_name: str, sources: List[str],
                         protocol: str,
                         local_ports: List[int]) -> List[str]:
    args = [
        "netsh", "advfirewall", "firewall", "add", "rule",
        f"name={rule_name}",
        "dir=in", "action=block",
        f"protocol={protocol}",
    ]
    if local_ports:
        ports = ",".join(str(int(p)) for p in local_ports)
        args.append(f"localport={ports}")
    args.append(f"remoteip={','.join(sources)}")
    args.append("profile=any")
    return args


def _create_rule(rule_name: str, sources: List[str],
                 protocol: str,
                 local_ports: List[int]) -> Tuple[bool, str]:
    args = _build_add_rule_args(rule_name, sources, protocol, local_ports)
    ok, err = _run_netsh(args)
    if not ok:
        return False, err
    exists = _check_rule_exists(rule_name)
    if exists is not True:
        return False, "rule add returned ok but rule not found"
    return True, ""


def _delete_rule_verified(rule_name: str) -> Tuple[bool, str]:
    exists = _check_rule_exists(rule_name)
    if exists is False:
        return True, ""
    ok, err = _run_netsh([
        "netsh", "advfirewall", "firewall", "delete", "rule",
        f"name={rule_name}",
    ])
    if not ok:
        return False, err
    still = _check_rule_exists(rule_name)
    if still is True:
        return False, "rule still present after delete"
    if still is None:
        return False, "could not confirm delete"
    return True, ""


# ----------------------------------------------------------------------
# DistributedResponse — one instance per capability
# ----------------------------------------------------------------------
class DistributedResponse:
    """
    Owner of the distributed response for one capability.
    """

    def __init__(self, capability: str,
                 service_ports: List[int],
                 protocol: str = "TCP"):
        self.capability = capability
        self.service_ports = list(service_ports or [])
        self.protocol = protocol or "TCP"
        self.groups_section = f"layer_2_groups_{capability}"
        self.response_section = f"layer_4a_response_{capability}"
        self.actions: List[Dict] = []

        self._load_persisted_state()
        self._reconcile_actual_state()

    # ------------------------------------------------------------------
    # Persistence
    # ------------------------------------------------------------------
    def _load_persisted_state(self) -> None:
        section = _bb_read_section(self.response_section)
        existing = section.get("distributed_actions")
        if not isinstance(existing, list):
            return
        cleaned: List[Dict] = []
        for a in existing:
            if not isinstance(a, dict):
                continue
            name = a.get("rule_name")
            if not isinstance(name, str) or not name:
                continue
            sources = a.get("sources")
            if not isinstance(sources, list):
                sources = []
            cleaned.append({
                "shared_actor": _safe_str(a.get("shared_actor"), ""),
                "actor_kind": "user",
                "behavior": _safe_str(a.get("behavior"),
                                      REQUIRED_BEHAVIOR),
                "sources": [s for s in sources
                            if isinstance(s, str) and s],
                "source_count": int(a.get("source_count", 0) or 0),
                "enforced_source_count":
                    int(a.get("enforced_source_count", 0) or 0),
                "truncated": bool(a.get("truncated", False)),
                "family": int(a.get("family", 0) or 0),
                "first_seen": _safe_float(a.get("first_seen"), 0.0),
                "last_seen": _safe_float(a.get("last_seen"), 0.0),
                "rule_name": name,
                "scope": a.get("scope") or {
                    "protocol": self.protocol,
                    "local_ports": list(self.service_ports),
                },
                "installed_at": _safe_float(a.get("installed_at"), 0.0),
                "expires_at": _safe_float(a.get("expires_at"), 0.0),
                "status": "unknown",
                "verified": False,
            })
        self.actions = cleaned[-MAX_DISTRIBUTED_ACTIONS:]

    def _reconcile_actual_state(self) -> None:
        now = time.time()
        for a in self.actions:
            exists = _check_rule_exists(a["rule_name"])
            if exists is True:
                a["verified"] = True
                a["status"] = "active"
            elif exists is False:
                a["verified"] = False
                a["status"] = "missing"
                emit(self.capability, LAYER, "warn",
                     f"distributed rule missing on startup, will "
                     f"recreate if evidence is fresh: {a['rule_name']}")
            else:
                a["verified"] = False
                a["status"] = "unknown"
                emit(self.capability, LAYER, "warn",
                     f"could not verify distributed rule: "
                     f"{a['rule_name']}")
            a["reconciled_at"] = now

    # ------------------------------------------------------------------
    # Pruning
    # ------------------------------------------------------------------
    def _prune_expired(self, now: float) -> None:
        kept: List[Dict] = []
        for a in self.actions:
            expires = _safe_float(a.get("expires_at"), 0.0)
            if expires <= now:
                name = a["rule_name"]
                ok, err = _delete_rule_verified(name)
                if not ok:
                    a["status"] = "delete_failed"
                    a["delete_error"] = err[:200]
                    kept.append(a)
                    emit(self.capability, LAYER, "warn",
                         f"distributed delete failed for {name}: {err}")
                    continue
                emit(self.capability, LAYER, "info",
                     f"distributed rule expired: {name}")
                continue
            kept.append(a)
        self.actions = kept

    # ------------------------------------------------------------------
    # Lookup
    # ------------------------------------------------------------------
    def _find_action(self, actor: str) -> Optional[Dict]:
        for a in self.actions:
            if a.get("shared_actor") == actor:
                return a
        return None

    # ------------------------------------------------------------------
    # Create / update
    # ------------------------------------------------------------------
    def _record_new(self, actor: str, behavior: str,
                    sources: List[str], observed: int,
                    family: Optional[int],
                    first_seen: float, last_seen: float,
                    now: float) -> None:
        name = _rule_name_for(self.capability, actor)
        ok, err = _create_rule(
            name, sources, self.protocol, self.service_ports)
        entry = {
            "shared_actor": actor,
            "actor_kind": "user",
            "behavior": behavior,
            "sources": sources,
            "source_count": observed,
            "enforced_source_count": len(sources),
            "truncated": observed > len(sources),
            "family": int(family) if family else 0,
            "first_seen": first_seen,
            "last_seen": last_seen,
            "rule_name": name,
            "scope": {
                "protocol": self.protocol,
                "local_ports": list(self.service_ports),
            },
            "installed_at": now,
            "expires_at": now + DISTRIBUTED_BLOCK_SECONDS,
            "status": "active" if ok else "create_failed",
            "verified": ok,
        }
        if not ok:
            entry["error"] = err[:200]
        self.actions.append(entry)
        self.actions = self.actions[-MAX_DISTRIBUTED_ACTIONS:]
        if ok:
            emit(self.capability, LAYER, "info",
                 f"distributed block created | user={actor} "
                 f"sources={len(sources)} family=v{family} "
                 f"rule={name}")
        else:
            emit(self.capability, LAYER, "error",
                 f"distributed block failed | user={actor} "
                 f"rule={name} err={err}")

    def _record_update(self, action: Dict, sources: List[str],
                       observed: int, family: Optional[int],
                       first_seen: float, last_seen: float,
                       now: float) -> None:
        name = action["rule_name"]
        # Design choice: delete then re-add, rather than
        # netsh advfirewall firewall set rule. The set verb exists
        # and can change remoteip in place. Delete/add is used here
        # because it keeps the create and update paths identical and
        # verifiable by the same code. The cost is a brief window
        # between delete and add during which the rule is absent.
        # Accepted for the prototype; a future revision can switch
        # to set for continuous enforcement.
        ok_del, err_del = _delete_rule_verified(name)
        if not ok_del:
            action["status"] = "update_failed"
            action["update_error"] = f"delete: {err_del}"[:200]
            emit(self.capability, LAYER, "error",
                 f"distributed update delete failed for {name}: "
                 f"{err_del}")
            return
        ok_add, err_add = _create_rule(
            name, sources, self.protocol, self.service_ports)
        if not ok_add:
            action["status"] = "update_failed"
            action["update_error"] = f"add: {err_add}"[:200]
            action["verified"] = False
            emit(self.capability, LAYER, "error",
                 f"distributed update add failed for {name}: "
                 f"{err_add}")
            return
        action["sources"] = sources
        action["source_count"] = observed
        action["enforced_source_count"] = len(sources)
        action["truncated"] = observed > len(sources)
        action["family"] = int(family) if family else 0
        action["first_seen"] = first_seen
        action["last_seen"] = last_seen
        action["expires_at"] = now + DISTRIBUTED_BLOCK_SECONDS
        action["status"] = "active"
        action["verified"] = True
        action.pop("update_error", None)
        emit(self.capability, LAYER, "info",
             f"distributed block updated | user="
             f"{action['shared_actor']} sources={len(sources)} "
             f"family=v{family} rule={name}")

    def _publish(self, now: float) -> None:
        _bb_update(self.response_section, {
            "distributed_actions": self.actions,
            "distributed_count": len(self.actions),
            "distributed_threshold": DISTRIBUTED_SOURCE_THRESHOLD,
            "distributed_required_behavior": REQUIRED_BEHAVIOR,
            "distributed_evidence_max_age": MAX_DISTRIBUTED_EVIDENCE_AGE,
            "distributed_updated_at": now,
        })

    # ------------------------------------------------------------------
    # Cycle
    # ------------------------------------------------------------------
    def update(self) -> None:
        if not self.service_ports:
            return

        now = time.time()
        self._prune_expired(now)

        groups = _bb_read_section(self.groups_section)
        cross = groups.get("cross_source_by_user")
        if not isinstance(cross, list):
            self._publish(now)
            return

        for entry in cross:
            if not isinstance(entry, dict):
                continue
            actor = _safe_str(entry.get("user"), "")
            if not actor:
                continue
            behavior = _safe_str(entry.get("behavior"), "")
            if behavior != REQUIRED_BEHAVIOR:
                continue

            raw_sources = entry.get("sources")
            if not isinstance(raw_sources, list):
                continue
            validated, family_dropped, family = _validate_and_dedupe(
                raw_sources)
            observed = len(validated)
            if observed < DISTRIBUTED_SOURCE_THRESHOLD:
                continue

            enforced = validated[:MAX_SOURCES_PER_RULE]
            first_seen = _safe_float(entry.get("first_seen"), now)
            last_seen = _safe_float(entry.get("last_seen"), now)

            # Freshness gate.
            if last_seen <= 0 or (now - last_seen) > MAX_DISTRIBUTED_EVIDENCE_AGE:
                continue

            existing = self._find_action(actor)

            if existing is None:
                self._record_new(actor, behavior, enforced, observed,
                                 family, first_seen, last_seen, now)
                continue

            if not existing.get("verified", False):
                exists = _check_rule_exists(existing["rule_name"])
                if exists is True:
                    existing["verified"] = True
                    existing["status"] = "active"

            current = set(existing.get("sources") or [])
            desired = set(enforced)
            current_family = int(existing.get("family", 0) or 0)
            wanted_family = int(family) if family else 0
            if (current != desired
                    or current_family != wanted_family
                    or not existing.get("verified", False)):
                self._record_update(existing, enforced, observed,
                                    family, first_seen, last_seen, now)
            else:
                existing["last_seen"] = max(
                    _safe_float(existing.get("last_seen"), 0.0),
                    last_seen)
                existing["status"] = "active"

        self._publish(now)

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def release_all(self) -> None:
        survivors: List[Dict] = []
        for a in self.actions:
            name = a.get("rule_name")
            if not isinstance(name, str) or not name:
                continue
            ok, err = _delete_rule_verified(name)
            if not ok:
                a["status"] = "release_failed"
                a["release_error"] = err[:200]
                survivors.append(a)
                emit(self.capability, LAYER, "warn",
                     f"release failed for {name}: {err}")
            else:
                emit(self.capability, LAYER, "info",
                     f"released distributed rule: {name}")
        self.actions = survivors
        _bb_update(self.response_section, {
            "distributed_actions": self.actions,
            "distributed_count": len(self.actions),
            "distributed_released_at": time.time(),
        })