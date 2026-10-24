#!/usr/bin/env python3
"""
mtd/port_registry.py — Single source of truth for MTD port allocations.

Every MTD action that binds, blocks, or redirects a port reads its
port numbers from this module. The invariant — that no two
(capability, role) pairs share a port — is stated as one predicate,
find_collision(), and verified against every representation of the
port data:

  - the registry defaults, checked at import;
  - the effective port map after config overrides, checked by any
    caller that has a parsed config.

The predicate reads the whole map, not a slice of it. Any check that
uses find_collision() verifies the full invariant by construction.
"""

from typing import Dict, Optional, Tuple


# ----------------------------------------------------------------------
# Authoritative allocations
# ----------------------------------------------------------------------
# Structure: {capability: {"primary": int|None,
#                          "alternate": int|None,
#                          "decoy": int|None}}
#
# None means "this role is not used for this capability."

ALLOCATIONS: Dict[str, Dict[str, Optional[int]]] = {
    "ssh": {
        "primary": 22,
        "alternate": 2222,
        "decoy": 2022,
    },
    "app_http": {
        "primary": 80,
        "alternate": 8080,
        "decoy": 8081,
    },
    "app_smtp": {
        "primary": 25,
        "alternate": 2587,
        "decoy": 2525,
    },
    "app_ftp": {
        "primary": 21,
        "alternate": 2187,
        "decoy": 2121,
    },
    "app_mysql": {
        "primary": 3306,
        "alternate": 3357,
        "decoy": 3307,
    },
    "sensor": {
        "primary": None,
        "alternate": None,
        "decoy": 2023,
    },
}


# ----------------------------------------------------------------------
# The invariant, stated once
# ----------------------------------------------------------------------
def find_collision(port_map: Dict[Tuple[str, str], int]
                   ) -> Optional[str]:
    """
    Return a description of the first port value that appears in more
    than one (capability, role) entry, or None if the map is
    collision-free.

    The predicate is the invariant. Every caller that wants to verify
    "no two roles share a port" calls this function against whichever
    map is currently authoritative. The predicate reads the whole
    map; it has no notion of a "capability" or "role" grouping that
    would let a caller check only part of the data.
    """
    seen: Dict[int, Tuple[str, str]] = {}
    for key, port in port_map.items():
        if port in seen:
            other = seen[port]
            return (f"port {port} assigned to "
                    f"{key[0]}.{key[1]} and to "
                    f"{other[0]}.{other[1]}")
        seen[port] = key
    return None


# ----------------------------------------------------------------------
# The two representations of the port data
# ----------------------------------------------------------------------
def default_port_map() -> Dict[Tuple[str, str], int]:
    """
    Return {(capability, role): port} for every non-None allocation
    in ALLOCATIONS. This is the registry's own representation.
    """
    out: Dict[Tuple[str, str], int] = {}
    for cap, roles in ALLOCATIONS.items():
        for role, port in roles.items():
            if isinstance(port, int) and port > 0:
                out[(cap, role)] = port
    return out


def effective_port_map(config: Dict) -> Dict[Tuple[str, str], int]:
    """
    Return {(capability, role): port} with the config's shuffle
    overrides applied to the primary and alternate roles. Decoy
    ports and any other role use the registry defaults; there is no
    override path for them today.

    config is the parsed system_config.json dict. If it lacks
    capability_rules or the per-capability shuffle block, the
    defaults are returned unchanged.

    This is the representation that matters at runtime: an operator
    override is part of the effective port map whether or not the
    registry's defaults would have collided.
    """
    out = default_port_map()

    if not isinstance(config, dict):
        return out
    rules = config.get("capability_rules", {})
    if not isinstance(rules, dict):
        return out

    for cap in ALLOCATIONS:
        entry = rules.get(cap)
        if not isinstance(entry, dict):
            continue
        shuffle = entry.get("shuffle")
        if not isinstance(shuffle, dict):
            continue
        for role, key in (("primary", "primary_port"),
                          ("alternate", "alternate_port")):
            if key not in shuffle:
                continue
            try:
                v = int(shuffle[key])
            except (TypeError, ValueError):
                continue
            if 1 <= v <= 65535:
                out[(cap, role)] = v

    return out


# ----------------------------------------------------------------------
# Import-time check against the defaults
# ----------------------------------------------------------------------
_default_collision = find_collision(default_port_map())
if _default_collision:
    raise RuntimeError(
        f"port_registry: {_default_collision}. "
        f"Edit ALLOCATIONS in mtd/port_registry.py so every port "
        f"value is unique across all capabilities and roles.")


# ----------------------------------------------------------------------
# Public accessors
# ----------------------------------------------------------------------
def primary_port(capability: str) -> int:
    entry = ALLOCATIONS.get(capability)
    if not isinstance(entry, dict):
        return 0
    p = entry.get("primary")
    return int(p) if isinstance(p, int) and p > 0 else 0


def alternate_port(capability: str) -> int:
    entry = ALLOCATIONS.get(capability)
    if not isinstance(entry, dict):
        return 0
    p = entry.get("alternate")
    return int(p) if isinstance(p, int) and p > 0 else 0


def decoy_port(capability: str) -> int:
    entry = ALLOCATIONS.get(capability)
    if not isinstance(entry, dict):
        return 0
    p = entry.get("decoy")
    return int(p) if isinstance(p, int) and p > 0 else 0


def all_roles(capability: str) -> Dict[str, int]:
    entry = ALLOCATIONS.get(capability)
    if not isinstance(entry, dict):
        return {}
    out: Dict[str, int] = {}
    for role, port in entry.items():
        if isinstance(port, int) and port > 0:
            out[role] = port
    return out


def capabilities() -> list:
    return list(ALLOCATIONS.keys())