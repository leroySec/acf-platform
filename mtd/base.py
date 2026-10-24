#!/usr/bin/env python3
"""
mtd/base.py — The MTD action interface.

Every MTD action implements MTDAction. The engine treats all actions
uniformly: it calls the classmethod supports() to know whether the
action applies to a capability, then preflight() once, then
should_activate() every cycle, then activate()/deactivate() on
transitions, and status() to read back the current state.

Backward-compatibility contract:
  - No action writes to any Blackboard section other than the one the
    engine passes to it via status(). The engine owns the section.
  - No action imports or modifies any other ACF file.
  - No action changes the section name or the top-level keys the
    current mtd_engine.py already writes.
"""

import time
from abc import ABC, abstractmethod
from typing import Any, Dict, Tuple


# Preflight outcomes
STATUS_READY = "READY"
STATUS_BLOCKED = "BLOCKED"

# Preflight modes for STATUS_READY
MODE_PRIMARY = "A"       # the technique runs in its primary form
MODE_ADAPTED = "B"       # the environment forces a documented adaptation


class MTDAction(ABC):
    """
    One MTD action, applied per capability.

    Class attributes (set by each subclass):
      name           unique identifier, lowercase, underscore
      one_shot       True if activate() runs once and does not stay active
      requires_admin True if elevate required for any part of the action
    """

    name: str = "unnamed"
    one_shot: bool = False
    requires_admin: bool = False

    # ------------------------------------------------------------------
    # Capability matching
    # ------------------------------------------------------------------
    @classmethod
    @abstractmethod
    def supports(cls, capability: str, context: Dict[str, Any]) -> bool:
        """
        Return True if this action applies to the given capability.

        context contains at least:
          "capability"  — the capability name (ssh, sensor, ...)
          "log_path"    — path of the log the reader reads, or None
        """
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Lifecycle
    # ------------------------------------------------------------------
    def __init__(self, capability: str, context: Dict[str, Any]):
        self.capability = capability
        self.context = context
        self.created_at = time.time()
        self._preflight_status = STATUS_BLOCKED
        self._preflight_mode = ""
        self._preflight_reason = "not run"

    @abstractmethod
    def preflight(self) -> Tuple[str, str, str]:
        """
        Return (status, mode, reason).

        status is STATUS_READY or STATUS_BLOCKED.
        mode is MODE_PRIMARY or MODE_ADAPTED when status is READY,
        otherwise an empty string.
        reason is a human-readable message; empty on READY/MODE_PRIMARY.

        Called once at worker construction. The engine does not call an
        action whose preflight returned STATUS_BLOCKED.
        """
        raise NotImplementedError

    @abstractmethod
    def should_activate(self, state: str) -> bool:
        """
        Return True if, given the current security state, this action
        should be active.

        state is one of GREEN, YELLOW, ORANGE, RED.

        For one_shot actions, returning True means "run activate() this
        cycle". For non-one-shot actions, returning True means "be in
        the active state" and the engine keeps it active across cycles.
        """
        raise NotImplementedError

    @abstractmethod
    def is_active(self) -> bool:
        """
        Return True if the action is currently in its active state.

        For non-one-shot actions this must reflect reality, not intent.
        For one-shot actions this may always return False.
        """
        raise NotImplementedError

    @abstractmethod
    def activate(self) -> Tuple[bool, str]:
        """
        Perform the action. Return (ok, error).

        error is a short human-readable message, empty when ok is True.
        Must not raise; catch and convert to (False, message).

        Idempotent: calling activate() when already active must be safe.
        """
        raise NotImplementedError

    @abstractmethod
    def deactivate(self) -> Tuple[bool, str]:
        """
        Reverse the action. Return (ok, error).

        Must be safe to call when not active. Must not raise.
        For one-shot actions this may do nothing and return (True, "").
        """
        raise NotImplementedError

    @abstractmethod
    def status(self) -> Dict[str, Any]:
        """
        Return a JSON-serializable dict describing the action's state.

        The engine merges this dict under action_registry[name] in the
        section. Keys are action-specific. No key may collide with an
        existing top-level key the current mtd_engine.py writes.

        Must not raise.
        """
        raise NotImplementedError

    # ------------------------------------------------------------------
    # Preflight bookkeeping (called by the engine, not by the action)
    # ------------------------------------------------------------------
    def set_preflight(self, status: str, mode: str, reason: str) -> None:
        self._preflight_status = status
        self._preflight_mode = mode
        self._preflight_reason = reason

    @property
    def preflight_status(self) -> str:
        return self._preflight_status

    @property
    def preflight_mode(self) -> str:
        return self._preflight_mode

    @property
    def preflight_reason(self) -> str:
        return self._preflight_reason