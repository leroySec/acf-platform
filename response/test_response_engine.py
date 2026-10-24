"""
Tests for response/response_engine.py — F1, F2, F3.

Manual task F1 — Release isolation regardless of OS locale.
Manual task F2 — Capture firewall policy before changing it.
Manual task F3 — Enforce a maximum duration on isolation.

These tests are written before the fixes are implemented.
They are expected to fail against the current code and pass
once the fixes are applied.
"""

import os
import sys
import time
import pytest
from unittest.mock import patch, MagicMock

PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)

from response import response_engine as re_mod


# ----------------------------------------------------------------------
# F2 — Capture firewall policy before changing it
# ----------------------------------------------------------------------

class TestReadFirewallPolicy:
    """F2. Must work on any OS language, not just English."""

    def _fake_run(self, stdout, returncode=0):
        m = MagicMock()
        m.returncode = returncode
        m.stdout = stdout
        m.stderr = ""
        return m

    def test_french_output_is_parsed(self):
        """French Windows output must be recognised."""
        french = (
            "Paramètres Profil de domaine\n"
            "Stratégie de pare-feu\n"
            "BlockInbound, AllowOutbound\n"
            "\n"
            "Paramètres Profil privé\n"
            "Stratégie de pare-feu\n"
            "BlockInbound, AllowOutbound\n"
            "\n"
            "Paramètres Profil public\n"
            "Stratégie de pare-feu\n"
            "BlockInbound, BlockOutbound\n"
        )
        with patch("subprocess.run", return_value=self._fake_run(french)):
            policy = re_mod._read_firewall_policy()

        assert "domainprofile" in policy
        assert "privateprofile" in policy
        assert "publicprofile" in policy
        assert "blockinbound" in policy["domainprofile"].lower()
        assert "allowoutbound" in policy["domainprofile"].lower()

    def test_english_output_is_parsed(self):
        """English Windows output must still work."""
        english = (
            "Domain Profile Settings:\n"
            "Firewall Policy    BlockInbound,AllowOutbound\n"
            "\n"
            "Private Profile Settings:\n"
            "Firewall Policy    BlockInbound,AllowOutbound\n"
            "\n"
            "Public Profile Settings:\n"
            "Firewall Policy    BlockInbound,AllowOutbound\n"
        )
        with patch("subprocess.run", return_value=self._fake_run(english)):
            policy = re_mod._read_firewall_policy()

        assert "domainprofile" in policy
        assert "privateprofile" in policy
        assert "publicprofile" in policy

    def test_empty_output_returns_empty_dict(self):
        with patch("subprocess.run", return_value=self._fake_run("")):
            policy = re_mod._read_firewall_policy()
        assert policy == {}

    def test_command_failure_returns_empty_dict(self):
        with patch("subprocess.run",
                   return_value=self._fake_run("", returncode=1)):
            policy = re_mod._read_firewall_policy()
        assert policy == {}


# ----------------------------------------------------------------------
# F1 — Release isolation regardless of OS locale
# ----------------------------------------------------------------------

class TestReleaseIsolation:
    """F1. A missing rule on any language must be treated as benign."""

    def test_all_rules_already_gone_returns_success(self):
        """
        Every delete returns the French 'no rule matches' message.
        The release must succeed because the rules are already gone.
        """
        rule_names = ["ACF_ISOLATE_OUT_123", "ACF_ISOLATE_IN_123"]
        saved_policy = {"domainprofile": "blockinbound,allowoutbound"}

        def fake_run(cmd, retry=True):
            return False, "Aucune règle ne correspond aux critères spécifiés."

        with patch.object(re_mod, "_run_command", side_effect=fake_run):
            ok, err = re_mod._action_release_isolation(
                rule_names, saved_policy)

        assert ok is True
        assert err == ""

    def test_real_failure_is_recorded(self):
        """A genuine 'access denied' must not be treated as benign."""
        rule_names = ["ACF_ISOLATE_OUT_123"]
        saved_policy = {}

        def fake_run(cmd, retry=True):
            return False, "Access denied."

        with patch.object(re_mod, "_run_command", side_effect=fake_run):
            ok, err = re_mod._action_release_isolation(
                rule_names, saved_policy)

        assert ok is False
        assert "access denied" in err.lower()

    def test_empty_saved_policy_skips_restore(self):
        """Rules deleted, no policy to restore: success, no errors."""
        rule_names = ["ACF_ISOLATE_OUT_123", "ACF_ISOLATE_IN_123"]
        saved_policy = {}

        with patch.object(re_mod, "_run_command", return_value=(True, "")):
            ok, err = re_mod._action_release_isolation(
                rule_names, saved_policy)

        assert ok is True
        assert err == ""


# ----------------------------------------------------------------------
# F3 — Enforce a maximum duration on isolation
# ----------------------------------------------------------------------

class TestIsolationCeiling:
    """F3. Isolation must never outlive PANIC_TIMEOUT_SECONDS."""

    def _make_worker(self, monkeypatch):
        """
        Construct a ResponseWorker without touching the real Blackboard.
        """
        monkeypatch.setattr(re_mod, "_bb_read_section", lambda s: {})
        monkeypatch.setattr(
            re_mod, "load_config",
            lambda: {"capability_layers": {"ssh": ["layer4a"]}},
        )
        return re_mod.ResponseWorker("ssh", {})

    def test_recent_isolation_is_not_released_early(self, monkeypatch):
        """
        Isolation just started, state still RED. The ceiling must not
        release. Only state de-escalation could, and here it does not.
        """
        worker = self._make_worker(monkeypatch)
        worker.isolation_active = True
        worker.isolation_started_at = time.time()   # just now
        worker.isolation_rule_names = ["ACF_ISOLATE_OUT_X"]
        worker.saved_firewall_policy = {}

        calls = []
        def fake_release(rn, sp):
            calls.append((list(rn), dict(sp)))
            return True, ""

        monkeypatch.setattr(re_mod, "_action_release_isolation",
                            fake_release)

        worker._release_expired(time.time(), "RED")
        assert calls == []
        assert worker.isolation_active is True

    def test_ceiling_release_fires_after_timeout(self, monkeypatch):
        """
        Isolation has outlived PANIC_TIMEOUT_SECONDS. Ceiling must
        release regardless of state.
        """
        worker = self._make_worker(monkeypatch)
        ceiling = getattr(re_mod.Config, "PANIC_TIMEOUT_SECONDS", 300)
        worker.isolation_active = True
        worker.isolation_started_at = time.time() - (ceiling + 100)
        worker.isolation_rule_names = ["ACF_ISOLATE_OUT_X"]
        worker.saved_firewall_policy = {}

        released = []
        def fake_release(rn, sp):
            released.append((list(rn), dict(sp)))
            return True, ""

        monkeypatch.setattr(re_mod, "_action_release_isolation",
                            fake_release)

        worker._release_expired(time.time(), "RED")
        assert len(released) == 1
        assert worker.isolation_active is False
        assert worker.isolation_rule_names == []
        assert worker.saved_firewall_policy == {}

    def test_missing_start_time_uses_now(self, monkeypatch):
        """
        Isolation active but no start time recorded (upgrade path).
        Must not release immediately; must record now and wait.
        """
        worker = self._make_worker(monkeypatch)
        worker.isolation_active = True
        # No isolation_started_at set
        worker.isolation_rule_names = ["ACF_ISOLATE_OUT_X"]
        worker.saved_firewall_policy = {}

        calls = []
        monkeypatch.setattr(
            re_mod, "_action_release_isolation",
            lambda rn, sp: (calls.append(rn), (True, ""))[1],
        )

        worker._release_expired(time.time(), "RED")
        assert calls == []
        assert worker.isolation_active is True

    def test_missing_config_ceiling_uses_default(self, monkeypatch):
        """
        If Config.PANIC_TIMEOUT_SECONDS is absent, the engine must
        still behave. Default 300s applies.
        """
        monkeypatch.delattr(re_mod.Config, "PANIC_TIMEOUT_SECONDS",
                            raising=False)
        worker = self._make_worker(monkeypatch)
        worker.isolation_active = True
        worker.isolation_started_at = time.time() - 400  # > 300 default

        released = []
        monkeypatch.setattr(
            re_mod, "_action_release_isolation",
            lambda rn, sp: (released.append(rn), (True, ""))[1],
        )
        worker._release_expired(time.time(), "RED")
        assert len(released) == 1
        assert worker.isolation_active is False