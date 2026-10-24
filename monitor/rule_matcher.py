#!/usr/bin/env python3
"""
monitor/rule_matcher.py — Decide whether a decoded record qualifies.

FIX: single source of truth for event_id — the record carries it.
No source_event_id parameter. Every consumer reads record["event_id"].

Invalid rules rejected at construction. event_id rules that cannot
fire because the record lacks event_id return a declared reason.
"""
import re


class RuleMatcher:

    def __init__(self, capability, rules):
        self.capability = capability
        self._rules = []
        self._inert = 0
        self._invalid = 0
        self._config_reason = ""
        self._any_event_id_rule = False

        if not isinstance(rules, list):
            self._config_reason = f"rules_not_list:{type(rules).__name__}"
            return

        for r in rules:
            compiled = self._compile(r)
            if compiled is None:
                self._invalid += 1
            elif compiled.get("inert"):
                self._inert += 1
            else:
                self._rules.append(compiled)
                if compiled.get("event_id") is not None:
                    self._any_event_id_rule = True

    def _compile(self, rule):
        if not isinstance(rule, dict):
            return None

        event_id = rule.get("event_id")
        field = rule.get("field")
        regex = rule.get("regex")
        match = rule.get("match")

        eid = None
        if event_id is not None:
            if isinstance(event_id, bool):
                return None
            if isinstance(event_id, int):
                eid = event_id
            elif isinstance(event_id, str):
                try:
                    eid = int(event_id)
                except (ValueError, TypeError):
                    return None
            else:
                return None

        if field is not None and not isinstance(field, str):
            return None

        cr = None
        if regex is not None:
            if not isinstance(regex, str) or not regex:
                return None
            try:
                cr = re.compile(regex)
            except re.error:
                return None

        cm = None
        if match is not None:
            if not isinstance(match, str) or not match:
                return None
            try:
                cm = re.compile(match)
            except re.error:
                return None

        has_criterion = (eid is not None or cr is not None or cm is not None)
        if not has_criterion:
            return {"inert": True}

        return {
            "event_id": eid,
            "field": field,
            "regex": cr,
            "match": cm,
        }

    def _coerce_eid(self, value):
        """Return (int_or_None, str_or_None)."""
        if value is None:
            return None, None
        if isinstance(value, bool):
            return None, None
        if isinstance(value, int):
            return value, str(value)
        if isinstance(value, str):
            try:
                return int(value), value
            except (ValueError, TypeError):
                return None, value
        return None, None

    def match(self, record):
        """
        Returns (qualifies, reason).
        record is a dict. event_id is read from record["event_id"].
        """
        if self._config_reason:
            return False, self._config_reason
        if not self._rules:
            if self._inert:
                return False, f"all_rules_inert:{self._inert}"
            if self._invalid:
                return False, f"all_rules_invalid:{self._invalid}"
            return False, "no_rules_configured"
        if not isinstance(record, dict):
            return False, f"record_not_dict:{type(record).__name__}"

        src_int, src_str = self._coerce_eid(record.get("event_id"))

        if self._any_event_id_rule and src_int is None and src_str is None:
            eid_rules = [r for r in self._rules
                         if r["event_id"] is not None]
            non_eid = [r for r in self._rules
                       if r["event_id"] is None]
            if eid_rules and not non_eid:
                return False, "event_id_absent_in_record"

        any_field_missing = False
        for rule in self._rules:
            if rule["event_id"] is not None:
                if src_int is not None and src_int == rule["event_id"]:
                    return True, ""
                if src_str is not None and src_str == str(rule["event_id"]):
                    return True, ""
                continue

            field = rule["field"]
            if field is not None:
                if field not in record:
                    any_field_missing = True
                    continue
                value = record[field]
            else:
                value = " ".join(
                    str(v) for v in record.values() if v is not None)

            if not isinstance(value, str):
                try:
                    value = str(value)
                except Exception:
                    continue

            if rule["regex"] is not None:
                try:
                    if rule["regex"].search(value):
                        return True, ""
                except Exception:
                    pass
            if rule["match"] is not None:
                try:
                    if rule["match"].search(value):
                        return True, ""
                except Exception:
                    pass

        if any_field_missing:
            return False, "rule_field_absent_in_record"
        return False, ""