#!/usr/bin/env python3
"""
monitor/reader_consumer.py — Consume reader_<cap>, hand items forward.

Deduplicates on recent_events_ts (written only when new events arrive)
rather than on reading_timestamp (written every cycle).
"""
import math

MAX_ITEMS_PER_CYCLE = 5000


def _validate_number(v, name):
    if isinstance(v, bool):
        return 0.0, f"{name}_is_bool"
    if not isinstance(v, (int, float)):
        return 0.0, f"{name}_not_numeric"
    f = float(v)
    if math.isnan(f):
        return 0.0, f"{name}_is_nan"
    if math.isinf(f):
        return 0.0, f"{name}_is_inf"
    return f, ""


class ReaderConsumer:

    def __init__(self, capability, section_name, reader_fresh_seconds):
        self.capability = capability
        self.section = section_name

        fs, reason = _validate_number(reader_fresh_seconds,
                                      "reader_fresh_seconds")
        if reason or fs <= 0:
            self.reader_fresh_seconds = 30.0
            self._init_reason = (
                f"reader_fresh_seconds:{reason or 'non_positive'}")
        else:
            self.reader_fresh_seconds = fs
            self._init_reason = ""

        self._last_reading_timestamp = None

    def consume(self, read_section, now):
        try:
            section = read_section(self.section)
        except Exception as e:
            return [], "", f"read_section_raised:{type(e).__name__}"

        if not isinstance(section, dict):
            return [], "", f"section:not_dict:{type(section).__name__}"

        if section.get("reader_ready") is not True:
            return [], "", "reader_not_ready"

        # Liveness check: reading_timestamp is updated every cycle
        liveness_ts, reason = _validate_number(
            section.get("reading_timestamp"), "reading_timestamp")
        if reason:
            return [], "", f"timestamp:{reason}"

        if liveness_ts > now:
            return [], "", "timestamp_in_future"
        if liveness_ts <= 0:
            return [], "", "timestamp_non_positive"
        if (now - liveness_ts) > self.reader_fresh_seconds:
            return [], "", "reader_stale"

        backend = section.get("backend", "")
        if not isinstance(backend, str):
            return [], "", f"backend:not_str:{type(backend).__name__}"
        if backend not in ("file", "eventlog"):
            return [], "", f"backend_unknown:{backend!r}"

        # Dedup on recent_events_ts when present, otherwise liveness_ts.
        raw_events_ts = section.get("recent_events_ts")
        if raw_events_ts is not None:
            events_ts, _ = _validate_number(raw_events_ts,
                                            "recent_events_ts")
            if events_ts <= 0:
                events_ts = liveness_ts
        else:
            events_ts = liveness_ts

        # Already consumed this batch
        if (self._last_reading_timestamp is not None
                and events_ts <= self._last_reading_timestamp):
            return [], backend, ""

        if backend == "file":
            raw = section.get("recent_lines")
            if raw is None:
                return [], backend, "items:is_none"
            if not isinstance(raw, list):
                return [], backend, f"items:not_list:{type(raw).__name__}"
            items = [x for x in raw if isinstance(x, str)]
            non_str = len(raw) - len(items)
            if len(items) > MAX_ITEMS_PER_CYCLE:
                items = items[:MAX_ITEMS_PER_CYCLE]
            if not items and non_str > 0:
                return [], backend, f"items:all_non_str:{non_str}"
            self._last_reading_timestamp = events_ts
            return items, backend, ""

        # Eventlog: structured records
        raw = section.get("recent_events")
        if raw is None:
            return [], backend, "items:is_none"
        if not isinstance(raw, list):
            return [], backend, f"items:not_list:{type(raw).__name__}"
        items = [x for x in raw if isinstance(x, dict)]
        non_dict = len(raw) - len(items)
        if len(items) > MAX_ITEMS_PER_CYCLE:
            items = items[:MAX_ITEMS_PER_CYCLE]
        if not items and non_dict > 0:
            return [], backend, f"items:all_non_dict:{non_dict}"
        self._last_reading_timestamp = events_ts
        return items, backend, ""

    def status(self):
        return {
            "last_reading_timestamp": self._last_reading_timestamp,
            "init_reason": self._init_reason,
        }