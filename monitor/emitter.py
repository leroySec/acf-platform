#!/usr/bin/env python3
"""
monitor/emitter.py — Sole writer for layer_1_monitor_<cap>.

FIX (SRC_IP): Promote ips[0] to src_ip when src_ip is missing or is the
placeholder "0.0.0.0". Reader-produced eventlog records carry source IPs
in `ips` (list) but no `src_ip` field; downstream AIS grouper requires
`src_ip` (single string) to form source groups.
"""

_PERMITTED_KEYS = frozenset({
    "detections", "events",
    "last_failures", "last_failures_cumulative",
    "last_attacker_ip", "detail",
    "monitor_healthy", "monitor_healthy_reason",
    "source", "monitoring_timestamp",
    "collector_source", "version",
    "_collector_state",
})


class Emitter:

    def __init__(self, capability, section_name, schema_version):
        self.capability = capability
        self.section = section_name
        self.schema_version = schema_version

    def emit(self, write_and_readback, now,
             decoded_items, qualifying_records,
             cumulative_before, monitor_healthy,
             reason, source_type,
             detail=None, attacker_ip="0.0.0.0",
             extra_state=None):

        if not isinstance(decoded_items, list):
            try:
                decoded_items = list(decoded_items)
            except Exception:
                decoded_items = []
        if not isinstance(qualifying_records, list):
            try:
                qualifying_records = list(qualifying_records)
            except Exception:
                qualifying_records = []

        if isinstance(cumulative_before, bool) \
                or not isinstance(cumulative_before, int):
            cumulative_before = 0
        if not isinstance(monitor_healthy, bool):
            monitor_healthy = False

        normalized_events = []
        for e in decoded_items:
            if isinstance(e, dict):
                normalized_events.append(e)
            elif isinstance(e, str):
                normalized_events.append({"raw": e})

        detections = []
        for rec in qualifying_records:
            if not isinstance(rec, dict):
                if isinstance(rec, str):
                    detections.append({"raw": rec,
                                       "src_ip": "0.0.0.0",
                                       "src_ip_reason":
                                       "source_not_identifiable"})
                continue
            det = dict(rec)
            src = det.get("src_ip")
            if not isinstance(src, str) or not src or src == "0.0.0.0":
                # Promote ips[0] when src_ip is missing or placeholder.
                promoted = None
                ips = det.get("ips")
                if isinstance(ips, list):
                    for candidate in ips:
                        if isinstance(candidate, str) and candidate \
                                and candidate not in ("0.0.0.0", "::"):
                            promoted = candidate
                            break
                if promoted:
                    det["src_ip"] = promoted
                    det.pop("src_ip_reason", None)
                else:
                    det["src_ip"] = "0.0.0.0"
                    det["src_ip_reason"] = "source_not_identifiable"
            detections.append(det)

        new_cumulative = cumulative_before + len(detections)
        reason_value = reason or ("unspecified"
                                  if not monitor_healthy else "")

        update = {
            "detections":               detections,
            "events":                   normalized_events,
            "last_failures":            len(detections),
            "last_failures_cumulative": new_cumulative,
            "last_attacker_ip":         (attacker_ip
                                         if isinstance(attacker_ip, str)
                                         else "0.0.0.0"),
            "detail":                   (detail
                                         if isinstance(detail, dict)
                                         else {}),
            "monitor_healthy":          monitor_healthy,
            "monitor_healthy_reason":   reason_value,
            "source":                   self.capability,
            "monitoring_timestamp":     now,
            "collector_source":         source_type,
            "version":                  self.schema_version,
        }
        if isinstance(extra_state, dict):
            update["_collector_state"] = extra_state

        unexpected = set(update.keys()) - _PERMITTED_KEYS
        if unexpected:
            return cumulative_before, (
                f"write:unexpected_keys:{sorted(unexpected)}")

        try:
            ok, readback, err = write_and_readback(self.section, update)
        except Exception as e:
            return cumulative_before, f"write_exception:{type(e).__name__}"

        if not ok:
            return cumulative_before, f"write_failed:{err}"

        if not isinstance(readback, dict):
            return cumulative_before, "readback:not_dict"

        rb_detections = readback.get("detections")
        if not isinstance(rb_detections, list):
            return cumulative_before, \
                f"readback:detections_not_list:{type(rb_detections).__name__}"
        rb_events = readback.get("events")
        if not isinstance(rb_events, list):
            return cumulative_before, \
                f"readback:events_not_list:{type(rb_events).__name__}"
        rb_cumulative = readback.get("last_failures_cumulative")
        if isinstance(rb_cumulative, bool) or not isinstance(rb_cumulative, int):
            return cumulative_before, \
                f"readback:cumulative_not_int:{type(rb_cumulative).__name__}"
        rb_health = readback.get("monitor_healthy")
        if not isinstance(rb_health, bool):
            return cumulative_before, \
                f"readback:health_not_bool:{type(rb_health).__name__}"
        rb_ts = readback.get("monitoring_timestamp")
        if not isinstance(rb_ts, (int, float)) or isinstance(rb_ts, bool):
            return cumulative_before, \
                f"readback:timestamp_not_number:{type(rb_ts).__name__}"

        if rb_ts != now:
            return cumulative_before, "readback:timestamp_mismatch"
        if rb_health != monitor_healthy:
            return cumulative_before, "readback:health_mismatch"
        if readback.get("monitor_healthy_reason", "") != reason_value:
            return cumulative_before, "readback:reason_mismatch"
        if len(rb_detections) != len(detections):
            return cumulative_before, "readback:detections_mismatch"
        if len(rb_events) != len(normalized_events):
            return cumulative_before, "readback:events_mismatch"
        if rb_cumulative != new_cumulative:
            return cumulative_before, "readback:cumulative_mismatch"

        return new_cumulative, ""