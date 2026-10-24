#!/usr/bin/env python3
"""
monitor/decoder.py — Decode a raw text item into named fields.

File sources only. Eventlog records are already structured and
bypass the decoder.

Decoder XML is parsed structurally with xml.etree.ElementTree.
Malformed XML refuses at construction with a named reason.
"""
import re
import xml.etree.ElementTree as ET

MAX_ITEM_LENGTH = 100_000


class Decoder:

    def __init__(self, capability, decoder_xml, declared=True):
        self.capability = capability
        self.declared = bool(declared)
        self._ready = False
        self._ready_reason = ""
        self._prematch = None
        self._regex = None
        self._order = []
        self._named = {}
        self._parse(decoder_xml)

    def _parse(self, xml):
        if not isinstance(xml, str) or not xml.strip():
            self._ready_reason = "decoder_xml_empty"
            return

        # Wrap bare decoder string as XML root if needed.
        src = xml.strip()
        if not src.startswith("<"):
            self._ready_reason = "decoder_xml_not_markup"
            return
        if not src.startswith("<decoder"):
            src = f"<decoder>{src}</decoder>"

        try:
            root = ET.fromstring(src)
        except ET.ParseError as e:
            self._ready_reason = f"decoder_xml_parse_error:{e}"
            return

        regex_elems = root.findall("regex")
        if len(regex_elems) != 1:
            self._ready_reason = f"decoder_regex_count:{len(regex_elems)}"
            return
        order_elems = root.findall("order")
        if len(order_elems) != 1:
            self._ready_reason = f"decoder_order_count:{len(order_elems)}"
            return
        prematch_elems = root.findall("prematch")

        regex_text = (regex_elems[0].text or "").strip()
        if not regex_text:
            self._ready_reason = "decoder_regex_empty"
            return
        try:
            self._regex = re.compile(regex_text)
        except re.error as e:
            self._ready_reason = f"decoder_regex_invalid:{e}"
            return

        order_text = (order_elems[0].text or "").strip()
        order = [f.strip() for f in order_text.split(",") if f.strip()]
        if not order:
            self._ready_reason = "decoder_order_empty"
            return
        if len(order) != len(set(order)):
            self._ready_reason = "decoder_order_duplicate"
            return

        if self._regex.groups != len(order):
            self._ready_reason = (
                f"decoder_arity:{self._regex.groups}_groups_"
                f"{len(order)}_order")
            return

        self._named = dict(self._regex.groupindex) if \
            self._regex.groupindex else {}
        if self._named:
            named_set = set(self._named)
            order_set = set(order)
            extra = named_set - order_set
            if extra:
                self._ready_reason = (
                    f"decoder_named_not_in_order:"
                    f"{','.join(sorted(extra))}")
                return
            for name, idx in self._named.items():
                if idx < 1 or idx > len(order) or order[idx - 1] != name:
                    self._ready_reason = (
                        f"decoder_named_mismatch:{name}_at_{idx}")
                    return

        if len(prematch_elems) > 1:
            self._ready_reason = (
                f"decoder_prematch_count:{len(prematch_elems)}")
            return
        if prematch_elems:
            ptext = (prematch_elems[0].text or "").strip()
            if ptext:
                try:
                    self._prematch = re.compile(ptext)
                except re.error as e:
                    self._ready_reason = f"decoder_prematch_invalid:{e}"
                    return

        self._order = order
        self._ready = True

    def ready(self):
        return self._ready, self._ready_reason

    def decode(self, item):
        if not self._ready:
            return None, f"decoder_not_ready:{self._ready_reason}"

        if not isinstance(item, str):
            return None, f"item_not_str:{type(item).__name__}"

        truncated = False
        if len(item) > MAX_ITEM_LENGTH:
            item = item[:MAX_ITEM_LENGTH]
            truncated = True

        if self._prematch is not None:
            try:
                if not self._prematch.search(item):
                    return None, "prematch_miss"
            except Exception as e:
                return None, f"prematch_error:{type(e).__name__}"

        try:
            m = self._regex.search(item)
        except Exception as e:
            return None, f"regex_error:{type(e).__name__}"

        if not m:
            return None, ("regex_miss_truncated" if truncated
                          else "regex_miss")

        record = {}
        for i, name in enumerate(self._order, start=1):
            record[name] = m.group(i)

        if "event_id" in record:
            raw = record["event_id"]
            if isinstance(raw, str):
                try:
                    record["event_id"] = int(raw)
                except (ValueError, TypeError):
                    pass

        if "src_ip" not in record:
            record["src_ip"] = None

        return record, ""