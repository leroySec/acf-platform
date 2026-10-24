# console/events.py
# ============================================================================
# CONSOLE EVENTS — Live event handler
# ============================================================================
# Purpose: receive events from the event router's reader thread and push
# them into the console's in-memory buffer. Nothing else.
#
# The buffer itself lives in console_state. This module does not own state.
# Rendering happens in views.py when the work area is drawn.
#
# This function is called from event_reader's background thread.
# It must return quickly. The reader thread cannot wait for the console.
#
# CONTRACT:
#   - A non-dict argument is silently ignored.
#   - The event is copied before storage; the caller may reuse or mutate
#     its own dict without affecting buffered events.
#   - Exceptions from console_state.add_event are not caught here.
#     The reader thread's own guard isolates the reader from such failures.
# ============================================================================

import time
from typing import Dict, Any

from . import state as console_state


def on_event(event: Dict[str, Any]):
    """
    Handle one event from the reader thread.

    The event_router already emits JSON objects, and event_reader already
    skips malformed lines. By the time we get here, `event` is expected
    to be a dict with at least 'src', 'layer', 'level', and 'msg'.

    A shallow copy is made so the buffer never shares a reference with
    the caller's dict. This makes the "no reuse" clause of the contract
    true by construction.

    If 'ts' is missing or non-numeric, it is backfilled with the current
    time so the views have something to display.
    """
    if not isinstance(event, dict):
        return

    event = dict(event)

    ts = event.get("ts")
    if not isinstance(ts, (int, float)) or ts <= 0:
        event["ts"] = time.time()

    console_state.add_event(event)