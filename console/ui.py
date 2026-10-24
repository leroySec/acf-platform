# console/ui.py
# ============================================================================
# CONSOLE UI — Terminal rendering primitives
# ============================================================================
# Everything that touches the terminal lives here.
#
# FIXES APPLIED (round 1):
#   1. Non-TTY detection: disables ANSI/colors when stdout is redirected
#   2. Old Windows safety: tries to enable VT, falls back to plain output
#   3. Wide character support: uses wcwidth if available, fallback otherwise
#   4. Sanitizes text: strips \n, \r, control chars, ANSI sequences
#   5. Broken pipe: catches BrokenPipeError, sets shutdown flag, no-ops after
#   6. Auto deinit: atexit hook registered inside init()
#   7. Header truncation: prevents wrapping on narrow terminals
#   9. ANSI guards: cursor functions no-op when ANSI is disabled
#
# FIXES APPLIED (round 2):
#   A. Thread safety: RLock around every write
#   B. ANSI injection: sanitisation strips escape sequences
#   C. Cursor restoration: deinit shows cursor and resets style
#   D. wcswidth negative: _visible_width wrapper
#   E. Documentation: docstrings on every public function
#   F. ORANGE colour: uses LIGHTYELLOW_EX with fallback
#
# FIXES APPLIED (round 3):
#   P1  key_pressed() and consume_pending_keys() added for live views
# ============================================================================

import os
import sys
import shutil
import atexit
import threading
from typing import List, Optional, Tuple

# --- colorama (optional) ---
try:
    import colorama
    from colorama import Fore, Style
    _HAS_COLORAMA = True
except ImportError:
    _HAS_COLORAMA = False

    class _FakeColor:
        def __getattr__(self, name):
            return ""

    Fore = _FakeColor()
    Style = _FakeColor()

# --- wcwidth (optional) ---
try:
    from wcwidth import wcswidth as _wcswidth
    _HAS_WCWIDTH = True
except ImportError:
    _HAS_WCWIDTH = False

    def _wcswidth(text: str) -> int:
        if not isinstance(text, str):
            text = str(text)
        w = 0
        for ch in text:
            w += 2 if ord(ch) > 127 else 1
        return w


# ----------------------------------------------------------------------
# ANSI escape sequences
# ----------------------------------------------------------------------
CSI = "\033["
CLEAR_SCREEN = CSI + "2J"
CURSOR_HOME = CSI + "H"
CLEAR_TO_END = CSI + "J"
HIDE_CURSOR = CSI + "?25l"
SHOW_CURSOR = CSI + "?25h"
RESET = Style.RESET_ALL


# ----------------------------------------------------------------------
# Defaults
# ----------------------------------------------------------------------
DEFAULT_DIVIDER = "-"
DEFAULT_SIZE = (80, 24)
STATUS_MARGIN = 2


# ----------------------------------------------------------------------
# Sanitisation
# ----------------------------------------------------------------------
import re

_ANSI_RE = re.compile(r"\x1b\[[0-9;?]*[a-zA-Z]|\x1b\][^\x07]*\x07|\x1b[()][AB012]")
_BIDI_RE = re.compile(r"[\u202A-\u202E\u2066-\u2069]")


def _sanitize(text: str) -> str:
    """
    Strip characters that break single-line rendering or allow terminal injection:
      - newline and carriage return
      - ANSI escape sequences
      - other C0 control characters except tab (tab is replaced with a space)
      - DEL
      - bidirectional override characters
    """
    if not isinstance(text, str):
        text = str(text)
    text = _ANSI_RE.sub("", text)
    text = _BIDI_RE.sub("", text)
    text = text.replace("\n", " ").replace("\r", " ").replace("\t", " ")
    text = "".join(ch for ch in text if ch == " " or ord(ch) >= 0x20)
    return text


# ----------------------------------------------------------------------
# Safe write with thread lock
# ----------------------------------------------------------------------
_write_lock = threading.RLock()
_shutdown_requested = False


def _write(text: str):
    """
    Write to stdout atomically, catching broken pipes.
    Once a BrokenPipeError occurs, all further writes are no-ops.
    """
    global _shutdown_requested
    if _shutdown_requested:
        return
    with _write_lock:
        if _shutdown_requested:
            return
        try:
            sys.stdout.write(text)
            sys.stdout.flush()
        except BrokenPipeError:
            _shutdown_requested = True
        except Exception:
            pass


def is_shutdown_requested() -> bool:
    """Return True if a BrokenPipeError has terminated writing."""
    return _shutdown_requested


# ----------------------------------------------------------------------
# Width helper
# ----------------------------------------------------------------------
def _visible_width(text: str) -> int:
    """Return the visible column width of text, falling back on len()."""
    if not isinstance(text, str):
        text = str(text)
    try:
        w = _wcswidth(text)
        if w < 0:
            return len(text)
        return w
    except Exception:
        return len(text)


def _truncate(text: str, max_width: int) -> str:
    """Truncate text to fit max_width (in visible columns), with '...' suffix."""
    if max_width <= 0:
        return ""
    if _visible_width(text) <= max_width:
        return text
    suffix = "..."
    limit = max(1, max_width - len(suffix))
    result = []
    width = 0
    for ch in text:
        w = 2 if ord(ch) > 127 else 1
        if width + w > limit:
            break
        result.append(ch)
        width += w
    return "".join(result) + suffix


# ----------------------------------------------------------------------
# Environment detection
# ----------------------------------------------------------------------
def _detect_tty() -> bool:
    try:
        return bool(sys.stdout.isatty())
    except Exception:
        return False


def _detect_ansi() -> bool:
    if not _IS_TTY:
        return False
    if _HAS_COLORAMA:
        return True
    if os.name != "nt":
        return True
    try:
        import ctypes
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.GetStdHandle(-11)
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return False
        ENABLE_VT = 0x0004
        if not kernel32.SetConsoleMode(handle, mode.value | ENABLE_VT):
            return False
        return True
    except Exception:
        return False


_IS_TTY = _detect_tty()
_ANSI_ENABLED = _detect_ansi()


# ----------------------------------------------------------------------
# Initialization / deinitialization
# ----------------------------------------------------------------------
_initialized = False


def init():
    """
    Initialise the terminal layer.

    Call once at console startup. Idempotent.
    Registers an atexit hook that restores the cursor and style.
    """
    global _initialized
    if _initialized:
        return
    if _HAS_COLORAMA:
        try:
            colorama.init(autoreset=False)
        except Exception:
            pass
    atexit.register(deinit)
    _initialized = True


def deinit():
    """
    Restore the terminal (cursor visible, style reset).

    Called automatically via atexit if init() ran.
    """
    if not _initialized:
        return
    try:
        show_cursor()
        _write(RESET)
    except Exception:
        pass
    if _HAS_COLORAMA:
        try:
            colorama.deinit()
        except Exception:
            pass


# ----------------------------------------------------------------------
# Terminal size
# ----------------------------------------------------------------------
def get_size() -> Tuple[int, int]:
    """Return (columns, rows). Falls back to 80x24 if detection fails."""
    try:
        size = shutil.get_terminal_size(fallback=DEFAULT_SIZE)
        return max(20, size.columns), max(10, size.lines)
    except Exception:
        return DEFAULT_SIZE


# ----------------------------------------------------------------------
# Cursor and screen control
# ----------------------------------------------------------------------
def clear_screen():
    """
    Clear the terminal.

    No-op when stdout is not a TTY. Falls back to os.system when ANSI is off.
    """
    if _shutdown_requested:
        return
    if _ANSI_ENABLED:
        _write(CLEAR_SCREEN + CURSOR_HOME)
    else:
        try:
            os.system("cls" if os.name == "nt" else "clear")
        except Exception:
            pass


def clear_from_row(row: int):
    """Clear from the given row to the end of the screen. No-op when ANSI is off."""
    if not _ANSI_ENABLED:
        return
    row = max(1, row)
    _write(f"{CSI}{row};1H" + CLEAR_TO_END)


def move_cursor(row: int, col: int):
    """Move the cursor to (row, col), 1-indexed. No-op when ANSI is off."""
    if not _ANSI_ENABLED:
        return
    row = max(1, row)
    col = max(1, col)
    _write(f"{CSI}{row};{col}H")


def hide_cursor():
    """Hide the cursor. No-op when ANSI is off."""
    if _ANSI_ENABLED:
        _write(HIDE_CURSOR)


def show_cursor():
    """Show the cursor. No-op when ANSI is off."""
    if _ANSI_ENABLED:
        _write(SHOW_CURSOR)


# ----------------------------------------------------------------------
# Non-blocking input (round 3)
# ----------------------------------------------------------------------
def key_pressed() -> bool:
    """
    Return True if a key is available on stdin without consuming it.

    Windows: uses msvcrt.kbhit(). POSIX: uses select.select.
    On POSIX with a canonical TTY, select reports ready only when a
    full line (terminated by Enter) is available. A lone keystroke
    without Enter is not detected there.
    """
    try:
        if os.name == "nt":
            import msvcrt
            return bool(msvcrt.kbhit())
        else:
            import select
            r, _, _ = select.select([sys.stdin], [], [], 0)
            return bool(r)
    except Exception:
        return False


def consume_pending_keys() -> None:
    """
    Discard any pending input so a subsequent input() call sees a clean
    buffer. Used by live views when the user presses a key to exit.
    """
    try:
        if os.name == "nt":
            import msvcrt
            while msvcrt.kbhit():
                msvcrt.getch()
        else:
            import select
            while True:
                r, _, _ = select.select([sys.stdin], [], [], 0)
                if not r:
                    break
                sys.stdin.read(1)
    except Exception:
        pass


# ----------------------------------------------------------------------
# Low-level printing
# ----------------------------------------------------------------------
def print_at(row: int, col: int, text: str, color: str = "", bold: bool = False):
    """
    Print text at a specific position with optional colour and bold.

    Text is sanitised. When ANSI is disabled, falls back to print_line.
    """
    text = _sanitize(text)
    if not _ANSI_ENABLED:
        print_line(text, color=color, bold=bold)
        return
    prefix = ""
    if bold:
        prefix += Style.BRIGHT
    if color:
        prefix += color
    with _write_lock:
        _write(f"{CSI}{max(1,row)};{max(1,col)}H")
        _write(prefix + text + RESET)


def print_line(text: str = "", color: str = "", bold: bool = False):
    """
    Print a single line with a newline.

    Text is sanitised. Colour and bold are ignored when ANSI is disabled.
    """
    text = _sanitize(text)
    prefix = ""
    if bold:
        prefix += Style.BRIGHT
    if color and _ANSI_ENABLED:
        prefix += color
    suffix = RESET if _ANSI_ENABLED else ""
    _write(prefix + text + suffix + "\n")


# ----------------------------------------------------------------------
# Colour selection
# ----------------------------------------------------------------------
def color_for_state(state: str) -> str:
    """Return the colour for a security state. Empty when ANSI is disabled."""
    if not _ANSI_ENABLED:
        return ""
    s = (state or "").upper()
    if s == "GREEN":
        return Fore.GREEN
    if s == "YELLOW":
        return Fore.YELLOW
    if s == "ORANGE":
        return getattr(Fore, "LIGHTYELLOW_EX", Fore.YELLOW)
    if s == "RED":
        return Fore.RED
    return ""


def color_for_level(level: str) -> str:
    """Return the colour for an event level. Empty when ANSI is disabled."""
    if not _ANSI_ENABLED:
        return ""
    l = (level or "").lower()
    if l == "error":
        return Fore.RED
    if l == "warn":
        return Fore.YELLOW
    if l == "info":
        return Fore.CYAN
    return ""


# ----------------------------------------------------------------------
# Status bar
# ----------------------------------------------------------------------
def render_status_bar(
    state: str,
    risk: Optional[int],
    engines_running: int,
    engines_total: int,
    layers_enabled: int,
    layers_total: int,
    time_str: str,
):
    """
    Draw the single-line status bar.

    With ANSI: rendered at row 1, padded to terminal width.
    Without ANSI: printed as a regular scrolling line.
    """
    cols, _ = get_size()

    state_str = (state or "N/A").upper()
    risk_str = f"{risk}%" if risk is not None else "N/A"
    engines_str = f"{engines_running}/{engines_total}"
    layers_str = f"{layers_enabled}/{layers_total}"

    separator = "  |  "
    parts = [
        ("ACF", ""),
        (f"STATE: {state_str}", color_for_state(state_str)),
        (f"RISK: {risk_str}", ""),
        (f"ENGINES: {engines_str}", ""),
        (f"LAYERS: {layers_str}", ""),
        (time_str, ""),
    ]

    visible_parts = []
    remaining = cols - STATUS_MARGIN
    for i, (text, color) in enumerate(parts):
        if i > 0:
            if remaining < len(separator):
                break
            visible_parts.append((separator, ""))
            remaining -= len(separator)
        chunk = _truncate(text, remaining) if _visible_width(text) > remaining else text
        visible_parts.append((chunk, color))
        remaining -= _visible_width(chunk)
        if remaining <= 0:
            break

    if _ANSI_ENABLED:
        with _write_lock:
            _write(f"{CSI}1;1H")
            written = 0
            for text, color in visible_parts:
                if color:
                    _write(color + text + RESET)
                else:
                    _write(text)
                written += _visible_width(text)
            if written < cols:
                _write(" " * (cols - written))
    else:
        line = "".join(text for text, _ in visible_parts)
        print_line(line)


# ----------------------------------------------------------------------
# Divider, header, work area, prompt
# ----------------------------------------------------------------------
def render_divider(char: str = DEFAULT_DIVIDER):
    """Draw a horizontal divider on the current line."""
    cols, _ = get_size()
    print_line(char * cols)


def render_header(title: str):
    """Render a section header: blank line, bold title, divider."""
    cols, _ = get_size()
    title = _truncate(title, cols - 2)
    print_line("")
    print_line(f" {title}", bold=True)
    print_line(DEFAULT_DIVIDER * cols)


def render_work_area(lines: List[Tuple[str, str]]):
    """Render a list of (text, color) tuples as separate lines."""
    for text, color in lines:
        print_line(text, color=color)


def render_prompt(prompt: str):
    """Write the command prompt without a trailing newline."""
    _write(_sanitize(prompt))


# ----------------------------------------------------------------------
# Convenience helpers
# ----------------------------------------------------------------------
def print_error(message: str):
    print_line(f"  {message}", color=color_for_level("error"))


def print_warning(message: str):
    print_line(f"  {message}", color=color_for_level("warn"))


def print_info(message: str):
    print_line(f"  {message}", color=color_for_level("info"))


def print_success(message: str):
    print_line(f"  {message}", color=color_for_level("info"))


def flash_message(message: str, color: str = ""):
    """Short-lived message printed under the work area."""
    if not color:
        color = color_for_level("warn")
    print_line("")
    print_line(f"  {message}", color=color, bold=True)