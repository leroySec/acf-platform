#!/usr/bin/env python3
# ============================================================================
# PLATFORM UTILITIES (Strategy Pattern for Cross‑Platform Support)
# ============================================================================
# Provides:
# - get_temp_dir(): Returns a writable temporary directory path for the OS.
# - acquire_lock(fd, exclusive=True): Locks a file descriptor.
# - release_lock(fd): Unlocks a file descriptor.
#
# On Linux: uses fcntl.flock (native).
# On Windows: uses portalocker (cross‑platform lock).
# ============================================================================

import os

# ---- Temporary Directory ----
def get_temp_dir():
    """Return a writable temporary directory for the current OS."""
    if os.name == 'nt':
        # Windows: use user's temp folder (usually C:\Users\<user>\AppData\Local\Temp)
        return os.environ.get('TEMP', 'C:\\Temp')
    else:
        # Linux / Unix: standard /tmp
        return '/tmp'

# ---- File Locking (Strategy Pattern) ----
if os.name == 'nt':
    import portalocker
    import time

    def acquire_lock(fd, exclusive=True):
        mode = portalocker.LOCK_EX if exclusive else portalocker.LOCK_SH
        mode |= portalocker.LOCK_NB
        deadline = time.time() + 30
        while time.time() < deadline:
            try:
                portalocker.lock(fd, mode)
                return
            except portalocker.LockException:
                time.sleep(0.05)
            except OSError:
                time.sleep(0.05)
        portalocker.lock(fd, mode & ~portalocker.LOCK_NB)

    def release_lock(fd):
        try:
            portalocker.unlock(fd)
        except Exception:
            pass
else:
    import fcntl

    def acquire_lock(fd, exclusive=True):
        """Acquire an exclusive or shared lock."""
        mode = fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH
        fcntl.flock(fd, mode)

    def release_lock(fd):
        """Release the lock."""
        fcntl.flock(fd, fcntl.LOCK_UN)