#!/usr/bin/env python3
"""
process_tree.py — Kernel-enforced process containment for ACF.

Creates one Windows Job Object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
at orchestrator startup. Every child assigned to that job is killed by
the kernel when the orchestrator process exits — clean exit, Ctrl+C,
taskkill /F, Task Manager, crash. No signal has to be delivered. No
child cooperation is required. No parent code has to run at shutdown.

On non-Windows this module is a no-op: create_job returns None and
assign_process returns False. Behaviour is unchanged there.
"""

import os

_IS_WINDOWS = os.name == "nt"
_JOB_HANDLE = None

if _IS_WINDOWS:
    import ctypes

    _kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)

    _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
    _JobObjectExtendedLimitInformation = 9
    _PROCESS_SET_QUOTA = 0x0100
    _PROCESS_TERMINATE = 0x0001

    class _IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_ulonglong),
            ("WriteOperationCount", ctypes.c_ulonglong),
            ("OtherOperationCount", ctypes.c_ulonglong),
            ("ReadTransferCount", ctypes.c_ulonglong),
            ("WriteTransferCount", ctypes.c_ulonglong),
            ("OtherTransferCount", ctypes.c_ulonglong),
        ]

    class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_longlong),
            ("PerJobUserTimeLimit", ctypes.c_longlong),
            ("LimitFlags", ctypes.c_uint32),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", ctypes.c_uint32),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", ctypes.c_uint32),
            ("SchedulingClass", ctypes.c_uint32),
        ]

    class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation",
             _JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", _IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]


def create_job():
    """
    Create the kill-on-close job. Idempotent. Returns the handle on
    Windows, None on non-Windows or on any failure.

    The handle is held at module scope for the life of the process.
    Windows closes it automatically at process termination; the last
    handle closing triggers the kernel kill on every member.
    """
    global _JOB_HANDLE
    if not _IS_WINDOWS:
        return None
    if _JOB_HANDLE is not None:
        return _JOB_HANDLE

    try:
        handle = _kernel32.CreateJobObjectW(None, None)
        if not handle:
            return None

        info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = \
            _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE

        ok = _kernel32.SetInformationJobObject(
            handle,
            _JobObjectExtendedLimitInformation,
            ctypes.byref(info),
            ctypes.sizeof(info),
        )
        if not ok:
            _kernel32.CloseHandle(handle)
            return None

        _JOB_HANDLE = handle
        return handle
    except Exception:
        return None


def assign_process(proc_or_pid):
    """
    Assign a subprocess.Popen instance or an integer PID to the job.
    Best-effort. Returns True on success, False otherwise.

    Common failure: the orchestrator is itself running inside an
    outer job (Task Scheduler, service host) that does not permit
    breakaway. In that case the assignment is refused and the child
    runs normally, unprotected. kill_orphans() at next startup is
    the fallback for anything that escapes.
    """
    if not _IS_WINDOWS or _JOB_HANDLE is None:
        return False

    try:
        if hasattr(proc_or_pid, "pid"):
            pid = int(proc_or_pid.pid)
        else:
            pid = int(proc_or_pid)
    except Exception:
        return False

    try:
        h = _kernel32.OpenProcess(
            _PROCESS_SET_QUOTA | _PROCESS_TERMINATE, False, pid)
        if not h:
            return False
        try:
            return bool(
                _kernel32.AssignProcessToJobObject(_JOB_HANDLE, h))
        finally:
            _kernel32.CloseHandle(h)
    except Exception:
        return False