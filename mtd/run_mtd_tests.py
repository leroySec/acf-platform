#!/usr/bin/env python3
"""
run_mtd_tests.py - runnable test suite for the mtd package.

Works whether the file is placed at the repo root OR inside mtd/.
Run:

    python run_mtd_tests.py             # read-only (any OS)
    python run_mtd_tests.py --verbose
    python run_mtd_tests.py --live      # Windows + Administrator tests
"""

import argparse
import importlib
import inspect
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import traceback
from typing import Any, Callable, Dict, List, Optional, Tuple


_HERE = os.path.dirname(os.path.abspath(__file__))
_CWD = os.getcwd()


def _find_repo_root() -> str:
    if os.path.isfile(os.path.join(_HERE, "mtd", "base.py")):
        return _HERE
    if os.path.isfile(os.path.join(_HERE, "base.py")):
        return os.path.dirname(_HERE)
    if os.path.isfile(os.path.join(_CWD, "mtd", "base.py")):
        return _CWD
    if os.path.isfile(os.path.join(_CWD, "base.py")):
        return os.path.dirname(_CWD)
    return _HERE


_REPO = _find_repo_root()
if _REPO not in sys.path:
    sys.path.insert(0, _REPO)


class Skip(Exception):
    pass


def skip(reason: str) -> None:
    raise Skip(reason)


PASS = 0
FAIL = 0
SKIPPED = 0
VERBOSE = False
LIVE = False


def _t(name: str, fn: Callable[[], None]) -> None:
    global PASS, FAIL, SKIPPED
    try:
        fn()
    except Skip as e:
        SKIPPED += 1
        print(f"SKIP  {name}  ({e})")
        return
    except AssertionError as e:
        FAIL += 1
        print(f"FAIL  {name}  ({e})")
        return
    except Exception as e:
        FAIL += 1
        print(f"FAIL  {name}  ({type(e).__name__}: {e})")
        if VERBOSE:
            traceback.print_exc()
        return
    PASS += 1
    if VERBOSE:
        print(f"PASS  {name}")


_IMPORT_ERR: Dict[str, str] = {}


def _imp(dotted: str) -> Any:
    try:
        return importlib.import_module(dotted)
    except Exception as e:
        _IMPORT_ERR[dotted] = f"{type(e).__name__}: {e}"
        return None


_mtd = _imp("mtd")
_mtd_base = _imp("mtd.base")
_port_shuffle = _imp("mtd.action_port_shuffle")
_decoy = _imp("mtd.action_decoy")
_log_rotation = _imp("mtd.action_log_rotation")
_path_rotation = _imp("mtd.action_path_rotation")
_address_rotation = _imp("mtd.action_address_rotation")
_engine = _imp("mtd.mtd_engine")

MTDAction = getattr(_mtd_base, "MTDAction", None)
PortShuffleAction = getattr(_port_shuffle, "PortShuffleAction", None)
DecoyAction = getattr(_decoy, "DecoyAction", None)
LogRotationAction = getattr(_log_rotation, "LogRotationAction", None)
PathRotationAction = getattr(_path_rotation, "PathRotationAction", None)
AddressRotationAction = getattr(_address_rotation,
                                "AddressRotationAction", None)


def _classes() -> List[type]:
    return [c for c in (PortShuffleAction, DecoyAction, LogRotationAction,
                        PathRotationAction, AddressRotationAction)
            if c is not None]


def _on_windows() -> bool:
    return os.name == "nt"


def _elevated() -> bool:
    if not _on_windows():
        return False
    try:
        import ctypes
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:
        return False


def _has_powershell() -> bool:
    return any(shutil.which(c) for c in
               ("powershell.exe", "powershell", "pwsh.exe", "pwsh"))


_FIXTURES: List[str] = []


def _fixture_dir() -> str:
    d = tempfile.mkdtemp(prefix="mtd_test_")
    _FIXTURES.append(d)
    return d


def _make_sshd_config(path, port=22, listen="127.0.0.1"):
    lines = ["# synthetic sshd_config\n", f"Port {port}\n"]
    if listen is not None:
        lines.append(f"ListenAddress {listen}\n")
    lines += ["PermitRootLogin no\n", "PasswordAuthentication no\n"]
    with open(path, "w", encoding="utf-8") as f:
        f.writelines(lines)


def _make_system_config(path, sshd_path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump({
            "version": "1.0",
            "enabled_capabilities": {"ssh": True, "custom": {}},
            "capability_paths": {"ssh": sshd_path, "custom": {}},
            "capability_layers": {"ssh": ["layer4c"]},
            "layers": {"layer1": True, "layer4c": True},
        }, f, indent=2)


def _ctx(capability="ssh"):
    d = _fixture_dir()
    sshd = os.path.join(d, "sshd_config")
    cfg = os.path.join(d, "system_config.json")
    _make_sshd_config(sshd)
    _make_system_config(cfg, sshd)
    return {
        "capability": capability,
        "log_path": sshd,
        "config_path": cfg,
        "base_dir": d,
        "real_port": 22,
        "decoy_port": 2022,
        "bind_hosts": ["127.0.0.1"],
        "threshold_bytes": 1024,
    }


# ----------------------------------------------------------------------
# A. Package and interface
# ----------------------------------------------------------------------
def t_a1():
    assert _mtd is not None, _IMPORT_ERR.get("mtd", "import failed")


def t_a2():
    if _mtd_base is None:
        skip(f"mtd.base not importable: {_IMPORT_ERR.get('mtd.base', '')}")
    assert MTDAction is not None
    for name in ("STATUS_READY", "STATUS_BLOCKED",
                 "MODE_PRIMARY", "MODE_ADAPTED"):
        v = getattr(_mtd_base, name, None)
        assert isinstance(v, str) and v, f"{name} missing"


def t_a3():
    if MTDAction is None:
        skip("no MTDAction")
    for m in ("supports", "preflight", "should_activate",
              "is_active", "activate", "deactivate", "status",
              "set_preflight"):
        assert hasattr(MTDAction, m), f"MTDAction missing {m}"


def t_a4():
    cs = _classes()
    if not cs:
        skip("no action classes importable")
    for c in cs:
        for a in ("name", "one_shot", "requires_admin"):
            assert hasattr(c, a), f"{c.__name__} missing {a}"


def t_a5():
    cs = _classes()
    if not cs:
        skip("no action classes importable")
    for c in cs:
        for m in ("supports", "preflight", "should_activate",
                  "is_active", "activate", "deactivate", "status"):
            assert callable(getattr(c, m, None)), f"{c.__name__} .{m}"


def t_a6():
    cs = _classes()
    if not cs:
        skip("no action classes importable")
    names = [c.name for c in cs]
    assert len(names) == len(set(names)), f"dup names {names}"


# ----------------------------------------------------------------------
# B. Common shape
# ----------------------------------------------------------------------
def t_b1():
    cs = _classes()
    if not cs:
        skip("no action classes importable")
    for c in cs:
        assert c("ssh", _ctx("ssh")) is not None


def t_b2():
    cs = _classes()
    if not cs:
        skip("no action classes importable")
    for c in cs:
        ctx = _ctx("ssh")
        for cap in ("ssh", "sensor", "app_http", "custom", ""):
            assert isinstance(c.supports(cap, ctx), bool)


def t_b3():
    cs = _classes()
    if not cs:
        skip("no action classes importable")
    for c in cs:
        r = c("ssh", _ctx("ssh")).preflight()
        assert isinstance(r, tuple) and len(r) == 3, f"{c.__name__}: {r!r}"
        assert isinstance(r[0], str) and r[0]
        assert isinstance(r[1], str)
        assert isinstance(r[2], str)


def t_b4():
    cs = _classes()
    if not cs:
        skip("no action classes importable")
    for c in cs:
        inst = c("ssh", _ctx("ssh"))
        for s in ("GREEN", "YELLOW", "ORANGE", "RED",
                  "green", " RED ", "", None):
            assert isinstance(inst.should_activate(s), bool)


def t_b5():
    expect = {
        PortShuffleAction: {"ORANGE", "RED"},
        DecoyAction: {"ORANGE", "RED"},
        LogRotationAction: {"ORANGE", "RED"},
        PathRotationAction: {"RED"},
        AddressRotationAction: {"ORANGE", "RED"},
    }
    present = [c for c in expect if c is not None]
    if not present:
        skip("no action classes importable")
    for c in present:
        inst = c("ssh", _ctx("ssh"))
        for s in ("GREEN", "YELLOW", "ORANGE", "RED"):
            want = s in expect[c]
            got = inst.should_activate(s)
            assert got is want, f"{c.__name__} {s}: {got} != {want}"


def t_b6():
    cs = _classes()
    if not cs:
        skip("no action classes importable")
    for c in cs:
        assert isinstance(c("ssh", _ctx("ssh")).status(), dict)


def t_b7():
    cs = _classes()
    if not cs:
        skip("no action classes importable")
    for c in cs:
        assert isinstance(c("ssh", _ctx("ssh")).is_active(), bool)


def t_b8():
    cs = _classes()
    if not cs:
        skip("no action classes importable")
    for c in cs:
        inst = c("ssh", _ctx("ssh"))
        a = inst.deactivate()
        b = inst.deactivate()
        assert isinstance(a, tuple) and len(a) == 2, f"{c.__name__} a={a!r}"
        assert isinstance(b, tuple) and len(b) == 2, f"{c.__name__} b={b!r}"


def t_b9():
    cs = _classes()
    if not cs:
        skip("no action classes importable")
    for c in cs:
        params = list(inspect.signature(c.activate).parameters)
        assert params == ["self"], f"{c.__name__}: {params}"


def t_b10():
    cs = _classes()
    if not cs:
        skip("no action classes importable")
    for c in cs:
        assert isinstance(c("ssh", _ctx("ssh")).status(), dict)


def t_b11():
    cs = _classes()
    if not cs:
        skip("no action classes importable")
    for c in cs:
        for bad in ("rotate_now", "force_rotate", "apply", "run_now"):
            assert not hasattr(c, bad), f"{c.__name__}.{bad}"


# ----------------------------------------------------------------------
# C. Helper functions
# ----------------------------------------------------------------------
def t_c1():
    mods = [m for m in (_decoy, _log_rotation,
                        _path_rotation, _address_rotation) if m]
    if not mods:
        skip("no helper modules importable")
    for m in mods:
        for n in ("_coerce_int", "_coerce_float", "_coerce_bool"):
            assert hasattr(m, n), f"{m.__name__} missing {n}"


def t_c2():
    mods = [m for m in (_decoy, _log_rotation,
                        _path_rotation, _address_rotation) if m]
    if not mods:
        skip("no helper modules importable")
    for m in mods:
        f = m._coerce_int
        assert f(5, 1, 0, 10) == 5
        assert f("7", 1, 0, 10) == 7
        assert f(None, 3, 0, 10) == 3
        assert f("bad", 3, 0, 10) == 3
        assert f(-5, 3, 0, 10) == 3
        assert f(15, 3, 0, 10) == 3


def t_c3():
    mods = [m for m in (_decoy, _log_rotation,
                        _path_rotation, _address_rotation) if m]
    if not mods:
        skip("no helper modules importable")
    for m in mods:
        f = m._coerce_bool
        assert f(True, False) is True
        assert f("yes", False) is True
        assert f("0", True) is False
        assert f(None, True) is True


def t_c4():
    mods = [m for m in (_log_rotation, _path_rotation) if m]
    if not mods:
        skip("log/path rotation not importable")
    for m in mods:
        f = getattr(m, "_strftime_to_regex", None)
        if f is None:
            skip(f"{m.__name__} missing _strftime_to_regex")
        r, u = f("%Y%m%d-%H%M%S")
        assert r is not None and u == ""
        r, u = f("%Q")
        assert r is None and u == "%Q"


def t_c5():
    if _path_rotation is None:
        skip("path_rotation not importable")
    eq = _path_rotation._path_equal
    anc = _path_rotation._is_ancestor_or_equal
    assert eq("/a/b", "/a/b")
    assert not eq("/a/b", "/a/c")
    assert anc("/a", "/a/b/c")
    assert not anc("/a/b", "/a/bc")


def t_c6():
    if _address_rotation is None:
        skip("address_rotation not importable")
    v = _address_rotation._validate_loopback_target
    assert v("127.0.0.2", "127.0.0.1") is None
    assert v("10.0.0.2", "127.0.0.1") is not None
    assert v("127.0.0.1", "127.0.0.1") is not None
    assert v("127.255.255.255", "127.0.0.1") is not None


def t_c7():
    if _address_rotation is None:
        skip("address_rotation not importable")
    f = _address_rotation._parse_listen_address
    assert f("ListenAddress 127.0.0.1\n") == ("127.0.0.1", None, False)
    assert f("ListenAddress 127.0.0.2:2222\n") == ("127.0.0.2", 2222, False)
    addr, port, is6 = f("ListenAddress [::1]:22\n")
    assert addr == "::1" and port == 22 and is6 is True


def t_c8():
    if _address_rotation is None:
        skip("address_rotation not importable")
    f = _address_rotation._count_listen_address_lines
    assert f("ListenAddress 127.0.0.1\n") == 1
    assert f("ListenAddress 127.0.0.1\nListenAddress 127.0.0.2\n") == 2
    assert f("# ListenAddress 127.0.0.1\n") == 0


def t_c9():
    if _address_rotation is None or AddressRotationAction is None:
        skip("address_rotation not importable")
    f = AddressRotationAction._rewrite_listen_address
    out = f("Port 22\nListenAddress 127.0.0.1\n", "127.0.0.2")
    assert "ListenAddress 127.0.0.2" in out
    assert "ListenAddress 127.0.0.1" not in out
    out = f("Port 22\n", "127.0.0.5")
    assert "ListenAddress 127.0.0.5" in out


def t_c10():
    if _log_rotation is None:
        skip("log_rotation not importable")
    f = getattr(_log_rotation, "_parse_port", None)
    if f is None:
        skip("no _parse_port")
    assert f("Port 22\n") == 22
    assert f("port 2222\n") == 2222


def t_c11():
    if _log_rotation is None:
        skip("log_rotation not importable")
    f = getattr(_log_rotation, "_has_include_directive", None)
    if f is None:
        skip("no _has_include_directive")
    assert f("Include C:\\foo\\bar.conf\n")
    assert not f("# Include x\n")


def t_c12():
    if _path_rotation is None or PathRotationAction is None:
        skip("path_rotation not importable")
    f = PathRotationAction._try_rmdir_empty
    with tempfile.TemporaryDirectory() as d:
        f_path = os.path.join(d, "file")
        with open(f_path, "w") as fh:
            fh.write("x")
        assert f(f_path) == (False, "not_a_directory")
        assert f(d) == (False, "not_empty")
        e = os.path.join(d, "empty")
        os.makedirs(e)
        assert f(e) == (True, "removed")


def t_c13():
    if _decoy is None:
        skip("decoy not importable")
    for n in ("_DEFAULT_DECOY_PORTS", "_DEFAULT_REAL_PORTS",
              "_DEFAULT_BANNERS", "_DEFAULT_DIRECTIONS"):
        assert isinstance(getattr(_decoy, n, None), dict), n


def t_c14():
    if _decoy is None or _port_shuffle is None:
        skip("decoy or port_shuffle not importable")
    decoy_ports = set(_decoy._DEFAULT_DECOY_PORTS.values())
    shuffle_ports = {_port_shuffle.BASE_PORT,
                     _port_shuffle.ALTERNATE_PORT,
                     _port_shuffle.AGGRESSIVE_PORT}
    assert not (decoy_ports & shuffle_ports), "port overlap"


def t_c15():
    if _log_rotation is None:
        skip("log_rotation not importable")
    decode = getattr(_log_rotation, "_read_text_with_encoding", None)
    write = getattr(_log_rotation, "_write_text_with_encoding", None)
    if decode is None or write is None:
        skip("no encoding helpers")
    cases = [
        ("utf-8", b"", "hello"),
        ("utf-8", b"\xef\xbb\xbf", "hello"),
        ("utf-16-le", b"\xff\xfe", "hello"),
        ("utf-16-be", b"\xfe\xff", "hello"),
    ]
    for enc, bom, text in cases:
        with tempfile.TemporaryDirectory() as d:
            p = os.path.join(d, "cfg")
            write(p, text, bom, enc)
            rt, rb, _ = decode(p)
            assert rt == text, f"{enc}: {rt!r} != {text!r}"
            assert rb == bom, f"{enc}: bom {rb!r} != {bom!r}"


# ----------------------------------------------------------------------
# D. Cross-action source scan
# ----------------------------------------------------------------------
def _mtd_dir() -> Optional[str]:
    for c in (os.path.join(_REPO, "mtd"), _REPO, _HERE):
        if os.path.isdir(c) and os.path.isfile(os.path.join(c, "base.py")):
            return c
    return None


def t_d1():
    d = _mtd_dir()
    if d is None:
        skip("mtd dir not found")
    for f in sorted(os.listdir(d)):
        if not f.startswith("action_") or not f.endswith(".py"):
            continue
        with open(os.path.join(d, f), encoding="utf-8") as fh:
            src = fh.read()
        assert "BLACKBOARD_FILE" not in src, f"{f} uses BLACKBOARD_FILE"


def t_d2():
    d = _mtd_dir()
    if d is None:
        skip("mtd dir not found")
    for f in sorted(os.listdir(d)):
        if not f.startswith("action_") or not f.endswith(".py"):
            continue
        with open(os.path.join(d, f), encoding="utf-8") as fh:
            src = fh.read()
        for m in re.finditer(
                r"^\s*(?:from|import)\s+mtd\.action_(\w+)",
                src, re.MULTILINE):
            assert m.group(1) == f[7:-3], f"{f} imports {m.group(1)}"


def t_d3():
    cs = _classes()
    if not cs:
        skip("no action classes importable")
    for c in cs:
        inst = c("ssh", _ctx("ssh"))
        assert isinstance(getattr(inst, "_lock_key", None), str)
        assert inst._lock_key


# ----------------------------------------------------------------------
# LIVE tests
# ----------------------------------------------------------------------
def _live_ready(inst, capability="ssh"):
    if not LIVE:
        return False, "use --live"
    if not _on_windows():
        return False, "Windows only"
    if not _elevated():
        return False, "requires Administrator"
    st = inst.preflight()
    if st[0] != "READY":
        return False, f"preflight {st[0]}: {st[2]}"
    return True, ""


def _real_sshd_config():
    p = r"C:\ProgramData\ssh\sshd_config"
    return p if os.path.isfile(p) else None


def _backup(path):
    if not path or not os.path.isfile(path):
        return None
    b = path + ".test_bak"
    shutil.copy2(path, b)
    return b


def _restore(backup, target):
    if backup and os.path.isfile(backup):
        try:
            shutil.copy2(backup, target)
            os.remove(backup)
        except Exception:
            pass


def _real_ctx(capability):
    cfg = _real_sshd_config()
    if cfg is None:
        return None
    return {"capability": capability, "log_path": cfg,
            "config_path": os.path.join(os.getcwd(),
                                        "system_config.json"),
            "base_dir": os.path.dirname(cfg)}


def t_live_ps_readonly():
    if not LIVE:
        skip("use --live")
    if not _on_windows():
        skip("Windows only")
    if not _has_powershell():
        skip("no PowerShell")
    cmd = ("$s = Get-Service -Name sshd -ErrorAction SilentlyContinue; "
           "if ($s) { $s.Status.ToString() } else { 'missing' }")
    r = subprocess.run(["powershell.exe", "-NoProfile", "-NonInteractive",
                        "-Command", cmd],
                       capture_output=True, text=True, timeout=15)
    assert r.returncode == 0, f"ps failed: {r.stderr}"
    out = (r.stdout or "").strip().lower()
    assert out in ("running", "stopped", "missing",
                   "startpending", "stoppending"), out


def t_live_port_shuffle_status():
    if PortShuffleAction is None:
        skip("action not importable")
    ctx = _real_ctx("ssh")
    if ctx is None:
        skip("no sshd_config on host")
    inst = PortShuffleAction("ssh", ctx)
    st = inst.status()
    assert isinstance(st.get("port"), int)
    assert st["port"] > 0


def t_live_port_shuffle_cycle():
    if PortShuffleAction is None:
        skip("action not importable")
    ctx = _real_ctx("ssh")
    if ctx is None:
        skip("no sshd_config on host")
    if not LIVE:
        skip("use --live")
    if not _elevated():
        skip("requires Administrator")
    cfg = ctx["log_path"]
    backup = _backup(cfg)
    try:
        inst = PortShuffleAction("ssh", ctx)
        original_port = inst.status()["port"]
        target = 2222 if original_port != 2222 else 22
        ok, err = inst._write_configured_port(target)
        assert ok, f"write failed: {err}"
        parsed = inst._read_configured_port()
        assert parsed == target, f"parsed {parsed} expected {target}"
        ok, err = inst._write_configured_port(original_port)
        assert ok, f"restore write failed: {err}"
        parsed = inst._read_configured_port()
        assert parsed == original_port, f"restore {parsed}"
    finally:
        _restore(backup, cfg)


def t_live_decoy_can_bind_and_release():
    if DecoyAction is None:
        skip("action not importable")
    if not LIVE:
        skip("use --live")
    if not _on_windows():
        skip("Windows only")
    ctx = {"capability": "custom", "decoy_port": 20022,
           "bind_hosts": ["127.0.0.1"],
           "protocol_direction": "server_first",
           "banner": b"hi\r\n",
           "max_concurrent": 2,
           "read_timeout": 1.0}
    inst = DecoyAction("custom", ctx)
    st = inst.preflight()
    if st[0] != "READY":
        skip(f"preflight {st[0]}: {st[2]}")
    inst.should_activate("ORANGE")
    ok, err = inst.activate()
    assert ok, f"activate failed: {err}"
    try:
        cmd = (f"$c = Get-NetTCPConnection -LocalAddress '127.0.0.1' "
               f"      -LocalPort 20022 -State Listen "
               f"      -ErrorAction SilentlyContinue; "
               f"if ($c) {{ 'yes' }} else {{ 'no' }}")
        r = subprocess.run(["powershell.exe", "-NoProfile",
                            "-NonInteractive", "-Command", cmd],
                           capture_output=True, text=True, timeout=10)
        assert "yes" in (r.stdout or "").lower(), "port not listening"
    finally:
        inst.deactivate()


def t_live_log_rotation_cycle():
    if LogRotationAction is None:
        skip("action not importable")
    d = _fixture_dir()
    log = os.path.join(d, "sample.log")
    with open(log, "w", encoding="utf-8") as f:
        f.write("x" * 4096)
    ctx = {"capability": "ssh", "log_path": log,
           "threshold_bytes": 10, "red_threshold_bytes": 10,
           "keep_rotated": 2, "min_seconds_between_rotations": 0.0}
    inst = LogRotationAction("ssh", ctx)
    st = inst.preflight()
    if st[0] != "READY":
        skip(f"preflight {st[0]}: {st[2]}")
    inst.should_activate("ORANGE")
    ok, err = inst.activate()
    assert ok, f"activate failed: {err}"
    s = inst.status()
    assert s["rotations_total"] >= 1, s
    assert os.path.isfile(log), "new log missing"
    rotated = [f for f in os.listdir(d) if f.startswith("sample.log.")]
    assert rotated, "no rotated files"


def t_live_path_rotation_cycle():
    if PathRotationAction is None:
        skip("action not importable")
    d = _fixture_dir()
    log = os.path.join(d, "sample.log")
    with open(log, "w", encoding="utf-8") as f:
        f.write("data")
    cfg = os.path.join(d, "system_config.json")
    _make_system_config(cfg, log)
    ctx = {"capability": "ssh", "log_path": log, "config_path": cfg,
           "base_dir": d, "min_seconds_between_rotations": 0.0,
           "path_pattern": "%Y%m%d-%H%M%S"}
    inst = PathRotationAction("ssh", ctx)
    st = inst.preflight()
    if st[0] != "READY":
        skip(f"preflight {st[0]}: {st[2]}")
    inst.should_activate("RED")
    ok, err = inst.activate()
    assert ok, f"activate failed: {err}"
    with open(cfg, "r", encoding="utf-8") as f:
        data = json.load(f)
    new_path = data["capability_paths"]["ssh"]
    assert new_path != log, "config not updated"
    assert os.path.isfile(new_path), f"new file missing: {new_path}"


def t_live_address_rotation_cycle():
    if AddressRotationAction is None or _address_rotation is None:
        skip("action not importable")
    ok, reason = _live_ready(AddressRotationAction("ssh",
                                                   {"capability": "ssh"}))
    if not ok:
        skip(reason)
    ctx = _real_ctx("ssh")
    if ctx is None:
        skip("no sshd_config")
    cfg = ctx["log_path"]
    backup = _backup(cfg)
    try:
        ctx2 = dict(ctx)
        ctx2["alternate_ip"] = "127.0.0.2"
        ctx2["aggressive_ip"] = "127.0.0.3"
        iface = _address_rotation._loopback_interface_index()
        assert iface is not None, "no loopback interface"
        ok, err = _address_rotation._add_loopback_ip("127.0.0.2", iface)
        assert ok, f"add IP failed: {err}"
        try:
            assert _address_rotation._ip_owned_by_loopback(
                "127.0.0.2", iface), "IP not on loopback"
        finally:
            _address_rotation._remove_loopback_ip("127.0.0.2", iface)
        assert not _address_rotation._ip_owned_by_loopback(
            "127.0.0.2", iface), "IP not removed"
    finally:
        _restore(backup, cfg)


TESTS: List[Tuple[str, Callable[[], None]]] = [
    ("A1 mtd package", t_a1),
    ("A2 mtd.base", t_a2),
    ("A3 MTDAction methods", t_a3),
    ("A4 class attrs", t_a4),
    ("A5 class interface", t_a5),
    ("A6 class names unique", t_a6),

    ("B1 construction", t_b1),
    ("B2 supports bool", t_b2),
    ("B3 preflight triple", t_b3),
    ("B4 should_activate bool", t_b4),
    ("B5 should_activate semantics", t_b5),
    ("B6 status dict", t_b6),
    ("B7 is_active bool", t_b7),
    ("B8 deactivate idempotent", t_b8),
    ("B9 activate signature", t_b9),
    ("B10 status before preflight", t_b10),
    ("B11 no forbidden mutators", t_b11),

    ("C1 coerce present", t_c1),
    ("C2 coerce_int", t_c2),
    ("C3 coerce_bool", t_c3),
    ("C4 strftime_to_regex", t_c4),
    ("C5 path equality", t_c5),
    ("C6 loopback target", t_c6),
    ("C7 parse ListenAddress", t_c7),
    ("C8 count ListenAddress", t_c8),
    ("C9 rewrite ListenAddress", t_c9),
    ("C10 parse Port", t_c10),
    ("C11 Include directive", t_c11),
    ("C12 rmdir empty", t_c12),
    ("C13 decoy defaults", t_c13),
    ("C14 decoy/shuffle port disjoint", t_c14),
    ("C15 encoding round-trip", t_c15),

    ("D1 no Blackboard writes", t_d1),
    ("D2 no cross-action imports", t_d2),
    ("D3 lock key present", t_d3),

    ("L1 PowerShell read", t_live_ps_readonly),
    ("L2 port_shuffle status", t_live_port_shuffle_status),
    ("L3 port_shuffle config cycle", t_live_port_shuffle_cycle),
    ("L4 decoy bind/release", t_live_decoy_can_bind_and_release),
    ("L5 log_rotation cycle", t_live_log_rotation_cycle),
    ("L6 path_rotation cycle", t_live_path_rotation_cycle),
    ("L7 address_rotation cycle", t_live_address_rotation_cycle),
]


def main() -> int:
    global VERBOSE, LIVE
    ap = argparse.ArgumentParser()
    ap.add_argument("--verbose", action="store_true")
    ap.add_argument("--live", action="store_true")
    args = ap.parse_args()
    VERBOSE = args.verbose
    LIVE = args.live

    print("=" * 64)
    print("mtd test runner")
    print("=" * 64)
    print(f"Host:       {sys.platform}  elevated={_elevated()}")
    print(f"Repo root:  {_REPO}")
    print(f"Runner at:  {_HERE}")
    print(f"Live mode:  {'on' if LIVE else 'off'}")
    print()

    if _IMPORT_ERR:
        print("Import issues detected:")
        for k, v in _IMPORT_ERR.items():
            print(f"  {k}: {v}")
        print()

    try:
        for name, fn in TESTS:
            _t(name, fn)
    finally:
        for d in _FIXTURES:
            shutil.rmtree(d, ignore_errors=True)

    total = PASS + FAIL + SKIPPED
    print()
    print("-" * 64)
    print(f"PASS {PASS}   FAIL {FAIL}   SKIP {SKIPPED}   TOTAL {total}")
    print("-" * 64)
    return 0 if FAIL == 0 else 1


if __name__ == "__main__":
    sys.exit(main())