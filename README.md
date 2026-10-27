# ACF — Autonomous Cybersecurity Framework

A single-host autonomous defence pipeline for Windows. Detects failed authentication, computes risk, transitions between security states, blocks attacking IPs, and applies Moving Target Defence — without operator intervention during the attack.

Developed as a research prototype. Evidence from gate testing is in `evidence/`. Fixes applied after gate testing are documented below.

---

## Architecture

The pipeline is a five-layer chain. Each layer is a separate Python process; they communicate through a shared JSON file (the Blackboard) in `%TEMP%\acf_state.json`.

```
┌─────────┐   ┌─────────┐   ┌─────────┐   ┌─────────┐   ┌──────────┐
│ Reader  │──▶│ Monitor │──▶│   AIS   │──▶│  State  │──▶│ Response │
│ (L1)    │   │ (L1)    │   │  (L2)   │   │  (L3)   │   │  (L4a)   │
└─────────┘   └─────────┘   └─────────┘   └─────────┘   └──────────┘
                                                 │
                                                 ▼
                                          ┌──────────┐
                                          │   MTD    │
                                          │  (L4c)   │
                                          └──────────┘
```

| Layer             | Role                                                       | Engine                       |
|-------------------|------------------------------------------------------------|------------------------------|
| **Reader**        | Ingests events from event logs and files                   | `monitor/reader.py`          |
| **Layer 1**       | Applies detection rules to events                          | `monitor/monitor_engine.py`  |
| **Layer 2 (AIS)** | Groups detections, classifies behaviour, computes risk     | `ais/ais_engine.py`          |
| **Layer 3**       | Maps risk to GREEN / YELLOW / ORANGE / RED with hysteresis | `state/state_engine.py`      |
| **Layer 4a**      | Blocks attacker IPs at ORANGE+ via Windows Firewall        | `response/response_engine.py`|
| **Layer 4c**      | Moving Target Defence: port flip, decoy, path rotation     | `mtd/mtd_engine.py`          |
| **Layer 5**       | Feedback / post-hoc analysis (not exercised in evaluation) | `feedback/feedback_engine.py`|

`orchestrator.py` spawns all layer engines as subprocesses. The `console/` module provides the interactive terminal UI. Events stream to the UI via a loopback TCP bus (`event_router.py` / `event_emit.py` / `event_reader.py`).

---

## Repository structure

```
acf_platform/
├── orchestrator.py            # Entry point — spawns everything
├── config.py                  # Constants, thresholds, precondition checks
├── config_interactive.py      # Human-in-the-loop setup wizard
├── platform_utils.py          # Cross-platform file locking
├── event_*.py                 # Event bus (router, emitter, reader)
├── layer_manager.py           # Reader supervision, backoff, restart
├── layer_selection.py         # Layer tick UI (used by config_interactive)
│
├── monitor/                   # Reader + monitor engine + decoding
├── ais/                       # Risk analysis, grouper, classifier
├── state/                     # State machine
├── response/                  # Response engine + distributed response
├── mtd/                       # Moving Target Defence actions
├── feedback/                  # Layer 5 (out of scope for this evaluation)
├── console/                   # Terminal UI
├── evidence/                  # Gate demonstration captures
│
└── system_config.json         # Active configuration
```

---

## Requirements

- Windows 10 or later (uses Win32 API for event logs and firewall)
- Python 3.10+
- `pywin32` — `pip install pywin32`
- `psutil` — `pip install psutil`
- `rich` — `pip install rich` (for console UI)
- Administrator privileges — required for reading the OpenSSH/Operational event channel and for creating firewall rules
- OpenSSH Server enabled with audit logging:

```powershell
Get-WindowsCapability -Online | Where-Object Name -like 'OpenSSH*'
Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0
```

---

## Setup

### First run

Run PowerShell as Administrator:

```powershell
cd acf_platform
python config_interactive.py
```

The wizard discovers capabilities, lets you select which layers to enable for each capability, and writes `system_config.json`.

Recommended configuration for a working SSH demo:

- **ssh:** layers `layer1`, `layer2`, `layer3`, `layer4a`, `layer4c`
- **sensor:** layers `layer1`, `layer2`, `layer3`, `layer4a`
- **defender / pfirewall:** layers `layer1`, `layer2`, `layer3`

The wizard writes `capability_rules.ssh.service_ports` and `capability_rules.ssh.shuffle` automatically when SSH is enabled — these are the fields the response and MTD engines require. See [Fixes applied](#fixes-applied-after-gate-testing) below.

### Run the framework

Run PowerShell as Administrator:

```powershell
python orchestrator.py
```

The console appears. Type `diag` for available views, `diag events all` for the event stream, and `diag reader` / `diag monitor` / `diag response` / `diag mtd` for per-engine views.

---

## Testing each capability

Each test below exercises one gate's claim. Run the attack from a Linux VM (Kali on `192.168.56.0/24`) against the Windows host at `192.168.56.1`. Use a different attacker IP for each test — once an IP is blocked it stays blocked for `bantime` (default 3600 seconds).

### Detection and response (Gate 1)

From Kali (source IP `192.168.56.102`):

```bash
for i in $(seq 1 30); do
  sshpass -p "wrong$i" ssh -b 192.168.56.102 \
    -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    testuser@192.168.56.1 exit 2>/dev/null
  sleep 0.5
done
```

Expected within 30 seconds:

- GUI: `[ssh-STATE]` transitions GREEN → YELLOW → ORANGE → RED
- GUI: `[ssh-RESP] ... Blocks: 1`
- `Get-NetFirewallRule -DisplayName "ACF_capability_ssh_BLOCK_192.168.56.102*"` shows the block rules

### Memory persistence (Gate 2)

After Gate 1, wait for state to de-escalate (attack stops → GREEN within about 60 seconds). The block must persist — `blocked_ips` still contains `.102` at GREEN, and the firewall rule is still active.

Before the G2-1 patch, the block was released as soon as state dropped below ORANGE. After the patch, it persists until `bantime` expires.

### Infrastructure resilience (Gate 3)

Disable AIS for SSH:

```powershell
python disable_ssh_layer2.py
```

Wait 45 seconds, then attack from a fresh IP (`192.168.56.103`) from Kali:

```bash
for i in $(seq 1 30); do
  sshpass -p "wrong$i" ssh -b 192.168.56.103 \
    -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    -o PreferredAuthentications=password -o PubkeyAuthentication=no \
    testuser@192.168.56.1 exit 2>/dev/null
  sleep 0.5
done
```

Expected within 40 seconds:

- `layer_3_state_ssh.detail.input_source == "layer_1_monitor_ssh"` (R3a)
- `layer_4a_response_ssh.blocked_ips` contains an entry for `.103` (R3b)
- `layer_2_ais_ssh.ais_healthy == False`

Before G3-1, response blocked nothing when AIS was down. After the patch, it falls back to Layer 1 evidence.

Re-enable AIS by restarting the orchestrator:

```powershell
Get-Process python* | Stop-Process -Force
python orchestrator.py
```

### Classifier diversity (Gate 4)

From a fresh IP (`192.168.56.104`), spray eight different usernames:

```bash
for user in alice bob carol dave eve frank grace heidi; do
  for i in 1 2 3; do
    sshpass -p "wrong$i" ssh -b 192.168.56.104 \
      -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
      -o PreferredAuthentications=password -o PubkeyAuthentication=no \
      "$user@192.168.56.1" exit 2>/dev/null
  done
done
```

Expected:

- `layer_2_groups_ssh.source_groups[0].distinct_users >= 5`
- `layer_2_ais_ssh.detail.behaviors` contains `multi_account_authentication_pattern`

Before G4-1, the same attack produced `focused_bruteforce`, identical to single-user brute force. After the patch, the classifier distinguishes them.

### Moving Target Defence (Gate 6)

Requires `layer4c` enabled and `shuffle.enabled: true` in `system_config.json`. Verify first:

```powershell
$c = Get-Content system_config.json -Raw | ConvertFrom-Json
$c.capability_rules.ssh.shuffle.enabled  # must be True
$c.layers.layer4c                        # must be True
```

Restart the orchestrator after any configuration change. Confirm MTD is ready:

```powershell
$bb = Get-Content $env:TEMP\acf_state.json -Raw | ConvertFrom-Json
$bb.layer_4c_mtd_ssh.action_registry.traffic_shuffle.preflight_status
# Expect: "READY"
```

Drive state to RED (attack from a fresh IP), then wait 60 seconds (the `trigger_red_seconds` value in the shuffle config). MTD flips port 22 to port 2222 via firewall — verify with:

```powershell
Get-NetFirewallRule -DisplayName "ACF_capability_ssh_SHUFFLE_BLOCK*"
```

After state de-escalates or `restore_after_seconds` elapses, the block rule is removed and port 22 is reachable again.

Before G6-1, MTD preflight was BLOCKED on this host and no flip occurred.

---

## Fixes applied after gate testing

The following defects were identified during gate runs, patched, and verified. Each is one commit; the commit message documents the before/after evidence.

| Commit    | Fix                                                                             | Verdict flipped                                            |
|-----------|---------------------------------------------------------------------------------|------------------------------------------------------------|
| `ea5030b` | **G4-1** — extract username from OpenSSH payload                                | R4 mechanism 2: not → demonstrated                         |
| `2d188e3` | **G2-1** — fail2ban blocks persist below ORANGE                                 | R4 mechanism 1: not → demonstrated                         |
| `5898945` | **G3-1** — fail2ban sweep falls back to Layer 1 when AIS down                   | R3b: not → demonstrated                                    |
| `2866a7f` | **G6-1** — MTD firewall status falls back to netsh                              | R4 mechanism 3: configured → demonstrated                  |
| `9b9a352` | **G0-1 + N-33** — config wizard writes SSH layer needs and correct event channel| Setup flow produces working config without external editing|
| `24d6ef4` | **N-34** — MTD defensively falls back on missing config                         | Robustness: MTD survives config gaps                       |

Details per fix are in each commit message. Read with:

```bash
git log --oneline
git show <commit-hash>
```

### Known defects not patched

Documented as scope boundaries. All are Medium or Low, none affect the four verdicts above.

| ID          | Severity | Issue                                                                                                                           |
|-------------|----------|---------------------------------------------------------------------------------------------------------------------------------|
| G1-1        | Medium   | `known_threats.hits` over-counts (adds `events_total` per cycle, not once). Cosmetic; fail2ban threshold is still met.          |
| G6-2        | Medium   | MTD worker does not rebuild on config change. Requires engine restart after editing `service_ports` or `shuffle`.               |
| G1-2        | Low      | `behavior_coverage` reads a config field absent for SSH; reports all behaviours NOT_COVERED. Reporting only, no runtime effect. |
| N-22, N-24  | Low      | MTD `action_summary` always empty; decoy connections omitted from `action_log`. Cosmetic.                                       |

---

## Evidence

`evidence/` contains gate demonstration captures from 22 October 2026:

| File                                   | Gate   | Content                                                                                                                                                  |
|----------------------------------------|--------|----------------------------------------------------------------------------------------------------------------------------------------------------------|
| `gates.txt`                            | Gate 0 | Engine cycling, hysteresis hold, state gating                                                                                                            |
| `gate1_lifecycle_20261022_165043.txt`  | Gate 1 | OS-level firewall confirmation, 13.52s latency                                                                                                           |
| `gate1_R5.txt`                         | Gate 1 | Latency anchor                                                                                                                                           |
| `gate1_rerun_transcript.txt`           | Gate 1 | 59-second window with no operator command (R1 autonomy)                                                                                                  |
| `gate4_classifier_20261022_213414.txt` | Gate 4 | Pre-patch classifier output                                                                                                                              |
| `gate3.txt`                            | Gate 3 | AIS-disabled fallback capture (transcript shows a failed attempt; the successful capture is an appended summary, documented in the Gate Execution Report)|

Post-patch evidence is captured inline in the commit messages for the six fixes above.

---

## Configuration reference

`system_config.json` is read by all engines. Only two paths write to it:

- `config_interactive.py` — the setup wizard (overwrites the file)
- The console's `enable` / `disable` commands (modifies specific keys)

Nothing else writes to `system_config.json` at runtime. Stopping and restarting the orchestrator reads the same file; no data is lost.

> **Important:** every run of `config_interactive.py` rewrites `system_config.json`. If the wizard is interrupted or produces an incomplete config, restore a known-good config with:
>
> ```bash
> git show <commit>:system_config.json > system_config.json
> ```
>
> Or use the wizard's own `.backup` file (it makes one on each save).

---

## Running the tests from a clean state

```powershell
# Clear any orphaned firewall rules from prior runs
Get-NetFirewallRule -DisplayName "ACF_capability_ssh_BLOCK*" `
  -ErrorAction SilentlyContinue | Remove-NetFirewallRule

# Clear reader markers (forces fresh subscription)
Remove-Item $env:TEMP\acf_reader_*.marker.json -ErrorAction SilentlyContinue

# Restart orchestrator
Get-Process python* | Stop-Process -Force
python orchestrator.py
```

Orphaned firewall rules are the most common cause of "attack from IP X is silent." If an IP was blocked in a prior run and the block was not released by `bantime` expiry, all subsequent attacks from that IP are dropped at the network layer — sshd never sees them, so no reader event appears. Always verify the IP has no block before attacking:

```powershell
Get-NetFirewallRule -DisplayName "ACF_capability_ssh_BLOCK_192.168.56.*" `
  -ErrorAction SilentlyContinue
```

Empty output = safe to attack. Any rules = delete them first.

---

## Scope and limitations

- **Single-host only.** No multi-host orchestration; no distributed response exercised end-to-end.
- **Windows-only.** Uses Win32 APIs for event logs (`pywin32`) and firewall (`netsh`). Linux support exists in the code but is not demonstrated here.
- **Layer 5 (feedback)** is present in the code but not evaluated in this demonstration.
- **MTD runtime reconfiguration (G6-2)** requires engine restart.
- **Behaviour coverage reporting (G1-2)** is inaccurate for SSH; ignore the `behavior_coverage` summary in `layer_1_monitor_ssh`.
- **`known_threats.hits` over-counts (G1-1);** treat the value as an attack-intensity signal, not an exact attempt count.

---

## Licence

Research prototype. Not for production use without security review. See the accompanying research report for full evaluation methodology and results.