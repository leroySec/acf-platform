# Evidence Annex

This directory contains the raw captures produced by the ACF
during the gate demonstrations on 22 October 2026. The code
state that produced these captures is the state committed
alongside this evidence. Patches applied after this commit
are listed in the repository history; the evidence here
describes the system *before* those patches.

## Files

| File | Gate | What it shows |
|---|---|---|
| gates.txt | Gate 0 | Engine cycling, hysteresis hold, state-gating |
| gate1_20261022_160444.txt | Gate 1 run 1 | Block released before OS query |
| gate1_20261022_160709.txt | Gate 1 run 1 | Continued run 1 |
| gate1_20261022_161327.txt | Gate 1 run 1 | Block confirmed released |
| gate1_lifecycle_20261022_165043.txt | Gate 1 run 2 | OS-level rule confirmation; rule/timestamp match to the millisecond |
| gate1_R5.txt | Gate 1 run 2 | Latency anchor: YELLOW to block = 13.52 s |
| gate1_rerun_transcript.txt | Gate 1 run 2 | 59 s window, no operator command — autonomy evidence |
| gate3.txt | Gate 3 | Live transcript records a failed PowerShell disable; successful fallback capture appears as an appended summary. See note below. |
| gate4_classifier_20261022_213414.txt | Gate 4 | Classifier score 69; groups_above 1 |

## Provenance notes

### gate3.txt
The live transcript in this file records an *unsuccessful*
attempt to disable AIS via PowerShell. The successful
`previous_state: YELLOW` capture cited in the Gate Execution
Report appears at the bottom of the file as a manually
appended summary with timestamps from a later run (20:55
local), not from the transcript itself. The R3a claim rests
on the Gate 3 re-run after the patches land (see `evidence/
gate3_rerun_*.txt` once produced). This file is preserved
as-is and its gap is documented here rather than hidden.

### Missing files
`acf.log` and `sshd_config.acf.bak.*` are not in this commit
if not present on disk at commit time. If they are added
later, they are added to this directory in a follow-up
commit before the first patch commit.