# Configuration Snapshots

Three `system_config.json` snapshots are preserved. They
are not identical: each documents a different point in the
demonstration timeline.

## system_config.gate6.json
The config in use during Gate 6 and the final state of the
system. SSH has `layer4c` in its layer list; `shuffle` is
enabled with primary 22 and alternate 2222; `service_ports`
is `[22]`. This is the config that would produce a working
MTD pipeline after the G6-1 patch lands.

## system_config.broken.json
What the setup flow (`config_interactive.py`) produces
without external editing. SSH has layers 1, 2, 3 only.
`layer4a` and `layer4c` are `false` at the top level.
`service_ports` and `shuffle` are absent from
`capability_rules.ssh`. A pipeline started against this
config runs detection and state but not response or MTD.
This is the concrete evidence for issue G0-1.

## system_config.gate1-4.json
Reconstructed, not recovered. Neither stored snapshot
matches the exact configuration that ran during Gates 1
through 4. This file reconstructs it from two sources:

  1. The `[CONFIG] Configuration updated` log line at
     15:25:58 in `evidence/gates.txt`, which records
     `Layers: {layer1: true, layer2: true, layer3: true,
     layer4a: true, layer4c: false, layer5: false,
     reader: true}`.
  2. `system_config.gate6.json`, with `layer4c` and
     `capability_rules.ssh.shuffle` removed, and
     `capability_layers.ssh` and `.sensor` set to
     `[layer1, layer2, layer3, layer4a]`.

The reconstruction is used only as a reference document.
Post-patch gate re-runs are executed against the live
working config after patches land, not against this file.