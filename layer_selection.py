#!/usr/bin/env python3
# ==============================================================
# LAYER SELECTION - Rich-rendered nested layer assignment UI
# ==============================================================
import os
import subprocess
from rich.console import Group
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.box import ROUNDED

ALL_LAYERS_ORDER = [
    "layer1", "layer2", "layer3",
    "layer4a", "layer4c", "layer5",
]

LAYER_LABELS = {
    "layer1": "Layer 1 (Monitoring)",
    "layer2": "Layer 2 (AIS - Risk Calculation)",
    "layer3": "Layer 3 (State Engine)",
    "layer4a": "Layer 4a (Response)",
    "layer4c": "Layer 4c (MTD)",
    "layer5": "Layer 5 (Feedback)",   # --- FEEDBACK (was Dashboard) ---
}


def _clear():
    if os.name == "nt":
        subprocess.run("cls", shell=True)
    else:
        subprocess.run("clear", shell=True)


def _draw(console, renderable):
    _clear()
    console.print(renderable)


def _box_width(console):
    return min(max(console.width - 4, 60), 88)


# ---------- Panels ----------
def _title_panel(text):
    return Panel(
        Text(text, justify="center", style="bold white"),
        border_style="bright_black",
        box=ROUNDED,
        padding=(0, 1),
    )


def _layer_list_box(enabled_caps, assignments):
    body = Text()
    for idx, layer_id in enumerate(ALL_LAYERS_ORDER, 1):
        caps_here = [
            cap for cap in enabled_caps
            if layer_id in assignments.get(cap, [])
        ]
        caps_str = ", ".join(caps_here) if caps_here else "(none)"
        style = "green" if caps_here else "grey42"
        label = LAYER_LABELS[layer_id]
        short = (
            label.split(" (", 1)[1].rstrip(")")
            if " (" in label else layer_id
        )
        body.append(f" {idx}. ", style="bold cyan")
        body.append(f"{layer_id:8}", style="bold white")
        body.append(f"({short})\n", style="grey62")
        body.append(f"     {caps_str}\n", style=style)
    return Panel(
        body,
        title="[bold purple]LAYERS[/bold purple]",
        title_align="left",
        border_style="purple",
        box=ROUNDED,
        padding=(1, 1),
    )


def _layer_detail_box(layer_id, enabled_caps, assignments):
    body = Text()
    for idx, cap in enumerate(enabled_caps, 1):
        assigned = layer_id in assignments.get(cap, [])
        mark = "[x]" if assigned else "[ ]"
        style = "green" if assigned else "grey42"
        body.append(f" {idx}.", style="bold cyan")
        body.append(f"{cap:16}", style="white")
        body.append(f"{mark}\n", style=style)
    return Panel(
        body,
        title=f"[bold purple]{LAYER_LABELS[layer_id].upper()}[/bold purple]",
        title_align="left",
        border_style="purple",
        box=ROUNDED,
        padding=(1, 1),
    )


def _options_box(left_items, right_items):
    left = Text()
    for key, label in left_items:
        left.append(f" [{key}] ", style="bold purple")
        left.append(f"{label}\n", style="white")
    right = Text()
    for key, label in right_items:
        right.append(f" [{key}] ", style="bold purple")
        right.append(f"{label}\n", style="white")
    grid = Table.grid(expand=True, padding=(0, 2))
    grid.add_column(ratio=4)
    grid.add_column(ratio=3)
    grid.add_row(left, right)
    return Panel(
        grid,
        title="[bold purple]OPTIONS[/bold purple]",
        title_align="left",
        border_style="purple",
        box=ROUNDED,
        padding=(1, 1),
    )


def _input_box():
    return Panel(
        Text.from_markup(
            " [grey42]>[/grey42] [grey42]enter your choice[/grey42]"
        ),
        border_style="cyan",
        box=ROUNDED,
        padding=(0, 1),
    )


def _wrap_outer(console, *children):
    return Panel(
        Group(*children),
        border_style="bright_black",
        box=ROUNDED,
        padding=(1, 1),
        width=_box_width(console),
    )


# ---------- Screens ----------
def _screen_overview(console, enabled_caps, assignments):
    return _wrap_outer(
        console,
        _title_panel("LAYER SELECTION"),
        _layer_list_box(enabled_caps, assignments),
        _options_box(
            [("1-6", "Configure a layer")],
            [("b", "Back to main menu")],
        ),
        _input_box(),
    )


def _screen_detail(console, layer_id, enabled_caps, assignments):
    return _wrap_outer(
        console,
        _title_panel(f"LAYER SELECTION - {LAYER_LABELS[layer_id]}"),
        _layer_detail_box(layer_id, enabled_caps, assignments),
        _options_box(
            [(f"1-{len(enabled_caps)}", "Toggle assignment")],
            [("b", "Back to layer list")],
        ),
        _input_box(),
    )


def _screen_confirm(console, cap, layer_id):
    body = Text()
    body.append("  You are about to remove ", style="yellow")
    body.append(cap, style="bold white")
    body.append(" from ", style="yellow")
    body.append(layer_id, style="bold white")
    body.append(".\n\n", style="yellow")
    body.append("  ", style="")
    body.append(cap, style="bold white")
    body.append(" has no other layers assigned.\n", style="yellow")
    body.append("  This will stop ", style="yellow")
    body.append(cap, style="bold white")
    body.append(" at all layers.\n", style="yellow")
    return _wrap_outer(
        console,
        _title_panel("CONFIRM REMOVAL"),
        Panel(body, border_style="yellow", box=ROUNDED, padding=(1, 1)),
        _input_box(),
    )


def _read(console, text="enter your choice"):
    console.print()
    console.print(f"[bold cyan]>[/bold cyan] {text}: ", end="")
    return console.input("").strip().lower()


# ---------- Public entry point ----------
def run_layer_selection(console, enabled_caps, capability_layers):
    if not enabled_caps:
        _draw(console, _wrap_outer(
            console,
            _title_panel("LAYER SELECTION"),
            Panel(
                "[yellow]No capabilities configured. "
                "Add capabilities first.[/yellow]",
                border_style="yellow", box=ROUNDED, padding=(1, 1),
            ),
            _input_box(),
        ))
        console.print()
        console.input("[cyan]Press Enter to continue...[/cyan]")
        return capability_layers

    assignments = {
        cap: list(capability_layers.get(cap, []))
        for cap in enabled_caps
    }
    mode = "overview"
    current_layer = None

    while True:
        if mode == "overview":
            _draw(console, _screen_overview(
                console, enabled_caps, assignments
            ))
            choice = _read(console)
            if choice == 'b':
                return {
                    cap: caps for cap, caps in assignments.items() if caps
                }
            if choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(ALL_LAYERS_ORDER):
                    current_layer = ALL_LAYERS_ORDER[idx]
                    mode = "detail"
        elif mode == "detail":
            _draw(console, _screen_detail(
                console, current_layer, enabled_caps, assignments
            ))
            choice = _read(console)
            if choice == 'b':
                mode = "overview"
                current_layer = None
                continue
            if choice.isdigit():
                idx = int(choice) - 1
                if 0 <= idx < len(enabled_caps):
                    cap = enabled_caps[idx]
                    current = assignments.get(cap, [])
                    if current_layer in current:
                        if len(current) == 1:
                            _draw(console, _screen_confirm(
                                console, cap, current_layer
                            ))
                            ans = _read(console, "confirm (y/n)")
                            if ans != 'y':
                                continue
                        assignments[cap] = [
                            L for L in current if L != current_layer
                        ]
                    else:
                        assignments[cap] = list(current) + [current_layer]