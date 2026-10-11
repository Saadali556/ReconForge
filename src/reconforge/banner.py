"""Terminal banner, status lines and run summary (interactive terminals only)."""
from __future__ import annotations

import os
import shutil
import sys

from . import __version__
from .core import SEVERITIES, paint

_GLYPHS = {
    "R": ["██████╗ ", "██╔══██╗", "██████╔╝", "██╔══██╗", "██║  ██║", "╚═╝  ╚═╝"],
    "E": ["███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "███████╗", "╚══════╝"],
    "C": [" ██████╗", "██╔════╝", "██║     ", "██║     ", "╚██████╗", " ╚═════╝"],
    "O": [" ██████╗ ", "██╔═══██╗", "██║   ██║", "██║   ██║", "╚██████╔╝", " ╚═════╝ "],
    "N": ["███╗   ██╗", "████╗  ██║", "██╔██╗ ██║", "██║╚██╗██║", "██║ ╚████║", "╚═╝  ╚═══╝"],
    "F": ["███████╗", "██╔════╝", "█████╗  ", "██╔══╝  ", "██║     ", "╚═╝     "],
    "G": [" ██████╗ ", "██╔════╝ ", "██║  ███╗", "██║   ██║", "╚██████╔╝", " ╚═════╝ "],
}
_GRADIENT = [51, 45, 39, 33, 63, 99, 135, 171, 207, 206, 205, 204]
TAGLINE = "Recon smarter. Stay in scope."


def color_ok(stream=None) -> bool:
    stream = stream or sys.stderr
    return stream.isatty() and "NO_COLOR" not in os.environ and os.environ.get("TERM") != "dumb"


def _c(text: str, code: str, stream=None) -> str:
    return f"\033[{code}m{text}\033[0m" if color_ok(stream) else text


def _word(word: str) -> list:
    return ["".join(_GLYPHS[ch][r] for ch in word) for r in range(6)]


def logo_lines() -> list:
    return _word("RECON") + _word("FORGE")


def render(width: int | None = None) -> str:
    width = width or shutil.get_terminal_size((80, 24)).columns
    lines = ["" ]
    if width >= 50:
        for i, row in enumerate(logo_lines()):
            lines.append("  " + _c(row, f"38;5;{_GRADIENT[i]}"))
    else:
        lines.append("  " + _c("RECONFORGE", "1;36"))
    info = f" v{__version__}  |  {TAGLINE} "
    bar = "─" * len(info)
    lines += ["", "  " + _c(f"┌{bar}┐", "90"), "  " + _c("│", "90") + _c(info, "1;97") + _c("│", "90"),
              "  " + _c(f"└{bar}┘", "90"),
              "  " + _c("⚠  Authorized testing only. ", "1;33") + _c("Get written permission first.", "33"), ""]
    return "\n".join(lines)


def show(force: bool = False) -> None:
    if force or (sys.stderr.isatty() and not os.environ.get("RECONFORGE_NO_BANNER")):
        print(render(), file=sys.stderr)


def status(msg: str, kind: str = "*") -> None:
    if sys.stderr.isatty():
        col = {"*": "36", "+": "32", "!": "33", "-": "31"}.get(kind, "36")
        print(f"  {_c(f'[{kind}]', '1;' + col)} {msg}", file=sys.stderr)


def summary(results: list, elapsed: float) -> None:
    counts = {s: 0 for s in SEVERITIES}
    for r in results:
        for f in r.findings:
            counts[f.severity] += 1
    total = sum(counts.values())
    parts = [paint(f"{s}: {n}", s) if n else f"{s}: {n}" for s, n in reversed(list(counts.items()))]
    print("\n" + "─" * 60)
    print(f"  {total} finding(s)  |  " + "  ".join(parts))
    print(f"  Completed in {elapsed:.1f}s")
    print("─" * 60)
