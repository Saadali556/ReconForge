"""Shared data model and console output."""
from __future__ import annotations

import datetime as dt
import os
import sys
from dataclasses import asdict, dataclass, field

SEVERITIES = ["info", "low", "medium", "high", "critical"]
_COLORS = {"info": "36", "low": "32", "medium": "33", "high": "31", "critical": "35;1"}


def now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


@dataclass
class Finding:
    title: str
    severity: str = "info"
    detail: str = ""
    module: str = ""


@dataclass
class Result:
    module: str
    target: str
    findings: list = field(default_factory=list)
    data: dict = field(default_factory=dict)
    started: str = field(default_factory=now)

    def add(self, title: str, severity: str = "info", detail: str = "") -> None:
        assert severity in SEVERITIES, severity
        self.findings.append(Finding(title, severity, detail, self.module))

    def to_dict(self) -> dict:
        return {
            "module": self.module,
            "target": self.target,
            "started": self.started,
            "findings": [asdict(f) for f in self.findings],
            "data": self.data,
        }


def paint(text: str, sev: str) -> str:
    if sys.stdout.isatty() and "NO_COLOR" not in os.environ:
        return f"\033[{_COLORS.get(sev, '0')}m{text}\033[0m"
    return text


def print_results(results: list) -> None:
    for r in results:
        print(f"\n== {r.module} :: {r.target} ==")
        for k, v in r.data.items():
            if isinstance(v, (list, dict)) and len(str(v)) > 200:
                continue
            print(f"  {k}: {v}")
        for f in sorted(r.findings, key=lambda x: -SEVERITIES.index(x.severity)):
            print(f"  [{paint(f.severity.upper().ljust(8), f.severity)}] {f.title}")
            if f.detail:
                print(f"             {f.detail}")
        if not r.findings:
            print("  (no findings)")
