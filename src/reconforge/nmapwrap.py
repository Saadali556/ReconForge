"""Nmap wrapper with XML parsing."""
from __future__ import annotations

import shutil
import subprocess
import xml.etree.ElementTree as ET

from .core import Result


def run(host: str, ports: str | None = None, timeout: int = 600) -> Result:
    res = Result("nmap", host)
    exe = shutil.which("nmap")
    if not exe:
        res.add("Nmap is not installed", "info", "Install it (e.g. sudo apt install nmap)")
        return res
    cmd = [exe, "-sV", "-oX", "-", "-Pn"] + (["-p", ports] if ports else ["--top-ports", "100"]) + [host]
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except subprocess.TimeoutExpired:
        res.add("Nmap timed out", "low")
        return res
    try:
        root = ET.fromstring(p.stdout)
    except ET.ParseError:
        res.add("Could not parse nmap output", "low", p.stderr.strip()[:200])
        return res
    services = []
    for port in root.iter("port"):
        st = port.find("state")
        if st is None or st.get("state") != "open":
            continue
        sv = port.find("service")
        name = sv.get("name", "?") if sv is not None else "?"
        ver = " ".join(x for x in (sv.get("product", ""), sv.get("version", "")) if x) if sv is not None else ""
        services.append({"port": int(port.get("portid")), "proto": port.get("protocol"), "service": name, "version": ver})
        res.add(f"{port.get('portid')}/{port.get('protocol')} {name}", "info", ver)
    res.data["services"] = services
    return res
