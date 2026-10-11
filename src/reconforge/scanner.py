"""Concurrent TCP connect scanner with banner grabbing."""
from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor

from .core import Result

COMMON = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995, 1433,
          1521, 2049, 3000, 3306, 3389, 5000, 5432, 5900, 6379, 8000, 8080, 8443, 8888, 9200, 27017]
RISKY = {21: "FTP", 23: "Telnet", 445: "SMB", 3389: "RDP", 6379: "Redis", 27017: "MongoDB",
         9200: "Elasticsearch", 1433: "MSSQL", 3306: "MySQL", 5432: "PostgreSQL", 5900: "VNC"}
HTTP_PORTS = {80, 3000, 5000, 8000, 8080, 8888}
HTTPS_PORTS = {443, 8443}


def parse_ports(spec: str) -> list:
    if spec == "common":
        return list(COMMON)
    if spec == "top1000":
        return list(range(1, 1001))
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if "-" in part:
            a, b = part.split("-", 1)
            ports.update(range(int(a), int(b) + 1))
        elif part:
            ports.add(int(part))
    bad = [p for p in ports if not 1 <= p <= 65535]
    if bad:
        raise ValueError(f"ports out of range: {bad[:3]}")
    return sorted(ports)


def _probe(host: str, port: int, timeout: float):
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.settimeout(min(timeout, 1.0))
            banner = ""
            try:
                if port in HTTP_PORTS:
                    s.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = s.recv(256).decode("latin-1", "replace").strip().splitlines()[0][:120]
            except (OSError, IndexError):
                pass
            return port, banner
    except OSError:
        return None


def scan(host: str, ports: list, timeout: float = 1.0, workers: int = 100) -> Result:
    res = Result("scan", host)
    with ThreadPoolExecutor(max_workers=max(1, min(workers, 500))) as ex:
        found = [r for r in ex.map(lambda p: _probe(host, p, timeout), ports) if r]
    found.sort()
    res.data["scanned"] = len(ports)
    res.data["open_ports"] = [p for p, _ in found]
    res.data["banners"] = {p: b for p, b in found if b}
    for p, b in found:
        sev = "medium" if p in RISKY else "info"
        label = f" ({RISKY[p]} exposed)" if p in RISKY else ""
        res.add(f"Port {p}/tcp open{label}", sev, b)
    return res
