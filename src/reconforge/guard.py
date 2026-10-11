"""Authorization guardrails: refuse out-of-scope targets by default."""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse


class ScopeError(Exception):
    pass


def host_of(target: str) -> str:
    t = target.strip()
    if "://" in t:
        return urlparse(t).hostname or ""
    return t.split("/")[0].rsplit(":", 1)[0] if t.count(":") == 1 else t


def validate(target: str) -> str:
    host = host_of(target)
    if not host or host.startswith("-") or any(c in host for c in " ;|&$`\n"):
        raise ScopeError(f"invalid target: {target!r}")
    return host


def _ips(host: str) -> list:
    try:
        return [ipaddress.ip_address(i[4][0]) for i in socket.getaddrinfo(host, None)]
    except (socket.gaierror, ValueError):
        return []


def is_private(host: str) -> bool:
    ips = _ips(host)
    return bool(ips) and all(i.is_private or i.is_loopback or i.is_link_local for i in ips)


def load_scope(path: str) -> list:
    with open(path, encoding="utf-8") as fh:
        return [l.strip() for l in fh if l.strip() and not l.startswith("#")]


def in_scope(host: str, entries: list) -> bool:
    ips = _ips(host)
    for e in entries:
        if "/" in e:
            try:
                net = ipaddress.ip_network(e, strict=False)
            except ValueError:
                continue
            if ips and all(i in net for i in ips):
                return True
        elif host == e or host.endswith("." + e.lstrip("*.")):
            return True
    return False


def check(target: str, authorized: bool = False, scope_file: str | None = None) -> str:
    """Return the validated host or raise ScopeError."""
    host = validate(target)
    if scope_file:  # a scope file is strict: must match even for private hosts
        if in_scope(host, load_scope(scope_file)):
            return host
        raise ScopeError(f"{host} is NOT in scope file {scope_file}")
    if is_private(host) or authorized:
        return host
    raise ScopeError(
        f"{host} is not loopback/private. Re-run with --authorized only if you have "
        "written permission to test it, or supply --scope FILE."
    )
