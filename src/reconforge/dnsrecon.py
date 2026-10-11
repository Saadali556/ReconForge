"""DNS resolution and wordlist subdomain discovery."""
from __future__ import annotations

import secrets
import socket
from concurrent.futures import ThreadPoolExecutor

from .core import Result

DEFAULT_WORDS = ("www mail ftp admin dev test staging api app portal vpn remote blog shop beta cdn "
                 "git gitlab jenkins ns1 ns2 smtp imap webmail intranet dashboard grafana db sql "
                 "static assets media docs support status monitor login sso auth old new demo").split()


def resolve(host: str) -> Result:
    res = Result("dns", host)
    try:
        name, aliases, addrs = socket.gethostbyname_ex(host)
    except socket.gaierror as exc:
        res.add("Resolution failed", "info", str(exc))
        return res
    res.data.update(canonical=name, aliases=aliases, addresses=addrs)
    for a in addrs:
        res.add(f"A record: {a}", "info")
    if name != host:
        res.add(f"CNAME/canonical: {name}", "info")
    try:
        for fam, *_, sa in socket.getaddrinfo(host, None, socket.AF_INET6):
            res.add(f"AAAA record: {sa[0]}", "info")
            break
    except socket.gaierror:
        pass
    return res


def _lookup(fqdn):
    try:
        return fqdn, socket.gethostbyname_ex(fqdn)[2]
    except socket.gaierror:
        return None


def subdomains(domain: str, wordlist: str | None = None, workers: int = 50) -> Result:
    res = Result("subdomains", domain)
    words = DEFAULT_WORDS
    if wordlist:
        with open(wordlist, encoding="utf-8") as fh:
            words = [w.strip() for w in fh if w.strip() and not w.startswith("#")]
    wildcard = _lookup(f"{secrets.token_hex(8)}.{domain}")
    if wildcard:
        res.add("Wildcard DNS detected", "info", "Results filtered to avoid false positives")
    wild_ips = set(wildcard[1]) if wildcard else set()
    with ThreadPoolExecutor(max_workers=workers) as ex:
        hits = [h for h in ex.map(_lookup, (f"{w}.{domain}" for w in words)) if h]
    found = {}
    for fqdn, ips in hits:
        if wild_ips and set(ips) <= wild_ips:
            continue
        found[fqdn] = ips
        res.add(f"{fqdn}", "info", ", ".join(ips))
    res.data["found"] = found
    res.data["tried"] = len(words)
    return res
