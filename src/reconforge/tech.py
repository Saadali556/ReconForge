"""Web technology fingerprinting."""
from __future__ import annotations

import re

from .core import Result
from .http import fetch, normalize

BODY_SIGS = [
    (r"wp-content|wp-includes", "WordPress"), (r"Joomla!", "Joomla"), (r"Drupal", "Drupal"),
    (r"jquery[.-]?(\d+\.\d+(?:\.\d+)?)", "jQuery"), (r"bootstrap[.@/-]v?(\d+\.\d+(?:\.\d+)?)", "Bootstrap"),
    (r"react(?:\.min)?\.js|data-reactroot", "React"), (r"ng-version=\"([\d.]+)\"", "Angular"),
    (r"Damn Vulnerable Web", "DVWA"),
]
HEADER_SIGS = ["server", "x-powered-by", "x-generator", "via", "x-aspnet-version"]


def detect(target: str, timeout: float = 8.0, insecure: bool = False) -> Result:
    url = normalize(target)
    res = Result("tech", url)
    _, hdr, body, _ = fetch(url, timeout, insecure)
    techs = {}
    for h in HEADER_SIGS:
        if hdr.get(h):
            techs[h] = hdr[h]
    for pat, name in BODY_SIGS:
        m = re.search(pat, body, re.I)
        if m:
            techs[name] = m.group(1) if m.groups() else "detected"
    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    if gen:
        techs["generator"] = gen.group(1)
    res.data["technologies"] = techs
    for k, v in techs.items():
        res.add(f"{k}: {v}", "info")
    return res
