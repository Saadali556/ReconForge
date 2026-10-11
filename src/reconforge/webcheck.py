"""HTTP security header, cookie, CORS and information-leak checks."""
from __future__ import annotations

import re

from .core import Result
from .http import fetch, normalize

HEADERS = {
    "content-security-policy": ("medium", "Missing Content-Security-Policy"),
    "x-frame-options": ("low", "Missing X-Frame-Options (clickjacking protection)"),
    "x-content-type-options": ("low", "Missing X-Content-Type-Options: nosniff"),
    "referrer-policy": ("low", "Missing Referrer-Policy"),
    "permissions-policy": ("info", "Missing Permissions-Policy"),
}


def check(target: str, timeout: float = 8.0, insecure: bool = False) -> Result:
    url = normalize(target)
    res = Result("web", url)
    status, hdr, _, final = fetch(url, timeout, insecure)
    res.data.update(status=status, final_url=final)
    low = {k.lower(): v for k, v in hdr.items()}

    for name, (sev, msg) in HEADERS.items():
        if name not in low:
            res.add(msg, sev)
    csp = low.get("content-security-policy", "")
    if csp and re.search(r"unsafe-inline|unsafe-eval|\*(?=[\s;]|$)", csp):
        res.add("Weak Content-Security-Policy", "medium", "Contains unsafe-inline/unsafe-eval or wildcard source")
    if final.startswith("https://"):
        if "strict-transport-security" not in low:
            res.add("Missing Strict-Transport-Security (HSTS)", "medium")
    else:
        res.add("Site served over plain HTTP", "low", "Traffic can be intercepted; use HTTPS")

    for h in ("server", "x-powered-by", "x-aspnet-version"):
        if h in low and re.search(r"\d", low[h]):
            res.add(f"Version disclosure in {h} header", "low", low[h])

    https = final.startswith("https://")
    for c in hdr.get_all("Set-Cookie") or []:
        name = c.split("=", 1)[0].strip()
        flags = c.lower()
        missing = [f for f, ok in (("HttpOnly", "httponly" in flags),
                                   ("SameSite", "samesite" in flags),
                                   ("Secure", "secure" in flags or not https)) if not ok]
        if missing:
            res.add(f"Cookie '{name}' missing flags", "medium" if "Secure" in missing or "HttpOnly" in missing else "low",
                    ", ".join(missing))

    try:  # CORS probe
        _, h2, _, _ = fetch(url, timeout, insecure, {"Origin": "https://evil.example"})
        acao = h2.get("Access-Control-Allow-Origin")
        cred = (h2.get("Access-Control-Allow-Credentials") or "").lower() == "true"
        if acao == "https://evil.example":
            res.add("CORS reflects arbitrary Origin", "high" if cred else "medium",
                    "with credentials allowed" if cred else "")
        elif acao == "*":
            res.add("CORS allows any origin (*)", "low")
    except OSError:
        pass
    return res
