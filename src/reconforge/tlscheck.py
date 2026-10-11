"""TLS inspection: trust, expiry, protocol, cipher."""
from __future__ import annotations

import datetime as dt
import socket
import ssl

from .core import Result


def _connect(host, port, timeout, verify):
    ctx = ssl.create_default_context()
    if not verify:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=host) as s:
            return s.getpeercert(), s.version(), s.cipher()


def inspect(host: str, port: int = 443, timeout: float = 6.0) -> Result:
    res = Result("tls", f"{host}:{port}")
    cert = None
    try:
        cert, version, cipher = _connect(host, port, timeout, True)
    except ssl.SSLCertVerificationError as exc:
        res.add("Certificate not trusted", "high", exc.verify_message)
        cert, version, cipher = _connect(host, port, timeout, False)
    res.data.update(protocol=version, cipher=cipher[0] if cipher else None)
    if version in ("TLSv1", "TLSv1.1", "SSLv3"):
        res.add(f"Obsolete protocol negotiated: {version}", "high")
    elif version:
        res.add(f"Protocol: {version}", "info")
    if cipher and any(w in cipher[0] for w in ("RC4", "3DES", "NULL", "EXPORT", "MD5")):
        res.add(f"Weak cipher: {cipher[0]}", "high")
    if cert:
        exp = dt.datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), dt.timezone.utc)
        days = (exp - dt.datetime.now(dt.timezone.utc)).days
        res.data["expires"] = exp.date().isoformat()
        res.data["days_left"] = days
        sev = "high" if days < 0 else "medium" if days < 14 else "low" if days < 30 else "info"
        res.add("Certificate expired" if days < 0 else f"Certificate expires in {days} days", sev)
        subj = dict(x[0] for x in cert.get("subject", ()))
        res.data["subject"] = subj.get("commonName")
    return res
