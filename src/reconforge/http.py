"""Tiny HTTP helper (stdlib only)."""
from __future__ import annotations

import ssl
import urllib.error
import urllib.request

UA = "ReconForge/3.1 (authorized security testing)"


def fetch(url: str, timeout: float = 8.0, insecure: bool = False, headers: dict | None = None,
          max_body: int = 200_000):
    """Return (status, headers_obj, body_text). Raises OSError on connection failure."""
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    req = urllib.request.Request(url, headers={"User-Agent": UA, **(headers or {})})
    try:
        resp = urllib.request.urlopen(req, timeout=timeout, context=ctx)
    except urllib.error.HTTPError as exc:  # still has headers/body
        resp = exc
    except urllib.error.URLError as exc:
        raise OSError(str(exc.reason)) from exc
    body = resp.read(max_body).decode("utf-8", "replace")
    return resp.status if hasattr(resp, "status") else resp.code, resp.headers, body, resp.geturl()


def normalize(target: str) -> str:
    return target if "://" in target else "http://" + target
