"""NVD CVE lookup with local caching and optional API key."""
from __future__ import annotations

import hashlib
import json
import os
import time
import urllib.parse
import urllib.request

from .core import Result

API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
CACHE = os.path.join(os.path.expanduser("~"), ".cache", "reconforge")


def _sev(score: float) -> str:
    return "critical" if score >= 9 else "high" if score >= 7 else "medium" if score >= 4 else "low"


def _score(cve: dict):
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        m = cve.get("metrics", {}).get(key)
        if m:
            return m[0]["cvssData"]["baseScore"]
    return None


def parse(payload: dict) -> list:
    out = []
    for item in payload.get("vulnerabilities", []):
        c = item["cve"]
        desc = next((d["value"] for d in c.get("descriptions", []) if d["lang"] == "en"), "")
        out.append({"id": c["id"], "score": _score(c), "summary": desc})
    return sorted(out, key=lambda x: -(x["score"] or 0))


def lookup(keyword: str, limit: int = 10, api_key: str | None = None, ttl: int = 86400,
           timeout: float = 20.0) -> Result:
    res = Result("cve", keyword)
    api_key = api_key or os.environ.get("NVD_API_KEY")
    url = f"{API}?{urllib.parse.urlencode({'keywordSearch': keyword, 'resultsPerPage': limit})}"
    path = os.path.join(CACHE, hashlib.sha256(url.encode()).hexdigest() + ".json")
    payload = None
    if os.path.exists(path) and time.time() - os.path.getmtime(path) < ttl:
        with open(path, encoding="utf-8") as fh:
            payload = json.load(fh)
        res.data["cached"] = True
    if payload is None:
        req = urllib.request.Request(url, headers={"User-Agent": "ReconForge/3.1", **({"apiKey": api_key} if api_key else {})})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as r:
                payload = json.load(r)
        except Exception as exc:  # network, 403/429 rate limit, etc.
            res.add("NVD lookup failed", "low", f"{exc} (set NVD_API_KEY to raise rate limits)")
            return res
        os.makedirs(CACHE, exist_ok=True)
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(payload, fh)
    items = parse(payload)
    res.data["total"] = payload.get("totalResults", len(items))
    for i in items:
        sc = i["score"]
        res.add(f"{i['id']} (CVSS {sc if sc is not None else 'n/a'})", _sev(sc) if sc is not None else "info",
                i["summary"][:200])
    return res
