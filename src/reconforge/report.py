"""JSON and HTML report writers."""
from __future__ import annotations

import html
import json
import os
import re

from .core import SEVERITIES, now

SCHEMA = "reconforge/1"
_CSS = ("body{font-family:system-ui,sans-serif;margin:2rem auto;max-width:900px;padding:0 1rem;color:#222}"
        "h1{margin-bottom:0}.m{color:#666}table{border-collapse:collapse;width:100%;margin:.5rem 0 1.5rem}"
        "td,th{border:1px solid #ddd;padding:6px 8px;text-align:left;vertical-align:top}"
        ".info{background:#e8f4fb}.low{background:#e9f7ec}.medium{background:#fff6dd}"
        ".high{background:#fde8e8}.critical{background:#f3d1f3}")


def _slug(s: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]+", "_", s)[:60]


def build(results: list) -> dict:
    counts = {s: 0 for s in SEVERITIES}
    for r in results:
        for f in r.findings:
            counts[f.severity] += 1
    return {"schema": SCHEMA, "generated": now(), "summary": counts,
            "results": [r.to_dict() for r in results]}


def to_html(doc: dict) -> str:
    e = html.escape
    out = [f"<!doctype html><meta charset=utf-8><title>ReconForge report</title><style>{_CSS}</style>",
           "<h1>ReconForge report</h1>", f"<p class=m>Generated {e(doc['generated'])}</p>",
           "<h2>Summary</h2><table><tr>" + "".join(f"<th>{s}</th>" for s in SEVERITIES) + "</tr><tr>"
           + "".join(f"<td>{doc['summary'][s]}</td>" for s in SEVERITIES) + "</tr></table>"]
    for r in doc["results"]:
        out.append(f"<h2>{e(r['module'])} &mdash; {e(r['target'])}</h2><table><tr><th>Severity</th><th>Finding</th><th>Detail</th></tr>")
        for f in sorted(r["findings"], key=lambda x: -SEVERITIES.index(x["severity"])):
            out.append(f"<tr class={f['severity']}><td>{f['severity']}</td><td>{e(f['title'])}</td><td>{e(f['detail'])}</td></tr>")
        out.append("</table>")
    return "\n".join(out)


def write(results: list, fmt: str, outdir: str) -> list:
    if fmt == "none":
        return []
    os.makedirs(outdir, exist_ok=True)
    doc = build(results)
    stamp = doc["generated"].replace(":", "").replace("-", "")[:15]
    base = os.path.join(outdir, f"{_slug(results[0].module)}_{_slug(results[0].target)}_{stamp}")
    paths = []
    if fmt in ("json", "both"):
        with open(base + ".json", "w", encoding="utf-8") as fh:
            json.dump(doc, fh, indent=2)
        paths.append(base + ".json")
    if fmt in ("html", "both"):
        with open(base + ".html", "w", encoding="utf-8") as fh:
            fh.write(to_html(doc))
        paths.append(base + ".html")
    return paths
