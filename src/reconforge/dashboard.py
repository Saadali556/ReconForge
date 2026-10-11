"""Local report dashboard bound to loopback only."""
from __future__ import annotations

import functools
import html
import http.server
import os


def index(outdir: str) -> None:
    files = sorted(f for f in os.listdir(outdir) if f.endswith((".html", ".json")) and f != "index.html")
    rows = "".join(f'<li><a href="{html.escape(f)}">{html.escape(f)}</a></li>' for f in files)
    with open(os.path.join(outdir, "index.html"), "w", encoding="utf-8") as fh:
        fh.write(f"<!doctype html><meta charset=utf-8><title>ReconForge reports</title>"
                 f"<h1>ReconForge reports</h1><ul>{rows or '<li>No reports yet</li>'}</ul>")


def serve(outdir: str, port: int = 8765) -> None:
    os.makedirs(outdir, exist_ok=True)
    index(outdir)
    handler = functools.partial(http.server.SimpleHTTPRequestHandler, directory=outdir)
    with http.server.ThreadingHTTPServer(("127.0.0.1", port), handler) as srv:  # never 0.0.0.0
        print(f"Dashboard: http://127.0.0.1:{port}  (Ctrl+C to stop)")
        try:
            srv.serve_forever()
        except KeyboardInterrupt:
            print("\nStopped.")
