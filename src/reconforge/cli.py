"""ReconForge command line interface."""
from __future__ import annotations

import argparse
import sys
import time
from urllib.parse import urlparse

from . import __version__, banner, cve, dashboard, dnsrecon, guard, nmapwrap, report, scanner, tech, tlscheck, webcheck
from .core import print_results

BANNER = "ReconForge - toolkit for AUTHORIZED security testing only"


def build_parser() -> argparse.ArgumentParser:
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument("--target", required=True, help="host, IP or URL")
    common.add_argument("--timeout", type=float, default=5.0, help="network timeout in seconds")
    common.add_argument("--report", choices=["none", "json", "html", "both"], default="none")
    common.add_argument("--output-dir", default="reports")
    common.add_argument("--authorized", action="store_true",
                        help="confirm you have written permission to test a non-private target")
    common.add_argument("--scope", metavar="FILE", help="scope file (hosts, domains, CIDRs); strictly enforced")
    common.add_argument("--no-banner", action="store_true", default=argparse.SUPPRESS, help="hide the startup banner")
    common.add_argument("--insecure", action="store_true", help="skip TLS certificate verification (web/tech)")

    p = argparse.ArgumentParser(prog="reconforge", description=BANNER)
    p.add_argument("--version", action="version", version=f"reconforge {__version__}")
    p.add_argument("--no-banner", action="store_true", help="hide the startup banner")
    sub = p.add_subparsers(dest="cmd")

    s = sub.add_parser("scan", parents=[common], help="concurrent TCP port scan with banners")
    s.add_argument("--ports", default="common", help="common | top1000 | 1-1024 | 22,80,443")
    s.add_argument("--workers", type=int, default=100)
    n = sub.add_parser("nmap", parents=[common], help="Nmap service/version scan (parsed)")
    n.add_argument("--ports", help="e.g. 22,80,8080 (default: top 100)")
    sub.add_parser("dns", parents=[common], help="DNS A/AAAA records and aliases")
    d = sub.add_parser("subdomains", parents=[common], help="wordlist subdomain discovery")
    d.add_argument("--wordlist")
    sub.add_parser("web", parents=[common], help="headers, cookies, CORS, version leaks")
    sub.add_parser("tech", parents=[common], help="web technology detection")
    t = sub.add_parser("tls", parents=[common], help="TLS certificate/protocol inspection")
    t.add_argument("--port", type=int, default=443)
    c = sub.add_parser("cve", help="NVD CVE keyword lookup (cached)")
    c.add_argument("--keyword", required=True, help='e.g. "apache 2.4.7"')
    c.add_argument("--limit", type=int, default=10)
    c.add_argument("--api-key", help="NVD API key (or NVD_API_KEY env var)")
    c.add_argument("--no-banner", action="store_true", default=argparse.SUPPRESS, help="hide the startup banner")
    c.add_argument("--report", choices=["none", "json", "html", "both"], default="none")
    c.add_argument("--output-dir", default="reports")
    a = sub.add_parser("all", parents=[common], help="run scan, web, tech, tls and dns in one go")
    a.add_argument("--ports", default="common")
    db = sub.add_parser("dashboard", help="serve saved reports on 127.0.0.1")
    db.add_argument("--output-dir", default="reports")
    db.add_argument("--no-banner", action="store_true", default=argparse.SUPPRESS, help="hide the startup banner")
    db.add_argument("--port", type=int, default=8765)
    return p


def _all(args, host: str) -> list:
    results = []
    sc = scanner.scan(host, scanner.parse_ports(args.ports), min(args.timeout, 2.0))
    results.append(sc)
    for port in sc.data["open_ports"]:
        if port in scanner.HTTP_PORTS | scanner.HTTPS_PORTS:
            scheme = "https" if port in scanner.HTTPS_PORTS else "http"
            url = f"{scheme}://{host}:{port}"
            for fn in (webcheck.check, tech.detect):
                try:
                    results.append(fn(url, args.timeout, args.insecure))
                except OSError as exc:
                    r = fn.__module__.split(".")[-1]
                    print(f"[!] {r} {url}: {exc}", file=sys.stderr)
        if port in scanner.HTTPS_PORTS:
            try:
                results.append(tlscheck.inspect(host, port, args.timeout))
            except OSError as exc:
                print(f"[!] tls {host}:{port}: {exc}", file=sys.stderr)
    if not host.replace(".", "").isdigit():
        results.append(dnsrecon.resolve(host))
    return results


def run(args) -> list:
    if args.cmd == "cve":
        return [cve.lookup(args.keyword, args.limit, args.api_key)]
    host = guard.check(args.target, args.authorized, args.scope)
    if args.cmd == "scan":
        return [scanner.scan(host, scanner.parse_ports(args.ports), args.timeout, args.workers)]
    if args.cmd == "nmap":
        return [nmapwrap.run(host, args.ports)]
    if args.cmd == "dns":
        return [dnsrecon.resolve(host)]
    if args.cmd == "subdomains":
        return [dnsrecon.subdomains(host, args.wordlist)]
    if args.cmd == "web":
        return [webcheck.check(args.target, args.timeout, args.insecure)]
    if args.cmd == "tech":
        return [tech.detect(args.target, args.timeout, args.insecure)]
    if args.cmd == "tls":
        port = urlparse(args.target).port or args.port if "://" in args.target else args.port
        return [tlscheck.inspect(host, port, args.timeout)]
    if args.cmd == "all":
        return _all(args, host)
    raise SystemExit(2)


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.no_banner:
        banner.show()
    if not args.cmd:
        parser.print_help()
        return 0
    if args.cmd == "dashboard":
        dashboard.serve(args.output_dir, args.port)
        return 0
    banner.status(f"Module: {args.cmd}   Target: {getattr(args, 'target', None) or getattr(args, 'keyword', '-')}")
    t0 = time.time()
    try:
        results = run(args)
    except guard.ScopeError as exc:
        print(f"[scope] {exc}", file=sys.stderr)
        return 3
    except (OSError, ValueError) as exc:
        print(f"[error] {exc}", file=sys.stderr)
        return 1
    print_results(results)
    banner.summary(results, time.time() - t0)
    for path in report.write(results, args.report, args.output_dir):
        print(f"\nReport saved: {path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
