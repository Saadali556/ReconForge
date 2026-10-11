# ReconForge

Zero-dependency (standard library only) toolkit for **authorized** security reconnaissance.
Use it only on systems you own or have written permission to test.

## Terminal experience
Running `reconforge` in an interactive terminal shows a gradient ASCII banner, a status line for the
current module and target, and a severity summary at the end. Everything is skipped automatically when
output is piped. Use `--no-banner`, `RECONFORGE_NO_BANNER=1` or `NO_COLOR=1` to turn it off.

## Install
```
python3 -m venv .venv && source .venv/bin/activate
python -m pip install -e .
reconforge --version
```

## Commands
| Command | What it does |
|---|---|
| `scan` | Concurrent TCP scan, banner grabbing, flags risky exposed services |
| `nmap` | Runs Nmap (`-sV`) and parses its XML output |
| `dns` | A/AAAA records and aliases |
| `subdomains` | Wordlist discovery with wildcard-DNS filtering |
| `web` | Security headers, weak CSP, cookie flags, CORS, version leaks |
| `tech` | Technology fingerprinting |
| `tls` | Trust, expiry, protocol and cipher checks |
| `cve` | NVD keyword lookup, cached 24h, CVSS-sorted (`NVD_API_KEY` supported) |
| `all` | Scan, then web/tech/tls/dns on what is found, one combined report |
| `dashboard` | Serves saved reports on `127.0.0.1` only |

## Examples (local DVWA)
```
docker run --rm -d -p 8080:80 --name dvwa vulnerables/web-dvwa
reconforge scan --target 127.0.0.1 --ports 1-10000
reconforge web  --target http://127.0.0.1:8080 --report both
reconforge all  --target 127.0.0.1 --ports 80,8080 --report both
reconforge cve  --keyword "apache 2.4.25"
reconforge dashboard
```

## Safety guardrails
- Loopback/private targets are allowed by default.
- Anything else is refused unless you pass `--authorized` (written permission) or a `--scope FILE`.
- With `--scope FILE`, targets must match the file, even private ones (see `scope.example.txt`).
- The dashboard never binds to anything except `127.0.0.1`.
- Exit codes: 0 ok, 1 error, 3 refused by scope.

## Reports
`--report json|html|both` writes to `--output-dir` (default `reports/`). Findings carry severity
(info/low/medium/high/critical); JSON schema id is `reconforge/1`.

## Tests
```
python -m pip install -e ".[dev]" && pytest
```
