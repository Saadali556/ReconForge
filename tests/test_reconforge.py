import http.server
import json
import socket
import threading

import pytest

from reconforge import guard, report, scanner, webcheck, cve
from reconforge.cli import main


class H(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Server", "Apache/2.4.7")
        self.send_header("Set-Cookie", "sid=1; Path=/")
        self.send_header("Access-Control-Allow-Origin", self.headers.get("Origin", ""))
        self.end_headers()
        self.wfile.write(b"<html>hello</html>")

    def log_message(self, *a):
        pass


@pytest.fixture()
def server():
    srv = http.server.HTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


def test_parse_ports():
    assert scanner.parse_ports("22,80,1-3") == [1, 2, 3, 22, 80]
    with pytest.raises(ValueError):
        scanner.parse_ports("70000")


def test_scan_finds_open_port(server):
    r = scanner.scan("127.0.0.1", [server, 1], timeout=0.5)
    assert r.data["open_ports"] == [server]


def test_web_findings(server):
    r = webcheck.check(f"http://127.0.0.1:{server}")
    titles = " ".join(f.title for f in r.findings)
    assert "Missing Content-Security-Policy" in titles
    assert "Version disclosure" in titles
    assert "Cookie 'sid'" in titles
    assert "CORS reflects" in titles


def test_guard_blocks_public_without_flag(monkeypatch):
    monkeypatch.setattr(guard, "_ips", lambda h: [guard.ipaddress.ip_address("93.184.216.34")])
    with pytest.raises(guard.ScopeError):
        guard.check("example.com")
    assert guard.check("example.com", authorized=True) == "example.com"


def test_guard_rejects_injection():
    with pytest.raises(guard.ScopeError):
        guard.check("-oN /tmp/x")
    with pytest.raises(guard.ScopeError):
        guard.check("127.0.0.1;ls")


def test_scope_file(tmp_path):
    f = tmp_path / "s.txt"
    f.write_text("10.0.0.0/8\nexample.com\n")
    assert guard.in_scope("10.1.2.3", guard.load_scope(str(f)))
    assert guard.in_scope("a.example.com", guard.load_scope(str(f)))
    assert not guard.in_scope("127.0.0.1", guard.load_scope(str(f)))


def test_report_roundtrip(server, tmp_path):
    r = scanner.scan("127.0.0.1", [server], timeout=0.5)
    paths = report.write([r], "both", str(tmp_path))
    doc = json.load(open([p for p in paths if p.endswith(".json")][0]))
    assert doc["schema"] == "reconforge/1" and doc["results"][0]["module"] == "scan"
    assert "<table>" in open([p for p in paths if p.endswith(".html")][0]).read()


def test_cve_parse():
    payload = {"vulnerabilities": [{"cve": {"id": "CVE-1", "descriptions": [{"lang": "en", "value": "x"}],
               "metrics": {"cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]}}}]}
    assert cve.parse(payload)[0]["score"] == 9.8


def test_cli_scope_refusal(monkeypatch, capsys):
    monkeypatch.setattr(guard, "_ips", lambda h: [guard.ipaddress.ip_address("8.8.8.8")])
    assert main(["scan", "--target", "example.org"]) == 3


def test_banner_render_and_quiet(capsys):
    from reconforge import banner
    out = banner.render(80)
    assert "██" in out and "Authorized testing only" in out
    banner.show()  # not a tty under pytest -> prints nothing
    assert capsys.readouterr().err == ""
    banner.show(force=True)
    assert "Authorized" in capsys.readouterr().err


def test_no_args_shows_help(capsys):
    assert main(["--no-banner"]) == 0
    assert "usage: reconforge" in capsys.readouterr().out


def test_no_banner_flag_after_subcommand(server, capsys):
    assert main(["scan", "--target", "127.0.0.1", "--ports", str(server), "--no-banner"]) == 0
    assert "open" in capsys.readouterr().out
