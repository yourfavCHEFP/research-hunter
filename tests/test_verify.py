"""
Verification engine tests.

Most tests use a local HTTP server, so they exercise the real requests ->
resolve -> fetch -> containment -> verdict path without depending on a third
party's uptime. A live-network smoke test is included but skipped unless
RUN_LIVE_VERIFY=1 is set.

Run:
    python3 -m pytest tests/test_verify.py -v
"""
import hashlib
import json
import os
import subprocess
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

# The tests run their own HTTP server on 127.0.0.1. Opt in explicitly; the
# deployed verifier blocks private hosts by default.
os.environ["VERIFY_ALLOW_PRIVATE_HOSTS"] = "1"

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import app as flask_app  # noqa: E402
import connectors  # noqa: E402
import config  # noqa: E402
import verify  # noqa: E402


PAGE_WITH_TOKEN = """<!doctype html>
<html><head><title>Offshore wind</title><style>.x{color:red}</style></head>
<body>
<nav>Skip to content</nav>
<main><h1>Offshore wind</h1>
<p>The Crown Estate reports strong results and awarded rights totalling 41GW.</p>
<p>There are six projects in Round 4.</p>
</main>
<script>var hidden = 'strong results should not be found in script';</script>
</body></html>"""

PAGE_WITHOUT_TOKEN = """<!doctype html>
<html><body><main>
<p>The Crown Estate reports solid results and awarded rights totalling 41GW.</p>
<p>There are seven projects in Round 4.</p>
</main></body></html>"""

NUMBER_PAGE_10_5 = """<!doctype html><html><body><main>
<p>Offshore capacity reached 10.5 GW in 2024.</p>
</main></body></html>"""

NUMBER_PAGE_10 = """<!doctype html><html><body><main>
<p>Offshore capacity reached 10 GW in 2024.</p>
</main></body></html>"""


class _Handler(BaseHTTPRequestHandler):
    """Deterministic document server for the verification tests."""

    def do_GET(self):  # noqa: N802
        routes = {
            "/with-token": (200, "text/html; charset=utf-8", PAGE_WITH_TOKEN),
            "/without-token": (200, "text/html; charset=utf-8", PAGE_WITHOUT_TOKEN),
            "/number-10-5": (200, "text/html; charset=utf-8", NUMBER_PAGE_10_5),
            "/number-10": (200, "text/html; charset=utf-8", NUMBER_PAGE_10),
            "/not-document": (200, "image/png", b"\x89PNG\r\n\x1a\nnot a document"),
            "/empty": (200, "text/html; charset=utf-8", b""),
            "/redirect": (302, "text/html", b""),
        }
        if self.path == "/redirect":
            self.send_response(302)
            self.send_header("Location", "/with-token")
            self.end_headers()
            return
        status, content_type, body = routes.get(
            self.path, (404, "text/html; charset=utf-8", b"<h1>Not Found</h1>strong results")
        )
        if isinstance(body, str):
            body = body.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{httpd.server_address[1]}"
    finally:
        httpd.shutdown()
        httpd.server_close()
        thread.join(timeout=5)


@pytest.fixture(autouse=True)
def isolated_snapshots(tmp_path, monkeypatch):
    """Keep snapshots out of the repository and assert their contents later."""
    monkeypatch.setattr(config, "SNAPSHOT_DIR", str(tmp_path))
    return tmp_path


def test_pass_on_real_fetched_page(server):
    result = verify.verify(f"{server}/with-token", ["strong results"])

    assert result["verdict"] == verify.PASS, result
    assert result["status"] == 200
    assert result["content_type"].startswith("text/html")
    assert result["bytes"] > 0
    assert result["final_url"] == f"{server}/with-token"
    assert result["tokens"][0]["matched"] is True
    assert "reports strong results" in result["tokens"][0]["span"]["quote"]
    assert result["sha256"] and len(result["sha256"]) == 64
    assert result["fetched_at"].endswith("Z")
    assert result["snapshot_path"]

    with open(result["snapshot_path"], "r", encoding="utf-8") as fh:
        snapshot = fh.read()
    assert hashlib.sha256(snapshot.encode("utf-8")).hexdigest() == result["sha256"]
    assert "reports strong results" in snapshot
    assert "should not be found in script" not in snapshot
    assert "Skip to content" not in snapshot


def test_fail_when_token_absent(server):
    result = verify.verify(f"{server}/without-token", ["strong results"])

    assert result["verdict"] == verify.FAIL
    assert result["status"] == 200
    assert result["tokens"][0]["matched"] is False
    assert "strong results" in result["reason"]
    # A near miss is diagnostic only; it must never turn into a PASS.
    assert result["tokens"][0]["near_miss"] is not None


def test_fail_on_dead_url_404_no_containment(server):
    result = verify.verify(
        f"{server}/definitely-missing",
        ["strong results"],
    )

    assert result["verdict"] == verify.FAIL
    assert result["status"] == 404
    assert result["sha256"] == ""
    assert result["snapshot_path"] == ""
    assert result["tokens"][0]["matched"] is False
    assert "not checked" in result["tokens"][0].get("error", "")
    assert any("404" in e for e in result["errors"])


def test_unreachable_host_is_unverifiable_not_fail():
    # Port 1 on loopback is reserved and nothing should be listening there.
    result = verify.verify("http://127.0.0.1:1/dead", ["anything"])

    assert result["verdict"] == verify.UNVERIFIABLE
    assert result["status"] == 0
    assert result["sha256"] == ""


def test_non_document_content_type_is_hard_fail(server):
    result = verify.verify(f"{server}/not-document", ["anything"])

    assert result["verdict"] == verify.FAIL
    assert result["status"] == 200
    assert "image/png" in result["reason"]
    assert result["sha256"] == ""
    assert result["tokens"][0]["matched"] is False


@pytest.mark.parametrize(
    "text, token, should_match",
    [
        ("Output reached 10.5 GW.", "10", False),
        ("Output reached 10 GW.", "10", True),
        ("Output reached 100 GW.", "10", False),
        ("Output reached 10,000 GW.", "10", False),
        ("Output reached 41.0GW.", "41GW", True),
        ("Output reached 141GW.", "41GW", False),
        ("There are six projects.", "six projects", True),
        ("There are 6 projects.", "six projects", True),
        ("There are seven projects.", "six projects", False),
    ],
)
def test_number_boundary_containment(text, token, should_match):
    result = verify.check_tokens(text, [token])[0]
    assert result["matched"] is should_match, (text, token, result)


def test_number_boundary_10_vs_10_5_end_to_end(server):
    miss = verify.verify(f"{server}/number-10-5", ["10"])
    hit = verify.verify(f"{server}/number-10", ["10"])

    assert miss["verdict"] == verify.FAIL
    assert hit["verdict"] == verify.PASS


def test_redirect_is_recorded(server):
    result = verify.verify(f"{server}/redirect", ["strong results"])

    assert result["verdict"] == verify.PASS
    assert result["final_url"] == f"{server}/with-token"
    assert result["redirect_chain"][0] == f"{server}/redirect"
    assert result["url"] == f"{server}/redirect"


def test_all_tokens_must_match(server):
    result = verify.verify(
        f"{server}/with-token",
        ["strong results", "six projects", "a phrase that is not here"],
    )

    assert result["verdict"] == verify.FAIL
    assert [t["matched"] for t in result["tokens"]] == [True, True, False]
    assert "a phrase that is not here" in result["reason"]


def test_no_tokens_is_unverifiable_not_vacuous_pass(server):
    result = verify.verify(f"{server}/with-token", [])
    assert result["verdict"] == verify.UNVERIFIABLE
    assert "no must_contain" in result["reason"]


def test_batch_report_and_exit_codes(server):
    claims = [
        {"id": "pass", "url": f"{server}/with-token", "must_contain": ["strong results"]},
        {"id": "fail", "url": f"{server}/without-token", "must_contain": ["strong results"]},
    ]
    results = verify.verify_batch(claims)
    assert [r["claim_id"] for r in results] == ["pass", "fail"]
    assert [r["verdict"] for r in results] == [verify.PASS, verify.FAIL]

    # Human CLI: any FAIL means exit code 1, and the report file has both rows.
    claims_file = os.path.join(str(isolated_tmp := "/tmp"), "verify_claims_test.json")
    with open(claims_file, "w", encoding="utf-8") as fh:
        json.dump(claims, fh)
    report_file = "/tmp/verify_report_test.json"
    proc = subprocess.run(
        [sys.executable, "verify.py", "--batch", claims_file, "--json", "--out", report_file],
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 1, proc.stderr
    with open(report_file, "r", encoding="utf-8") as fh:
        report = json.load(fh)
    assert report["summary"] == {"PASS": 1, "FAIL": 1, "UNVERIFIABLE": 0}

    # Single-item CLI: PASS -> exit 0.
    proc = subprocess.run(
        [sys.executable, "verify.py", "--url", f"{server}/with-token",
         "--must-contain", "strong results", "--json"],
        cwd=os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        capture_output=True,
        text=True,
        timeout=120,
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["verdict"] == verify.PASS


def test_flask_api_verify_route(server):
    client = flask_app.app.test_client()
    response = client.post(
        "/api/verify",
        json={"url": f"{server}/with-token", "must_contain": ["41GW"]},
    )
    assert response.status_code == 200
    body = response.get_json()
    assert body["verdict"] == verify.PASS
    assert body["tokens"][0]["matched"] is True
    assert body["fetched_at"].endswith("Z")

    bad = client.post("/api/verify", json={"url": "", "must_contain": ["x"]})
    assert bad.status_code == 400


def test_keyed_connectors_omit_when_no_key(monkeypatch):
    """Missing keys must produce an empty list, never a crash or a fake result."""
    monkeypatch.setattr(connectors, "COMPANIES_HOUSE_API_KEY", "")
    monkeypatch.setattr(connectors, "COURTLISTENER_API_KEY", "")

    assert connectors.search_companies_house("energy", 5) == []
    assert connectors.search_courtlistener("energy", 5) == []

    # The registry still advertises them, but the UI marks them unavailable.
    for key in ("companies_house", "courtlistener", "core", "fred"):
        spec = connectors.CONNECTORS[key]
        assert spec["needs_key"] is True
        assert flask_app._source_available(spec) is False

    for key, spec in connectors.CONNECTORS.items():
        if not spec["needs_key"]:
            assert flask_app._source_available(spec) is True


@pytest.mark.skipif(os.environ.get("RUN_LIVE_VERIFY") != "1", reason="set RUN_LIVE_VERIFY=1 for live network smoke test")
def test_live_crown_estate_41gw():
    result = verify.verify(
        "https://www.thecrownestate.co.uk/about-us/case-study-round-4",
        ["41GW"],
    )
    assert result["verdict"] == verify.PASS, result["errors"]

def test_ssrf_guard_blocks_private_hosts(monkeypatch):
 """Public deployment must not fetch localhost or cloud metadata."""
 monkeypatch.setattr(config, "VERIFY_ALLOW_PRIVATE_HOSTS", False)
 for url in (
  "http://127.0.0.1:5050/api/sources",
  "http://localhost:5050",
  "http://169.254.169.254/latest/meta-data/",
  "http://192.168.1.1/",
  "file:///etc/passwd",
 ):
  result = verify.resolve(url)
  assert result["status"] == 0, url
  assert result["error"].startswith("blocked URL:"), (url, result["error"])


def test_ssrf_guard_blocks_redirect_to_private(monkeypatch):
 """Each redirect hop is revalidated, not just the first URL."""
 class FakeResponse:
  status_code = 302
  url = "https://public.example.test/start"
  headers = {"Location": "http://127.0.0.1:5050/admin"}
  def close(self):
   pass
 class FakeSession:
  def get(self, *a, **kw):
   return FakeResponse()
 monkeypatch.setattr(config, "VERIFY_ALLOW_PRIVATE_HOSTS", False)
 monkeypatch.setattr(verify, "_dns_addresses", lambda host: ("93.184.216.34",))
 result = verify.resolve("https://public.example.test/start", session=FakeSession())
 assert result["error"].startswith("blocked URL:"), result
 assert "127.0.0.1" in result["error"], result


def test_dns_failure_is_unverifiable_not_fail(monkeypatch):
 """A hostname with no DNS answer is unknown, not a disproved claim."""
 monkeypatch.setattr(config, "VERIFY_ALLOW_PRIVATE_HOSTS", False)
 monkeypatch.setattr(verify, "_dns_addresses", lambda host: ())
 result = verify.verify("https://no-such-host.example.test/claim", ["anything"])
 assert result["verdict"] == verify.UNVERIFIABLE, result
 assert result["status"] == 0
 assert result["sha256"] == ""
 assert "could not reach source" in result["reason"]


def test_blocked_private_host_remains_hard_fail(monkeypatch):
 """Fixing DNS classification must not soften the SSRF refusal."""
 monkeypatch.setattr(config, "VERIFY_ALLOW_PRIVATE_HOSTS", False)
 result = verify.verify("http://127.0.0.1:5050/admin", ["anything"])
 assert result["verdict"] == verify.FAIL, result
 assert any(e.startswith("blocked URL:") for e in result["errors"]), result["errors"]


def test_empty_200_body_is_unverifiable(server):
    """A 200 with no document text is unknown, not a disproved claim."""
    result = verify.verify(f"{server}/empty", ["anything"])
    assert result["verdict"] == verify.UNVERIFIABLE, result
    assert result["status"] == 200
    assert "empty response body" in result["reason"]


def test_oversized_response_is_unverifiable(server, monkeypatch):
    """A truncated download cannot be used as evidence."""
    monkeypatch.setattr(config, "VERIFY_MAX_BYTES", 64)
    result = verify.verify(f"{server}/with-token", ["strong results"])
    assert result["verdict"] == verify.UNVERIFIABLE, result
    assert result["status"] == 200
    assert "byte limit" in result["reason"]


def test_snapshot_write_failure_is_unverifiable(server, monkeypatch):
    """PASS requires the exact hashed text to exist on disk."""
    monkeypatch.setattr(verify, "_write_snapshot", lambda sha, text: "")
    result = verify.verify(f"{server}/with-token", ["strong results"])
    assert result["verdict"] == verify.UNVERIFIABLE, result
    assert result["sha256"]
    assert result["snapshot_path"] == ""
    assert "snapshot" in result["reason"].lower()


def test_literal_ip_non_web_port_is_blocked(monkeypatch):
    """Literal IPs must obey the same public-web-port allowlist as hosts."""
    monkeypatch.setattr(config, "VERIFY_ALLOW_PRIVATE_HOSTS", False)
    result = verify.resolve("http://8.8.8.8:22/")
    assert result["status"] == 0
    assert result["error"].startswith("blocked URL:"), result
    assert "port" in result["error"]
