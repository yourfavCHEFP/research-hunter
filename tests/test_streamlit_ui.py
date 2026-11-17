"""
Streamlit UI smoke tests.

These run the real streamlit_app.py through Streamlit's AppTest runtime. All
HTTP sources are local fixtures, so the suite never depends on a third party's
uptime.
"""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

import pytest
from streamlit.testing.v1 import AppTest

import verify

WITH_TOKEN = b"""<!doctype html><html><body><main>
<p>The Crown Estate reports strong results and awarded rights totalling 41GW.</p>
</main></body></html>"""

WITHOUT_TOKEN = b"""<!doctype html><html><body><main>
<p>The Crown Estate reports solid results and awarded rights totalling 41GW.</p>
</main></body></html>"""


class _Handler(BaseHTTPRequestHandler):
    """Deterministic document server for the UI smoke tests."""

    def do_GET(self):  # noqa: N802
        routes = {
            "/with-token": (200, "text/html; charset=utf-8", WITH_TOKEN),
            "/without-token": (200, "text/html; charset=utf-8", WITHOUT_TOKEN),
        }
        status, content_type, body = routes.get(
            self.path, (404, "text/html", b"missing")
        )
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


@pytest.mark.parametrize(
    "path, token, expected",
    [
        ("/with-token", "strong results", "PASS"),
        ("/without-token", "strong results", "FAIL"),
    ],
)
def test_ui_displays_engine_result_with_evidence(
    server, tmp_path, monkeypatch, path, token, expected
):
    """The UI must show the engine verdict and its evidence, not invent its own."""
    monkeypatch.setenv("VERIFY_ALLOW_PRIVATE_HOSTS", "1")
    monkeypatch.setenv("VERIFY_SNAPSHOT_DIR", str(tmp_path / "snapshots"))

    at = AppTest.from_file(
        str(Path(__file__).resolve().parent.parent / "streamlit_app.py"),
        default_timeout=90,
    )
    at.run()
    claims = [
        {"id": f"ui-{expected.lower()}", "url": server + path, "must_contain": [token]}
    ]
    at.text_area[0].set_value(json.dumps(claims)).run()
    run_buttons = [b for b in at.button if b.label == "Run verification"]
    assert run_buttons, at.exception
    run_buttons[0].click().run()

    assert not at.exception, [e.message for e in at.exception]
    report = at.session_state["verify_report"]
    result = report["results"][0]
    assert result["verdict"] == expected, result
    assert result["fetched_at"].endswith("Z")
    assert [m.value for m in at.metric if m.label == expected] == ["1"]

    markdown = "\n".join(m.value for m in at.markdown)
    if expected == "PASS":
        assert len(result["sha256"]) == 64
        assert result["snapshot_path"]
        assert token in markdown
    else:
        assert result["tokens"][0]["matched"] is False


def test_ui_reports_unreachable_source_as_unverifiable(tmp_path, monkeypatch):
    """A dead endpoint must not be rendered as FAIL or PASS by the UI."""
    monkeypatch.setenv("VERIFY_ALLOW_PRIVATE_HOSTS", "1")
    monkeypatch.setenv("VERIFY_SNAPSHOT_DIR", str(tmp_path / "snapshots"))

    at = AppTest.from_file(
        str(Path(__file__).resolve().parent.parent / "streamlit_app.py"),
        default_timeout=90,
    )
    at.run()
    claims = [
        {
            "id": "ui-unverifiable",
            "url": "http://127.0.0.1:1/dead",
            "must_contain": ["anything"],
        }
    ]
    at.text_area[0].set_value(json.dumps(claims)).run()
    run_buttons = [b for b in at.button if b.label == "Run verification"]
    assert run_buttons, at.exception
    run_buttons[0].click().run()

    assert not at.exception, [e.message for e in at.exception]
    result = at.session_state["verify_report"]["results"][0]
    assert result["verdict"] == "UNVERIFIABLE", result
    assert result["sha256"] == ""
    assert result["snapshot_path"] == ""
    assert "UNVERIFIABLE" in [m.label for m in at.metric]


def test_recheck_recomputes_summary(server, tmp_path, monkeypatch):
    """Re-checking a row must not leave stale PASS/FAIL metrics or JSON."""
    monkeypatch.setenv("VERIFY_ALLOW_PRIVATE_HOSTS", "1")
    monkeypatch.setenv("VERIFY_SNAPSHOT_DIR", str(tmp_path / "snapshots"))

    at = AppTest.from_file(
        str(Path(__file__).resolve().parent.parent / "streamlit_app.py"),
        default_timeout=90,
    )
    at.run()
    claims = [
        {
            "id": "ui-recheck",
            "url": server + "/with-token",
            "must_contain": ["strong results"],
        }
    ]
    at.text_area[0].set_value(json.dumps(claims)).run()
    [b for b in at.button if b.label == "Run verification"][0].click().run()
    original = at.session_state["verify_report"]
    assert original["summary"]["PASS"] == 1

    def fake_verify(url, must_contain=None, session=None):
        result = json.loads(json.dumps(original["results"][0]))
        result["verdict"] = "FAIL"
        result["reason"] = "recheck changed verdict"
        return result

    monkeypatch.setattr(verify, "verify", fake_verify)
    recheck = [b for b in at.button if b.label == "Re-check this row"]
    assert recheck, at.exception
    recheck[0].click().run()

    report = at.session_state["verify_report"]
    assert report["results"][0]["verdict"] == "FAIL"
    assert report["summary"] == {"PASS": 0, "FAIL": 1, "UNVERIFIABLE": 0}
