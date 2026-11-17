"""Tests for the stdio MCP adapter around verify.py."""
import json
import subprocess
import sys
from pathlib import Path

import pytest

import mcp_server


ROOT = Path(__file__).resolve().parent.parent


def test_initialize_advertises_tools_without_model_claims():
    response = mcp_server.handle_request({
        "jsonrpc": "2.0",
        "id": 1,
        "method": "initialize",
        "params": {"protocolVersion": "2025-06-18"},
    })
    result = response["result"]
    assert result["protocolVersion"] == "2025-06-18"
    assert result["capabilities"]["tools"] == {}
    assert result["serverInfo"]["name"] == "research-hunter"
    assert response["id"] == 1


def test_tools_list_exposes_only_verifier_entrypoints():
    response = mcp_server.handle_request({
        "jsonrpc": "2.0",
        "id": 2,
        "method": "tools/list",
    })
    names = [tool["name"] for tool in response["result"]["tools"]]
    assert names == ["verify_claim", "verify_batch"]


def test_verify_claim_delegates_to_engine_and_returns_text(monkeypatch):
    seen = {}

    def fake_verify(url, must_contain=None, session=None):
        seen["args"] = (url, must_contain, session)
        return {"verdict": "PASS", "sha256": "abc", "url": url}

    monkeypatch.setattr(mcp_server.verify, "verify", fake_verify)
    response = mcp_server.handle_request({
        "jsonrpc": "2.0",
        "id": 3,
        "method": "tools/call",
        "params": {
            "name": "verify_claim",
            "arguments": {
                "url": "https://example.test/doc",
                "must_contain": ["41GW"],
            },
        },
    })
    assert seen["args"] == ("https://example.test/doc", ["41GW"], None)
    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload == {"verdict": "PASS", "sha256": "abc", "url": "https://example.test/doc"}
    assert "isError" not in response["result"]


def test_verify_batch_delegates_to_engine(monkeypatch):
    seen = {}

    def fake_batch(claims, session=None):
        seen["args"] = (claims, session)
        return {"summary": {"PASS": 1, "FAIL": 0, "UNVERIFIABLE": 0}, "results": []}

    monkeypatch.setattr(mcp_server.verify, "verify_batch", fake_batch)
    claims = [{"id": "c1", "url": "https://example.test/doc", "must_contain": ["41GW"]}]
    response = mcp_server.handle_request({
        "jsonrpc": "2.0",
        "id": 4,
        "method": "tools/call",
        "params": {"name": "verify_batch", "arguments": {"claims": claims}},
    })
    assert seen["args"] == (claims, None)
    payload = json.loads(response["result"]["content"][0]["text"])
    assert payload["summary"] == {"PASS": 1, "FAIL": 0, "UNVERIFIABLE": 0}


def test_unknown_tool_is_a_structured_tool_error():
    response = mcp_server.handle_request({
        "jsonrpc": "2.0",
        "id": 5,
        "method": "tools/call",
        "params": {"name": "invent_evidence", "arguments": {}},
    })
    assert response["result"]["isError"] is True
    assert "unknown tool" in response["result"]["content"][0]["text"]


def test_stdio_process_exchanges_jsonrpc_lines():
    messages = [
        {"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": {}},
        {"jsonrpc": "2.0", "method": "notifications/initialized"},
        {"jsonrpc": "2.0", "id": 2, "method": "tools/list"},
    ]
    proc = subprocess.run(
        [sys.executable, str(ROOT / "mcp_server.py")],
        input="\n".join(json.dumps(m) for m in messages) + "\n",
        capture_output=True,
        text=True,
        timeout=30,
        cwd=ROOT,
    )
    assert proc.returncode == 0, proc.stderr
    lines = [line for line in proc.stdout.splitlines() if line.strip()]
    responses = [json.loads(line) for line in lines]
    assert len(responses) == 2
    assert responses[0]["id"] == 1
    assert responses[1]["id"] == 2
    assert [t["name"] for t in responses[1]["result"]["tools"]] == [
        "verify_claim", "verify_batch"
    ]


def test_server_discover_returns_2026_discovery_result():
    response = mcp_server.handle_request({
        "jsonrpc": "2.0",
        "id": "discover-1",
        "method": "server/discover",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            }
        },
    })
    result = response["result"]
    assert result["resultType"] == "complete"
    assert result["supportedVersions"] == ["2026-07-28"]
    assert result["capabilities"] == {"tools": {}}


def test_2026_tools_list_includes_result_type():
    response = mcp_server.handle_request({
        "jsonrpc": "2.0",
        "id": 6,
        "method": "tools/list",
        "params": {
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            }
        },
    })
    assert response["result"]["resultType"] == "complete"
    assert [t["name"] for t in response["result"]["tools"]] == [
        "verify_claim", "verify_batch"
    ]


def test_2026_tools_call_includes_result_type_and_is_error(monkeypatch):
    monkeypatch.setattr(
        mcp_server.verify,
        "verify",
        lambda url, must_contain=None, session=None: {"verdict": "PASS"},
    )
    response = mcp_server.handle_request({
        "jsonrpc": "2.0",
        "id": 7,
        "method": "tools/call",
        "params": {
            "name": "verify_claim",
            "arguments": {"url": "https://example.test/doc", "must_contain": ["41GW"]},
            "_meta": {
                "io.modelcontextprotocol/protocolVersion": "2026-07-28",
                "io.modelcontextprotocol/clientCapabilities": {},
            },
        },
    })
    result = response["result"]
    assert result["resultType"] == "complete"
    assert result["isError"] is False
    assert json.loads(result["content"][0]["text"]) == {"verdict": "PASS"}


def test_malformed_params_return_invalid_params_error():
    response = mcp_server.handle_request({
        "jsonrpc": "2.0",
        "id": 8,
        "method": "tools/call",
        "params": "bad",
    })
    assert response["error"]["code"] == -32602
    assert "params" in response["error"]["message"].lower()


def test_initialize_negotiates_supported_protocol_version():
    response = mcp_server.handle_request({
        "jsonrpc": "2.0",
        "id": 9,
        "method": "initialize",
        "params": {"protocolVersion": "1999-01-01"},
    })
    assert response["result"]["protocolVersion"] == mcp_server.PROTOCOL_VERSION
