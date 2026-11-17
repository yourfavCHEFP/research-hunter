#!/usr/bin/env python3
"""
stdio MCP adapter for Research Hunter.

This module owns transport and argument validation only. Every verdict comes
from verify.py. There is no second matching implementation here.
"""
import json
import sys

import verify

SERVER_NAME = "research-hunter"
SERVER_VERSION = "1.0.0"
PROTOCOL_VERSION = "2025-06-18"
LATEST_PROTOCOL_VERSION = "2026-07-28"
SUPPORTED_VERSIONS = [LATEST_PROTOCOL_VERSION]
NEGOTIABLE_VERSIONS = (PROTOCOL_VERSION, LATEST_PROTOCOL_VERSION)

TOOLS = [
    {
        "name": "verify_claim",
        "description": (
            "Fetch one public source and mechanically check required tokens. "
            "PASS requires a fetched document containing every token; model "
            "memory can never produce PASS. Returns status, content type, "
            "SHA-256, snapshot, quoted spans, fetched_at, and a "
            "PASS/FAIL/UNVERIFIABLE verdict."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "url": {"type": "string", "description": "Public http(s) source URL."},
                "must_contain": {
                    "type": "array",
                    "items": {"type": "string"},
                    "minItems": 1,
                    "description": "Literal tokens that must appear in the fetched document.",
                },
            },
            "required": ["url", "must_contain"],
            "additionalProperties": False,
        },
    },
    {
        "name": "verify_batch",
        "description": (
            "Fetch and verify several claims with the same engine. Returns a "
            "report with a PASS/FAIL/UNVERIFIABLE summary and one evidence "
            "record per claim."
        ),
        "inputSchema": {
            "type": "object",
            "properties": {
                "claims": {
                    "type": "array",
                    "minItems": 1,
                    "items": {
                        "type": "object",
                        "properties": {
                            "id": {"type": "string"},
                            "url": {"type": "string"},
                            "must_contain": {
                                "type": "array",
                                "items": {"type": "string"},
                                "minItems": 1,
                            },
                        },
                        "required": ["url", "must_contain"],
                        "additionalProperties": False,
                    },
                },
            },
            "required": ["claims"],
            "additionalProperties": False,
        },
    },
]


def _ok(request_id, result):
    return {"jsonrpc": "2.0", "id": request_id, "result": result}


def _error(request_id, code, message):
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {"code": code, "message": message},
    }


def _uses_2026(params):
    meta = params.get("_meta") if isinstance(params, dict) else None
    return (
        isinstance(meta, dict)
        and meta.get("io.modelcontextprotocol/protocolVersion") == LATEST_PROTOCOL_VERSION
    )


def _versioned(result, params):
    """Add the 2026 result marker without changing legacy clients."""
    if not _uses_2026(params):
        return result
    versioned = dict(result)
    versioned["resultType"] = "complete"
    return versioned


def _tool_text(payload, is_error=False):
    result = {
        "content": [{
            "type": "text",
            "text": json.dumps(payload, ensure_ascii=False, indent=2),
        }]
    }
    if is_error:
        result["isError"] = True
    return result


def _validate_string_list(values, field):
    if not isinstance(values, list) or not values:
        raise ValueError(f"{field} must be a non-empty list of strings")
    if not all(isinstance(value, str) and value.strip() for value in values):
        raise ValueError(f"{field} must contain only non-empty strings")
    return [value.strip() for value in values]


def _call_tool(name, arguments):
    if not isinstance(arguments, dict):
        return _tool_text({"error": "arguments must be an object"}, is_error=True)

    try:
        if name == "verify_claim":
            url = arguments.get("url", "")
            if not isinstance(url, str) or not url.strip():
                raise ValueError("url must be a non-empty string")
            tokens = _validate_string_list(arguments.get("must_contain"), "must_contain")
            result = verify.verify(url.strip(), tokens)
            return _tool_text(result)

        if name == "verify_batch":
            claims = arguments.get("claims")
            if not isinstance(claims, list) or not claims:
                raise ValueError("claims must be a non-empty list")
            for index, claim in enumerate(claims):
                if not isinstance(claim, dict):
                    raise ValueError(f"claims[{index}] must be an object")
                if not isinstance(claim.get("url"), str) or not claim["url"].strip():
                    raise ValueError(f"claims[{index}].url must be a non-empty string")
                _validate_string_list(
                    claim.get("must_contain"), f"claims[{index}].must_contain"
                )
            result = verify.verify_batch(claims)
            return _tool_text(result)

        return _tool_text({"error": f"unknown tool: {name}"}, is_error=True)
    except (TypeError, ValueError) as exc:
        return _tool_text({"error": str(exc)}, is_error=True)
    except Exception as exc:  # noqa: BLE001 - transport must not leak stack traces
        return _tool_text(
            {"error": f"{type(exc).__name__}: {exc}"},
            is_error=True,
        )


def handle_request(message):
    """Handle one parsed JSON-RPC message. Returns None for notifications."""
    if not isinstance(message, dict):
        return _error(None, -32600, "Invalid Request")

    request_id = message.get("id")
    method = message.get("method")
    params = message.get("params") or {}

    if request_id is None:
        return None  # notification: no reply

    if not isinstance(params, dict):
        return _error(request_id, -32602, "Invalid params: expected an object")

    if method == "initialize":
        requested = params.get("protocolVersion")
        negotiated = (
            requested if requested in NEGOTIABLE_VERSIONS else PROTOCOL_VERSION
        )
        return _ok(request_id, {
            "protocolVersion": negotiated,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        })

    if method == "server/discover":
        return _ok(request_id, _versioned({
            "supportedVersions": SUPPORTED_VERSIONS,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": SERVER_NAME, "version": SERVER_VERSION},
        }, params))

    if method == "ping":
        return _ok(request_id, _versioned({}, params))

    if method == "tools/list":
        return _ok(request_id, _versioned({"tools": TOOLS}, params))

    if method == "tools/call":
        name = params.get("name")
        if not isinstance(name, str) or not name:
            return _error(request_id, -32602, "tools/call requires a tool name")
        tool_result = _call_tool(name, params.get("arguments", {}))
        if _uses_2026(params):
            tool_result = dict(tool_result)
            tool_result.setdefault("isError", False)
        return _ok(request_id, _versioned(tool_result, params))

    return _error(request_id, -32601, f"Method not found: {method}")


def main():
    for raw in sys.stdin:
        if not raw.strip():
            continue
        try:
            message = json.loads(raw)
        except json.JSONDecodeError as exc:
            response = _error(None, -32700, f"Parse error: {exc.msg}")
        else:
            response = handle_request(message)
        if response is None:
            continue
        sys.stdout.write(
            json.dumps(response, ensure_ascii=False, separators=(",", ":")) + "\n"
        )
        sys.stdout.flush()


if __name__ == "__main__":
    main()
