# Verification JSON contract

One module, `verify.py`, computes every verdict. The CLI, Flask `/api/verify`
and the Streamlit UI all call the same `verify()` / `verify_batch()` functions.
Nobody adds a verdict by hand, and no model output is evidence.

## Single claim

CLI:

```bash
python3 verify.py --url URL --must-contain "41GW" --must-contain "six projects" --json
python3 verify.py --url URL --must-contain "41GW" --out report.json
```

HTTP:

```http
POST /api/verify
Content-Type: application/json

{"url": "https://…", "must_contain": ["41GW", "six projects"]}
```

Response (one JSON object):

```json
{
  "url": "https://…",
  "must_contain": ["41GW"],
  "final_url": "https://…",
  "status": 200,
  "content_type": "text/html; charset=utf-8",
  "bytes": 101169,
  "redirect_chain": ["https://…"],
  "elapsed_ms": 914,
  "sha256": "cd0c13d850cf729a96e24f145b6a8574757aa114e9a1b489a9bd1b9adc8250a0",
  "snapshot_path": "01_Raw_Research/snapshots/<sha256>.txt",
  "content_kind": "html",
  "encoding": "utf-8",
  "text_chars": 24913,
  "text_preview": "…first 4000 characters of normalised text…",
  "tokens": [
    {
      "token": "41GW",
      "matched": true,
      "span": {
        "start": 1931,
        "end": 1935,
        "matched_text": "41GW",
        "quote": "…rights totalling 41GW and established…"
      },
      "matched_via": "unit-expanded",
      "occurrences": 1
    }
  ],
  "verdict": "PASS",
  "reason": "",
  "fetched_at": "2026-11-17T15:15:00Z",
  "started_at": "2026-11-17T15:14:59Z",
  "errors": [],
  "engine": "verify.py/1.0"
}
```

A failed token adds `near_miss` (diagnostic only, never a PASS):

```json
{
  "token": "61GW",
  "matched": false,
  "span": null,
  "matched_via": "",
  "occurrences": 0,
  "near_miss": {
    "kind": "numeric",
    "closest_value": "41GW",
    "position": 1931,
    "quote": "…rights totalling 41GW and established…",
    "note": "claim says 61GW, nearest matching-unit number in document is 41GW"
  }
}
```

When there is no document text (404, unreachable host, image content type),
tokens are reported as `matched: false` with
`"error": "not checked: no extractable document text"`. Do not read that as
"absent from the source" — the verdict and errors explain why.

## Batch

Input file (list, or `{"claims": [...]}`):

```json
[
  {"id": "c1", "url": "https://…", "must_contain": ["41GW"]},
  {"id": "c2", "url": "https://…", "must_contain": ["six projects"]}
]
```

`--batch file.json` produces, and `--out` writes:

```json
{
  "generated_at": "…Z",
  "engine": "verify.py/1.0",
  "count": 2,
  "summary": {"PASS": 2, "FAIL": 0, "UNVERIFIABLE": 0},
  "results": [ {"claim_id": "c1", "claim_index": 0, "…": "same shape as single result"} ]
}
```

## Verdict semantics

| Verdict | Meaning |
| --- | --- |
| `PASS` | HTTP 2xx document was fetched, text was extracted and hashed, and **every** `must_contain` token was found by mechanical containment. |
| `FAIL` | Server returned HTTP >= 400, content type is not a document, or at least one token is absent. The cited source does not support the claim. |
| `UNVERIFIABLE` | Could not reach the source (timeout / DNS / connection), could not extract text (unreadable PDF, empty body), or no tokens were supplied. We do not know. |

Order of decisions: resolve → fetch/normalise → containment → verdict.
Resolution failure stops the pipeline; containment is never run on an error
page. Any status >= 400 or non-document content type is a hard resolution
FAIL, not UNVERIFIABLE.

## Matching rules

- Case-insensitive, Unicode NFKC normalised, whitespace collapsed.
- Hyphen/dash variants and smart quotes are tolerated.
- Numbers: `41GW`, `41 GW`, `41 gigawatts`, `41.0GW` all match a claim of
  `41GW`. Number words (`six`) match digits (`6`).
- Numeric boundaries are strict: token `10` never matches `10.5`, `100` or
  `10,000`. This is tested.
- A miss returns a near-miss quote for a human to inspect. It never relaxes
  the match.

## Evidence and honesty

- Every verdict carries `fetched_at`, `sha256`, and `snapshot_path`. The full
  normalised text is stored at `01_Raw_Research/snapshots/<sha256>.txt`; the
  JSON carries only a 4000-character preview. "Verified" always means
  "verified against this document on this date".
- URLs are echoed exactly as supplied (plus the observed redirect target).
  The engine never invents a URL, source, or quotation.
- There is no LLM call in `verify.py`. Model memory cannot produce a PASS.
- Exit codes: `0` only when every item PASSes, `1` if any FAIL, `2` if any
  UNVERIFIABLE and no FAIL.

## MCP adapter

`mcp_server.py` is a stdio JSON-RPC adapter. It owns transport and argument
validation only; both tools call `verify.py` directly, so there is no second
verdict implementation and no model call in the verdict path.

- `verify_claim`: `{url, must_contain}` returns one single-claim result.
- `verify_batch`: `{claims: [{id?, url, must_contain}]}` returns one batch report.

Tool errors are returned as MCP tool results with `isError: true`, never as a
fabricated verdict. Unknown methods use JSON-RPC `-32601`; parse failures use
`-32700`. Every PASS/FAIL/UNVERIFIABLE result keeps the same evidence fields
as the CLI and HTTP API.
