# Research Hunter

Federated search across academic, regulatory, and financial-data sources —
one query, every connector at once, results normalized to a single schema.

## Setup (M3 Max / any Mac)

```bash
cd research-hunter
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt --break-system-packages
cp .env.example .env
# open .env and at minimum set CONTACT_EMAIL — see why below
python3 app.py
```

Then open `http://localhost:5050`.

## Why these sources, specifically

The original spec called for 8 general academic connectors (arXiv, CORE,
DOAJ, Semantic Scholar, OpenAlex, Unpaywall, Europe PMC, CrossRef). Those
are built and included — but they're tuned for literature review, and your
channel isn't writing literature reviews. "The Sovereign Landlords,"
"The Debt Engine," "The Central Bank Paradox" — these episodes live or die
on primary regulatory and financial documents, not journal abstracts. So
three sources were added on top of the original 8:

- **SEC EDGAR full-text search** — 10-Ks, 10-Qs, 8-Ks, proxy statements.
  This is the actual source of the "highlighted line in an SEC filing"
  visual your whole aesthetic is built around. No API key needed.
- **Federal Register** — executive orders, agency rules, proposed
  regulations. This is where EO 14376 (the housing EO from your
  Sovereign Landlords research) actually lives. No key needed.
- **FRED (Federal Reserve Economic Data)** — macro time series: rates,
  money supply, housing starts, employment. Needed for Pillar 3
  (Institutional Logic) episodes especially. Free key required.

One correction worth knowing: **Unpaywall isn't a search engine** — it's a
DOI lookup that tells you whether a free full-text version of a paper you
already found exists. It's wired in as an *enrichment* step instead of a
standalone connector: any result from CrossRef/OpenAlex/etc. that has a
DOI gets an `open_access_url` field automatically. Requires `CONTACT_EMAIL`
to be set — that's Unpaywall's usage policy, not this app's.

## Getting the optional API keys (both free, both instant)

| Key | Where | Notes |
|---|---|---|
| `CORE_API_KEY` | https://core.ac.uk/services/api | No approval wait |
| `FRED_API_KEY` | https://fred.stlouisfed.org/docs/api/api_key.html | No approval wait |

Skip either one and that connector is silently omitted from results — the
app never breaks because a key is missing.

## How this fits the rest of your pipeline

1. Search here → review results → click **Save to 01_Raw_Research**
2. That writes a timestamped JSON file into `./01_Raw_Research/`
3. Your **Orchestrator** (`orchestrator.py`, watching that folder with
   `watchdog`) should pick it up from there and route it toward
   **DataVet Pro** for cleaning, per your existing pipeline design.

## Notes on the SEC EDGAR connector

SEC EDGAR requires a descriptive `User-Agent` header identifying who's
making the request — this is enforced, not optional, and unset
`CONTACT_EMAIL` will get you blocked eventually. It's baked into every
outbound request automatically once you set it in `.env`.

## Verification engine and MCP plugin

`verify.py` is the only source of verdicts. It fetches a public document,
hashes the normalised text, stores a snapshot, checks literal tokens with
number-safe boundaries, and returns `PASS`, `FAIL`, or `UNVERIFIABLE`. No model
memory can produce a PASS.

Generic CLI:

```bash
python3 verify.py --url https://example.org/document --must-contain "41GW" --json
python3 verify.py --batch claims.json --out report.json
```

This directory is also a Claude Code plugin. It exposes two MCP tools:

- `verify_claim`: `{url, must_contain}` → one evidence-backed result
- `verify_batch`: `{claims: [{id?, url, must_contain}]}` → a batch report

Local development:

```bash
claude --plugin-dir /path/to/research-hunter
claude plugin validate /path/to/research-hunter
```

Any other MCP client can connect to the same server with:

```json
{
  "mcpServers": {
    "research-hunter": {
      "command": "python3",
      "args": ["/absolute/path/to/research-hunter/mcp_server.py"]
    }
  }
}
```

The server supports both the legacy `initialize` handshake and the 2026
`server/discover` handshake. Logs belong on stderr; stdout is JSON-RPC only.
Private hosts, loopback, link-local and cloud metadata addresses are blocked
by default. Set `VERIFY_ALLOW_PRIVATE_HOSTS=1` only for local tests.

`claude plugin validate` passes locally with no directory warnings. The plugin
is MIT licensed; both `license: "MIT"` in `.claude-plugin/plugin.json` and a
root `LICENSE` file are present. `.claude-plugin/icon.png` is the 800×800
Infrastructure & Power brand mark. The repository is also a marketplace, so
installation is one command once it is public:

```bash
/plugin install research-hunter --marketplace yourfavCHEFP/research-hunter
```
