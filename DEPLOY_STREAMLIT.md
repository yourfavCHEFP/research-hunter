# Deploying the verification UI to Streamlit Cloud

The Streamlit app is a thin UI over `verify.py`. It does not duplicate the
verification logic. Flask still works on port 5050; Streamlit is the deploy
target for reviewers.

## Local

From this directory (`master-handoff/02_production_tools/research-hunter`):

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
# optional: cp .env.example .env and fill in any keys you need for search
streamlit run streamlit_app.py --server.port 8501
```

Open <http://localhost:8501>. Paste a JSON list (or CSV rows) of claims,
press **Run verification**, inspect quoted spans, re-check a single row, or
download the JSON report.

## Streamlit Cloud

1. Push this repository to GitHub. The app must live in the repo you connect.
2. In [Streamlit Cloud](https://share.streamlit.io/), choose **New app** and
   select the repo, branch and main file:
   `master-handoff/02_production_tools/research-hunter/streamlit_app.py`
3. Set Python version to **3.11** in Advanced settings.
4. Add secrets under **Advanced settings → Secrets** if you want the search
   connectors, then **Deploy**. Verification itself needs **no** secrets.

### Secrets → environment variable mapping

`streamlit_app.py` copies these secret names into `os.environ` before importing
the engine. Use exactly these TOML keys in Streamlit Secrets:

```toml
CONTACT_EMAIL = "you@example.com"          # polite-pool identifier; strongly recommended
CORE_API_KEY = ""
FRED_API_KEY = ""
SEMANTIC_SCHOLAR_API_KEY = ""
COMPANIES_HOUSE_API_KEY = ""               # Companies House search
COURTLISTENER_API_KEY = ""                 # US case-law search
WORLD_BANK_API_KEY = ""                    # optional; raises World Bank limits

# Verification tuning (all optional; defaults in config.py)
VERIFY_USER_AGENT = ""
VERIFY_MAX_BYTES = "26214400"
VERIFY_TIMEOUT = "25"
VERIFY_SPAN_CONTEXT = "120"
VERIFY_MAX_REDIRECTS = "10"
VERIFY_SNAPSHOT_DIR = "/tmp/verify_snapshots"
```

Notes:

- Leave an unused key empty. An absent key makes that connector report
  `available: false` in `/api/sources` and return an empty list; it never
  crashes the app and it never fabricates a result.
- Streamlit Cloud containers have an ephemeral filesystem. Snapshots written
  by the verifier survive only for the life of the container. Set
  `VERIFY_SNAPSHOT_DIR` to a path such as `/tmp/verify_snapshots` and remember
  that a downloaded JSON report is the durable record of what was verified.
- The Cloud outbound network can be rate-limited or blocked by some official
  APIs. A connection failure yields `UNVERIFIABLE`, never a PASS.
- Never put a real key in `requirements.txt`, source code, or the app UI.

## Verifying the deployment

Run a claim with a known token, e.g.
`https://www.thecrownestate.co.uk/about-us/case-study-round-4` with
`must_contain: ["41GW"]`. You should see `PASS`, an HTTP 200 row, a SHA-256,
and a quoted span containing "41GW". Then change the token to `61GW`: the
verdict must become `FAIL` with a numeric near miss. If it does not, stop and
investigate before using the tool on a film.

## Local verification result (2026-11-17)

The app was launched on `http://localhost:8501` and `/_stcore/health`
returned `ok`. Streamlit `AppTest` drove the real UI through three cases:
PASS with quoted span/SHA-256/`fetched_at`, FAIL with a numeric near miss,
and UNVERIFIABLE for an unreachable source. The repository test suite passed
with `46 passed, 1 skipped` (the skip is the opt-in live-network smoke test). The
same engine verified all 12 sources in `001-the-sovereign-landlords` on
2026-11-18: 12 PASS, 0 FAIL, 0 UNVERIFIABLE.

Streamlit Cloud deployment has **not** been performed here: it requires the
repository to be pushed to GitHub and a Streamlit Cloud account with access
to that repository. Once those exist, use the steps above. Do not claim the
app is publicly deployed until the Cloud URL returns the same three verdicts.


## Residual SSRF limitation

The URL guard validates scheme, host, literal IPs, public-web ports and DNS
answers before every request and every redirect. It does not pin the socket to
the validated IP, so a hostile DNS resolver that rebinds between validation
and connection could still redirect the fetch to a blocked address. Do not
expose this verifier to untrusted callers on a public deployment until DNS
pinning or a controlled egress proxy is in place. Private hosts are blocked by
default in normal use.
