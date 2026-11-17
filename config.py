"""
Central configuration for Research Hunter.

All keys are optional except CONTACT_EMAIL, which several APIs require
(or strongly request) so your requests land in their "polite pool" and
don't get rate-limited or blocked. Set these in a local .env file
(copy .env.example -> .env) — never commit real keys to git.
"""
import os
from dotenv import load_dotenv

load_dotenv()

# Used as a polite-pool identifier for OpenAlex, CrossRef, Unpaywall, and
# in the User-Agent sent to SEC EDGAR (which requires one by policy).
CONTACT_EMAIL = os.environ.get("CONTACT_EMAIL", "").strip()

# Free key from https://core.ac.uk/services/api — search stays enabled
# without it, CORE is just skipped.
CORE_API_KEY = os.environ.get("CORE_API_KEY", "").strip()

# Free key from https://fred.stlouisfed.org/docs/api/api_key.html —
# skipped if absent.
FRED_API_KEY = os.environ.get("FRED_API_KEY", "").strip()

# Optional Semantic Scholar key (https://www.semanticscholar.org/product/api)
# raises your rate limit; works fine unauthenticated at low volume.
SEMANTIC_SCHOLAR_API_KEY = os.environ.get("SEMANTIC_SCHOLAR_API_KEY", "").strip()

REQUEST_TIMEOUT = 12  # seconds, per outbound connector call
DEFAULT_LIMIT = 10

RAW_RESEARCH_DIR = os.path.join(os.path.dirname(__file__), "01_Raw_Research")

# ---------------------------------------------------------------------------
# Primary-source connectors
# All optional. A connector whose key is missing is omitted from the registry
# entirely — it never crashes, it just does not appear in the source checklist.
# ---------------------------------------------------------------------------

# Free key: https://developer.company-information.service.gov.uk/
# Sent as HTTP Basic username, with an empty password.
COMPANIES_HOUSE_API_KEY = os.environ.get("COMPANIES_HOUSE_API_KEY", "").strip()

# Free token: https://www.courtlistener.com/help/api/rest/
COURTLISTENER_API_KEY = os.environ.get("COURTLISTENER_API_KEY", "").strip()

# Optional. The rest of the government/statistics connectors are keyless.
WORLD_BANK_API_KEY = os.environ.get("WORLD_BANK_API_KEY", "").strip()

# ---------------------------------------------------------------------------
# Verification engine (verify.py)
# ---------------------------------------------------------------------------

# Where normalised text snapshots live, keyed by their SHA-256. A verdict is
# only meaningful because the exact text it was judged against is still on
# disk and still hashes to the same value.
SNAPSHOT_DIR = os.environ.get(
    "VERIFY_SNAPSHOT_DIR", os.path.join(RAW_RESEARCH_DIR, "snapshots")
)

# Ceiling on how much of a document we download into memory. A 500 MB PDF is
# not evidence, it is a denial of service.
VERIFY_MAX_BYTES = int(os.environ.get("VERIFY_MAX_BYTES", str(25 * 1024 * 1024)))

# Per-request timeout for the resolve/fetch stages, in seconds.
VERIFY_TIMEOUT = int(os.environ.get("VERIFY_TIMEOUT", "25"))

# Characters of surrounding context to quote around a matched token.
VERIFY_SPAN_CONTEXT = int(os.environ.get("VERIFY_SPAN_CONTEXT", "120"))

# Refuse to follow a redirect chain longer than this (loop guard).
VERIFY_MAX_REDIRECTS = int(os.environ.get("VERIFY_MAX_REDIRECTS", "10"))

# Override the outbound User-Agent for verification fetches.
VERIFY_USER_AGENT = os.environ.get("VERIFY_USER_AGENT", "").strip()

# SSRF guard. A public-facing verifier must not be able to fetch loopback,
# link-local, private or otherwise reserved addresses. Tests that run their own
# local HTTP server opt in explicitly with VERIFY_ALLOW_PRIVATE_HOSTS=1.
VERIFY_ALLOW_PRIVATE_HOSTS = os.environ.get(
 "VERIFY_ALLOW_PRIVATE_HOSTS", ""
).strip().lower() in ("1", "true", "yes", "on")
