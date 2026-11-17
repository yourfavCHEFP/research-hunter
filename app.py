import json
import logging
import os
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from flask import Flask, render_template, request, jsonify

from connectors import CONNECTORS, enrich_with_unpaywall
import config as _config
import verify as _verify
from config import RAW_RESEARCH_DIR, DEFAULT_LIMIT, CONTACT_EMAIL

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("research_hunter.app")

app = Flask(__name__)
os.makedirs(RAW_RESEARCH_DIR, exist_ok=True)


def _source_available(connector):
    """
    Is this connector usable right now?

    Keyless connectors are always available. A connector that needs a key is
    available only if that key is set. We resolve the key name against the
    config module rather than a hardcoded dict, so adding a connector with a
    new key does not require editing this function — the previous hardcoded
    {"CORE_API_KEY", "FRED_API_KEY"} map silently marked every new keyed
    connector as unavailable.
    """
    if not connector.get("needs_key"):
        return True
    key_name = connector.get("key_name")
    if not key_name:
        return True
    return bool(getattr(_config, key_name, "") or os.environ.get(key_name, ""))


@app.route("/")
def index():
    sources_meta = {
        key: {
            "label": c["label"],
            "type": c["type"],
            "needs_key": c["needs_key"],
            "available": _source_available(c),
        }
        for key, c in CONNECTORS.items()
    }
    return render_template("index.html", sources=sources_meta, contact_set=bool(CONTACT_EMAIL))

@app.route("/api/sources")
def api_sources():
    out = {}
    for key, c in CONNECTORS.items():
        available = _source_available(c)
        out[key] = {"label": c["label"], "type": c["type"], "needs_key": c["needs_key"], "available": available}
    return jsonify(out)


@app.route("/api/search", methods=["POST"])
def api_search():
    payload = request.get_json(force=True, silent=True) or {}
    query = (payload.get("query") or "").strip()
    limit = int(payload.get("limit") or DEFAULT_LIMIT)
    limit = max(1, min(limit, 25))
    requested_sources = payload.get("sources") or list(CONNECTORS.keys())
    enrich = bool(payload.get("enrich_open_access", True))

    if not query:
        return jsonify({"error": "query is required"}), 400

    active = [s for s in requested_sources if s in CONNECTORS]
    if not active:
        return jsonify({"error": "no valid sources selected"}), 400

    results_by_source = {}
    errors = {}

    with ThreadPoolExecutor(max_workers=max(1, len(active))) as pool:
        futures = {pool.submit(CONNECTORS[s]["fn"], query, limit): s for s in active}
        for future in as_completed(futures):
            src = futures[future]
            try:
                res = future.result()
                results_by_source[src] = res
                if not res and CONNECTORS[src]["needs_key"]:
                    errors[src] = "skipped — API key not configured"
            except Exception as exc:
                log.exception("Connector %s raised", src)
                results_by_source[src] = []
                errors[src] = str(exc)

    combined = []
    for src, items in results_by_source.items():
        combined.extend(items)

    if enrich:
        combined = enrich_with_unpaywall(combined)

    # best-effort recency sort — falls back to original order when dates
    # aren't comparable across sources with different date granularities
    def sort_key(r):
        d = r.get("date", "") or ""
        return d

    combined_sorted = sorted(combined, key=sort_key, reverse=True)

    return jsonify({
        "query": query,
        "results_by_source": results_by_source,
        "combined": combined_sorted,
        "errors": errors,
        "counts": {src: len(items) for src, items in results_by_source.items()},
    })


@app.route("/api/verify", methods=["POST"])
def api_verify():
    """
    Verify a claim against a primary source. The verdict is computed solely
    from byte-level containment in the fetched document; no model judgement
    is involved. See VERIFY_CONTRACT.md for the request/response shapes.
    """
    payload = request.get_json(force=True, silent=True) or {}
    url = (payload.get("url") or "").strip()
    tokens = payload.get("must_contain") or []
    if isinstance(tokens, str):
        tokens = [tokens] if tokens.strip() else []
    if not url:
        return jsonify({"error": "url is required"}), 400
    if not tokens:
        return jsonify({"error": "must_contain is required"}), 400

    result = _verify.verify(url, tokens)
    return jsonify(result)


def _slugify(text, max_len=60):
    slug = re.sub(r"[^a-zA-Z0-9]+", "-", text.strip().lower()).strip("-")
    return slug[:max_len] or "query"


@app.route("/api/save", methods=["POST"])
def api_save():
    """
    Writes the current result set into ./01_Raw_Research/ as JSON, matching
    the drop-zone the Orchestrator (orchestrator.py) watches with `watchdog`.
    This is the hand-off point between Research Hunter and the rest of the
    pipeline — dropping a file here is what should trigger the Orchestrator
    to route it toward DataVet Pro for cleanup.
    """
    payload = request.get_json(force=True, silent=True) or {}
    query = payload.get("query", "untitled")
    results = payload.get("results", [])

    if not results:
        return jsonify({"error": "no results to save"}), 400

    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    filename = f"{_slugify(query)}_{timestamp}.json"
    filepath = os.path.join(RAW_RESEARCH_DIR, filename)

    record = {
        "query": query,
        "saved_at": timestamp,
        "result_count": len(results),
        "results": results,
    }

    with open(filepath, "w", encoding="utf-8") as f:
        json.dump(record, f, indent=2, ensure_ascii=False)

    log.info("Saved %d results to %s", len(results), filepath)
    return jsonify({"saved": True, "filename": filename, "path": filepath})


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode, port=int(os.environ.get("PORT", 5050)))
