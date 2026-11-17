"""
Streamlit UI for the verification engine.

All verdicts come from verify.py. This file contains no extraction, matching,
or judgement logic — it only collects claims, calls the engine, and displays
what the engine returned.

Run locally:
    streamlit run streamlit_app.py --server.port 8501
"""
import csv
import io
import json
import os

import streamlit as st

# Streamlit Cloud stores secrets in st.secrets, not os.environ. config.py reads
# os.environ, so copy known secrets into the environment BEFORE importing the
# engine. Nothing here invents a value: absent secrets stay absent, and the
# relevant connector is omitted by config/connectors.py.
_SECRET_KEYS = (
    "CONTACT_EMAIL",
    "CORE_API_KEY",
    "FRED_API_KEY",
    "SEMANTIC_SCHOLAR_API_KEY",
    "COMPANIES_HOUSE_API_KEY",
    "COURTLISTENER_API_KEY",
    "WORLD_BANK_API_KEY",
    "VERIFY_USER_AGENT",
    "VERIFY_MAX_BYTES",
    "VERIFY_TIMEOUT",
    "VERIFY_SPAN_CONTEXT",
    "VERIFY_MAX_REDIRECTS",
    "VERIFY_SNAPSHOT_DIR",
)

try:
    for _key in _SECRET_KEYS:
        _value = st.secrets.get(_key, "")
        if _value not in (None, "") and not os.environ.get(_key):
            os.environ[_key] = str(_value)
except Exception:
    # Locally there may be no secrets.toml at all. That is fine: verification
    # itself needs no API keys.
    pass

import verify as engine  # noqa: E402

st.set_page_config(page_title="Research Hunter · Verification", page_icon="✓", layout="wide")
st.title("Research Hunter — Claim Verification")
st.caption(
    "A PASS means this exact text was found in the document fetched at the timestamp below. "
    "No model memory, no heuristics, no invented quotations."
)

if "verify_report" not in st.session_state:
    st.session_state.verify_report = None
if "claims_text" not in st.session_state:
    st.session_state.claims_text = json.dumps(
        [
            {
                "id": "crown-41gw",
                "url": "https://www.thecrownestate.co.uk/about-us/case-study-round-4",
                "must_contain": ["41GW"],
            },
            {
                "id": "crown-six-projects",
                "url": "https://www.thecrownestate.co.uk/our-business/marine/Round4",
                "must_contain": ["six projects"],
            },
        ],
        indent=2,
    )


def _parse_claims(text, filename=None):
    """Parse pasted JSON/CSV or an uploaded file into claim dicts for the engine."""
    if not text or not text.strip():
        return [], ["Claims list is empty."]

    name = (filename or "").lower()
    is_csv = name.endswith(".csv") or (
        not name and text.lstrip()[:1] not in ("[", "{")
    )

    try:
        if is_csv:
            reader = csv.DictReader(io.StringIO(text))
            raw = list(reader)
        else:
            payload = json.loads(text)
            if isinstance(payload, dict):
                raw = payload.get("claims", [])
            elif isinstance(payload, list):
                raw = payload
            else:
                return [], ["JSON must be a list, or an object with a 'claims' list."]
    except (ValueError, json.JSONDecodeError, csv.Error) as exc:
        return [], [f"Could not parse claims: {exc}"]

    claims, errors = [], []
    for index, row in enumerate(raw):
        if not isinstance(row, dict):
            errors.append(f"Row {index + 1}: expected an object.")
            continue
        url = str(row.get("url", "") or "").strip()
        tokens = row.get("must_contain", row.get("tokens", []))
        if isinstance(tokens, str):
            # CSV uses | or ; to separate tokens; a single JSON string is one token.
            separator = "|" if "|" in tokens else (";" if ";" in tokens else None)
            tokens = [t.strip() for t in tokens.split(separator)] if separator else [tokens.strip()]
        tokens = [str(t).strip() for t in (tokens or []) if str(t).strip()]
        if not url:
            errors.append(f"Row {index + 1}: missing url.")
            continue
        if not tokens:
            errors.append(f"Row {index + 1}: missing must_contain tokens.")
            continue
        claims.append(
            {
                "id": str(row.get("id", "") or index + 1),
                "url": url,
                "must_contain": tokens,
            }
        )
    return claims, errors


def _span_text(result):
    bits = []
    for token in result.get("tokens", []):
        if token.get("matched") and token.get("span"):
            bits.append(f"“{token['span']['quote']}”")
        elif token.get("near_miss"):
            bits.append(f"near miss for {token['token']!r}: {token['near_miss']['quote']}")
    return "  ·  ".join(bits) or "—"


left, right = st.columns([3, 1])

with right:
    st.subheader("Input")
    uploaded = st.file_uploader("Upload claims (.json or .csv)", type=["json", "csv", "txt"])
    if uploaded is not None:
        content = uploaded.getvalue().decode("utf-8", errors="replace")
        if st.button("Use uploaded file"):
            st.session_state.claims_text = content
            st.rerun()

    st.markdown(
        """
        **JSON**
        ```json
        [{"id":"c1","url":"https://…","must_contain":["41GW"]}]
        ```
        **CSV** columns: `id,url,must_contain`
        (separate multiple tokens with `|`).
        """
    )
    st.info(
        "Verification itself needs no API key. Search connectors with keys are "
        "skipped when those keys are absent."
    )

with left:
    claims_text = st.text_area(
        "Paste claims (JSON list or CSV rows)",
        height=280,
        key="claims_text",
    )
    claims, parse_errors = _parse_claims(
        claims_text, uploaded.name if uploaded is not None else None
    )
    for message in parse_errors:
        st.error(message)

    run = st.button("Run verification", type="primary", disabled=not claims)
    if run:
        with st.spinner(f"Fetching and checking {len(claims)} document(s)…"):
            results = engine.verify_batch(claims)
        st.session_state.verify_report = {
            "generated_at": engine._now_iso(),
            "engine": "verify.py/1.0 (Streamlit UI)",
            "count": len(results),
            "summary": {
                engine.PASS: sum(1 for r in results if r["verdict"] == engine.PASS),
                engine.FAIL: sum(1 for r in results if r["verdict"] == engine.FAIL),
                engine.UNVERIFIABLE: sum(
                    1 for r in results if r["verdict"] == engine.UNVERIFIABLE
                ),
            },
            "results": results,
        }

report = st.session_state.verify_report

if report:
    st.subheader("Verdicts")
    summary = report["summary"]
    c1, c2, c3 = st.columns(3)
    c1.metric("PASS", summary[engine.PASS])
    c2.metric("FAIL", summary[engine.FAIL])
    c3.metric("UNVERIFIABLE", summary[engine.UNVERIFIABLE])

    rows = []
    for index, result in enumerate(report["results"]):
        rows.append(
            {
                "#": index + 1,
                "ID": result.get("claim_id", ""),
                "Verdict": result["verdict"],
                "Source": result["url"],
                "Final URL": result.get("final_url", ""),
                "HTTP": result.get("status", 0),
                "Tokens": ", ".join(t["token"] for t in result.get("tokens", [])),
                "Quoted span": _span_text(result),
                "SHA-256": (result.get("sha256") or "")[:16],
                "Fetched at": result.get("fetched_at", ""),
            }
        )
    st.dataframe(rows, width="stretch", hide_index=True)

    st.subheader("Detail and re-check")
    for index, result in enumerate(report["results"]):
        label = f"{index + 1}. {result.get('claim_id', '') or result['url']} — {result['verdict']}"
        with st.expander(label, expanded=False):
            st.markdown(f"**Requested URL:** `{result['url']}`")
            st.markdown(f"**Final URL:** `{result.get('final_url', '')}`")
            st.markdown(
                f"**HTTP:** {result.get('status', 0)} · "
                f"**Type:** {result.get('content_type', '') or '—'} · "
                f"**Bytes:** {result.get('bytes', 0)}"
            )
            st.markdown(
                f"**SHA-256:** `{result.get('sha256') or '—'}`  \n"
                f"**Snapshot:** `{result.get('snapshot_path') or '—'}`  \n"
                f"**Fetched at:** `{result.get('fetched_at', '')}`"
            )
            if result.get("reason"):
                st.warning(result["reason"])
            for token in result.get("tokens", []):
                status = "MATCH" if token.get("matched") else "NO MATCH"
                st.markdown(f"- `{token['token']}` — **{status}** ({token.get('matched_via') or 'no variant'})")
                if token.get("span"):
                    st.write(token["span"]["quote"])
                if token.get("near_miss"):
                    st.caption(f"Near miss (diagnostic only): {token['near_miss']['quote']}")
            if result.get("errors"):
                st.code("\n".join(result["errors"]))

            if st.button("Re-check this row", key=f"recheck-{index}"):
                with st.spinner("Re-fetching this source…"):
                    fresh = engine.verify(result["url"], result["must_contain"])
                    fresh["claim_id"] = result.get("claim_id", "")
                    fresh["claim_index"] = index
                    report["results"][index] = fresh
                    report["summary"] = {
                        engine.PASS: sum(
                            1 for r in report["results"] if r["verdict"] == engine.PASS
                        ),
                        engine.FAIL: sum(
                            1 for r in report["results"] if r["verdict"] == engine.FAIL
                        ),
                        engine.UNVERIFIABLE: sum(
                            1
                            for r in report["results"]
                            if r["verdict"] == engine.UNVERIFIABLE
                        ),
                    }
                st.rerun()

    report_json = json.dumps(report, indent=2, ensure_ascii=False)
    st.download_button(
        "Download JSON report",
        data=report_json,
        file_name=f"verification_report_{report['generated_at'].replace(':', '')}.json",
        mime="application/json",
    )
