"""
Research Hunter connectors.

Every function has the same contract:
    search_x(query: str, limit: int) -> list[dict]

Each result dict is normalized to:
    {
        "title": str,
        "authors": str,          # comma-joined, "" if unknown
        "date": str,              # ISO-ish string, "" if unknown
        "snippet": str,           # abstract / excerpt / description
        "url": str,
        "source": str,            # connector display name
        "source_type": str,       # "academic" | "regulatory" | "financial"
        "doi": str,                # "" if none — used by the Unpaywall enricher
    }

No connector ever raises past its own function — network failures,
missing keys, and bad responses are caught and logged, and an empty
list is returned so one dead source never takes down the whole search.
"""
import logging
import requests
import feedparser

from config import (
    CONTACT_EMAIL,
    CORE_API_KEY,
    FRED_API_KEY,
    SEMANTIC_SCHOLAR_API_KEY,
    REQUEST_TIMEOUT,
    COMPANIES_HOUSE_API_KEY,
    COURTLISTENER_API_KEY,
    WORLD_BANK_API_KEY,
)

log = logging.getLogger("research_hunter.connectors")

UA = f"ResearchHunter/1.0 (Infrastructure & Power research tool; {CONTACT_EMAIL or 'no-contact-set'})"


def _safe_get(url, **kwargs):
    kwargs.setdefault("timeout", REQUEST_TIMEOUT)
    kwargs.setdefault("headers", {})
    kwargs["headers"].setdefault("User-Agent", UA)
    return requests.get(url, **kwargs)


# ---------------------------------------------------------------------------
# ACADEMIC / RESEARCH SOURCES (no key required unless noted)
# ---------------------------------------------------------------------------

def search_arxiv(query, limit):
    """arXiv — preprints, strongest for quant finance, ML, and complex-systems angles."""
    try:
        url = "http://export.arxiv.org/api/query"
        params = {"search_query": f"all:{query}", "start": 0, "max_results": limit}
        resp = _safe_get(url, params=params)
        resp.raise_for_status()
        feed = feedparser.parse(resp.content)
        out = []
        for e in feed.entries:
            out.append({
                "title": e.get("title", "").replace("\n", " ").strip(),
                "authors": ", ".join(a.get("name", "") for a in e.get("authors", [])),
                "date": e.get("published", "")[:10],
                "snippet": e.get("summary", "").replace("\n", " ").strip()[:500],
                "url": e.get("link", ""),
                "source": "arXiv",
                "source_type": "academic",
                "doi": e.get("arxiv_doi", ""),
            })
        return out
    except Exception as exc:
        log.warning("arXiv search failed: %s", exc)
        return []


def search_crossref(query, limit):
    """CrossRef — the DOI registry; best broad coverage of peer-reviewed literature."""
    try:
        url = "https://api.crossref.org/works"
        params = {"query": query, "rows": limit}
        if CONTACT_EMAIL:
            params["mailto"] = CONTACT_EMAIL
        resp = _safe_get(url, params=params)
        resp.raise_for_status()
        items = resp.json().get("message", {}).get("items", [])
        out = []
        for it in items:
            title = " ".join(it.get("title", []) or [""])
            authors = ", ".join(
                f"{a.get('given', '')} {a.get('family', '')}".strip()
                for a in it.get("author", []) or []
            )
            date_parts = (
                it.get("published-print", it.get("published-online", {}))
                .get("date-parts", [[]])
            )
            date = "-".join(str(p) for p in date_parts[0]) if date_parts and date_parts[0] else ""
            out.append({
                "title": title,
                "authors": authors,
                "date": date,
                "snippet": (it.get("container-title") or [""])[0],
                "url": it.get("URL", ""),
                "source": "CrossRef",
                "source_type": "academic",
                "doi": it.get("DOI", ""),
            })
        return out
    except Exception as exc:
        log.warning("CrossRef search failed: %s", exc)
        return []


def search_openalex(query, limit):
    """OpenAlex — free, huge, well-structured metadata; good for citation/impact signal."""
    try:
        url = "https://api.openalex.org/works"
        params = {"search": query, "per-page": limit}
        if CONTACT_EMAIL:
            params["mailto"] = CONTACT_EMAIL
        resp = _safe_get(url, params=params)
        resp.raise_for_status()
        results = resp.json().get("results", [])
        out = []
        for it in results:
            authors = ", ".join(
                a.get("author", {}).get("display_name", "")
                for a in it.get("authorships", []) or []
            )
            oa = it.get("open_access", {}) or {}
            out.append({
                "title": it.get("title") or it.get("display_name") or "",
                "authors": authors,
                "date": it.get("publication_date", ""),
                "snippet": it.get("primary_location", {}).get("source", {}).get("display_name", "") or "",
                "url": oa.get("oa_url") or it.get("id", ""),
                "source": "OpenAlex",
                "source_type": "academic",
                "doi": (it.get("doi") or "").replace("https://doi.org/", ""),
            })
        return out
    except Exception as exc:
        log.warning("OpenAlex search failed: %s", exc)
        return []


def search_semantic_scholar(query, limit):
    """Semantic Scholar — strong abstracts and citation counts, good relevance ranking."""
    try:
        url = "https://api.semanticscholar.org/graph/v1/paper/search"
        params = {
            "query": query,
            "limit": limit,
            "fields": "title,abstract,year,authors,url,externalIds",
        }
        headers = {}
        if SEMANTIC_SCHOLAR_API_KEY:
            headers["x-api-key"] = SEMANTIC_SCHOLAR_API_KEY
        resp = _safe_get(url, params=params, headers=headers)
        resp.raise_for_status()
        data = resp.json().get("data", [])
        out = []
        for it in data:
            out.append({
                "title": it.get("title", ""),
                "authors": ", ".join(a.get("name", "") for a in it.get("authors", []) or []),
                "date": str(it.get("year", "") or ""),
                "snippet": (it.get("abstract") or "")[:500],
                "url": it.get("url", ""),
                "source": "Semantic Scholar",
                "source_type": "academic",
                "doi": (it.get("externalIds") or {}).get("DOI", ""),
            })
        return out
    except Exception as exc:
        log.warning("Semantic Scholar search failed: %s", exc)
        return []


def search_doaj(query, limit):
    """DOAJ — Directory of Open Access Journals; everything returned is free to read in full."""
    try:
        url = f"https://doaj.org/api/search/articles/{requests.utils.quote(query)}"
        params = {"pageSize": limit}
        resp = _safe_get(url, params=params)
        resp.raise_for_status()
        results = resp.json().get("results", [])
        out = []
        for it in results:
            bib = it.get("bibjson", {})
            authors = ", ".join(a.get("name", "") for a in bib.get("author", []) or [])
            link = next((l.get("url", "") for l in bib.get("link", []) or []), "")
            out.append({
                "title": bib.get("title", ""),
                "authors": authors,
                "date": bib.get("year", ""),
                "snippet": bib.get("abstract", "")[:500] if bib.get("abstract") else "",
                "url": link,
                "source": "DOAJ",
                "source_type": "academic",
                "doi": next(
                    (i.get("id", "") for i in bib.get("identifier", []) or [] if i.get("type") == "doi"),
                    "",
                ),
            })
        return out
    except Exception as exc:
        log.warning("DOAJ search failed: %s", exc)
        return []


def search_europepmc(query, limit):
    """Europe PMC — deep for public health / biotech angles (relevant to Pillar 4 biotech topics)."""
    try:
        url = "https://www.ebi.ac.uk/europepmc/webservices/rest/search"
        params = {"query": query, "format": "json", "pageSize": limit}
        resp = _safe_get(url, params=params)
        resp.raise_for_status()
        results = resp.json().get("resultList", {}).get("result", [])
        out = []
        for it in results:
            out.append({
                "title": it.get("title", ""),
                "authors": it.get("authorString", ""),
                "date": it.get("firstPublicationDate", ""),
                "snippet": it.get("abstractText", "")[:500] if it.get("abstractText") else "",
                "url": f"https://europepmc.org/article/{it.get('source', '')}/{it.get('id', '')}",
                "source": "Europe PMC",
                "source_type": "academic",
                "doi": it.get("doi", ""),
            })
        return out
    except Exception as exc:
        log.warning("Europe PMC search failed: %s", exc)
        return []


def search_core(query, limit):
    """CORE — aggregates full-text from repositories worldwide. Needs a free API key."""
    if not CORE_API_KEY:
        return []
    try:
        url = "https://api.core.ac.uk/v3/search/works/"
        headers = {"Authorization": f"Bearer {CORE_API_KEY}"}
        params = {"q": query, "limit": limit}
        resp = _safe_get(url, params=params, headers=headers)
        resp.raise_for_status()
        results = resp.json().get("results", [])
        out = []
        for it in results:
            authors = ", ".join(a.get("name", "") for a in it.get("authors", []) or [])
            out.append({
                "title": it.get("title", ""),
                "authors": authors,
                "date": (it.get("publishedDate", "") or "")[:10],
                "snippet": (it.get("abstract") or "")[:500],
                "url": it.get("downloadUrl") or it.get("sourceFulltextUrls", [""])[0] if it.get("sourceFulltextUrls") else it.get("id", ""),
                "source": "CORE",
                "source_type": "academic",
                "doi": it.get("doi", "") or "",
            })
        return out
    except Exception as exc:
        log.warning("CORE search failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# REGULATORY / POLICY SOURCES — added for Infrastructure & Power specifically.
# The original 8 academic connectors are built for literature review; a
# channel about corporate structures, executive orders, and institutional
# power needs primary regulatory documents far more than journal articles.
# ---------------------------------------------------------------------------

def search_sec_edgar(query, limit):
    """
    SEC EDGAR full-text search — 10-Ks, 10-Qs, 8-Ks, proxy statements.
    This is the single best source for the "highlighted line in an SEC
    filing" visual the whole channel style is built around.
    SEC requires a descriptive User-Agent with a contact — set CONTACT_EMAIL.
    """
    try:
        url = "https://efts.sec.gov/LATEST/search-index"
        params = {"q": f'"{query}"', "forms": "10-K,10-Q,8-K,DEF 14A", "hits": limit}
        resp = _safe_get(url, params=params)
        resp.raise_for_status()
        hits = resp.json().get("hits", {}).get("hits", [])
        out = []
        for h in hits[:limit]:
            src = h.get("_source", {})
            cik = src.get("ciks", [""])[0] if src.get("ciks") else ""
            accession = h.get("_id", "").split(":")[0]
            out.append({
                "title": src.get("display_names", [""])[0] + " — " + src.get("form", ""),
                "authors": src.get("display_names", [""])[0] if src.get("display_names") else "",
                "date": src.get("file_date", ""),
                "snippet": f"Form {src.get('form', '')} filed {src.get('file_date', '')}",
                "url": f"https://www.sec.gov/cgi-bin/browse-edgar?action=getcompany&CIK={cik}",
                "source": "SEC EDGAR",
                "source_type": "regulatory",
                "doi": "",
            })
        return out
    except Exception as exc:
        log.warning("SEC EDGAR search failed: %s", exc)
        return []


def search_federal_register(query, limit):
    """Federal Register — executive orders, agency rules, proposed regulations. No key required."""
    try:
        url = "https://www.federalregister.gov/api/v1/articles.json"
        params = {
            "conditions[term]": query,
            "per_page": limit,
            "order": "newest",
        }
        resp = _safe_get(url, params=params)
        resp.raise_for_status()
        results = resp.json().get("results", [])
        out = []
        for it in results:
            out.append({
                "title": it.get("title", ""),
                "authors": ", ".join(it.get("agencies_names", []) or []) if it.get("agencies_names") else (it.get("agency_names") or ""),
                "date": it.get("publication_date", ""),
                "snippet": (it.get("abstract") or it.get("type", ""))[:500] if it.get("abstract") else it.get("type", ""),
                "url": it.get("html_url", ""),
                "source": "Federal Register",
                "source_type": "regulatory",
                "doi": "",
            })
        return out
    except Exception as exc:
        log.warning("Federal Register search failed: %s", exc)
        return []


def search_fred(query, limit):
    """FRED — Federal Reserve Economic Data series search. Needs a free API key."""
    if not FRED_API_KEY:
        return []
    try:
        url = "https://api.stlouisfed.org/fred/series/search"
        params = {
            "search_text": query,
            "api_key": FRED_API_KEY,
            "file_type": "json",
            "limit": limit,
        }
        resp = _safe_get(url, params=params)
        resp.raise_for_status()
        series = resp.json().get("seriess", [])
        out = []
        for s in series:
            out.append({
                "title": s.get("title", ""),
                "authors": s.get("units", ""),
                "date": s.get("last_updated", "")[:10] if s.get("last_updated") else "",
                "snippet": f"Frequency: {s.get('frequency', '')}. Observation range: {s.get('observation_start', '')} to {s.get('observation_end', '')}.",
                "url": f"https://fred.stlouisfed.org/series/{s.get('id', '')}",
                "source": "FRED",
                "source_type": "financial",
                "doi": "",
            })
        return out
    except Exception as exc:
        log.warning("FRED search failed: %s", exc)
        return []


# ---------------------------------------------------------------------------
# ENRICHMENT — Unpaywall is a DOI lookup, not a search engine, so it can't
# be a standalone connector. It's applied after the fact to any result that
# carries a DOI, to check whether a free full-text version exists.
# ---------------------------------------------------------------------------

def enrich_with_unpaywall(results):
    """Given normalized results, add 'open_access_url' for any with a DOI, via Unpaywall."""
    if not CONTACT_EMAIL:
        for r in results:
            r["open_access_url"] = ""
        return results
    for r in results:
        doi = r.get("doi", "")
        if not doi:
            r["open_access_url"] = ""
            continue
        try:
            url = f"https://api.unpaywall.org/v2/{doi}"
            resp = _safe_get(url, params={"email": CONTACT_EMAIL})
            if resp.status_code == 200:
                data = resp.json()
                best = data.get("best_oa_location") or {}
                r["open_access_url"] = best.get("url_for_pdf") or best.get("url") or ""
            else:
                r["open_access_url"] = ""
        except Exception as exc:
            log.warning("Unpaywall enrichment failed for DOI %s: %s", doi, exc)
            r["open_access_url"] = ""
    return results


# ---------------------------------------------------------------------------
# PRIMARY / OFFICIAL SOURCES (Task A) — legislation, courts, government,
# statistics, corporate registries. Prioritised free + keyless. Every
# connector degrades to [] when a required key is absent and never raises.
# ---------------------------------------------------------------------------

def _squash(s):
    """Collapse whitespace so titles/snippets from XML or scraped HTML stay tidy."""
    return " ".join((s or "").split())


def _legislation_uri_for_section(url):
    """
    Turn a human legislation.gov.uk URL into the API section/content URL.

    Accepts e.g.
      https://www.legislation.gov.uk/ukpga/2023/1/section/5
      https://www.legislation.gov.uk/ukpga/2023/1/section/5/enacted
      https://www.legislation.gov.uk/uksi/2019/1234/regulation/7
    and returns the /data.xml form of the *specific provision* so callers can
    resolve and extract the text of one section rather than the whole Act.
    Returns ("", "") when the URL does not carry a provision path.
    """
    from urllib.parse import urlparse

    path = urlparse(url).path.strip("/")
    if not path:
        return "", ""
    # Provision keywords used by legislation.gov.uk service URLs.
    markers = ["/section/", "/regulation/", "/article/", "/schedule/",
               "/part/", "/chapter/", "/rule/"]
    for marker in markers:
        if marker in "/" + path:
            base, _, rest = ("/" + path).partition(marker)
            provision = rest.split("/")[0]
            if provision:
                kind = marker.strip("/")
                api_path = f"{base.strip('/')}/{kind}/{provision}/data.xml"
                return f"https://www.legislation.gov.uk/{api_path}", f"{base.strip('/')}/{kind}/{provision}"
    # Whole-instrument URL (no provision) — fall back to the instrument itself.
    return f"https://www.legislation.gov.uk/{path}/data.xml", path


def search_legislation_gov_uk(query, limit):
    """
    legislation.gov.uk — UK statutes and statutory instruments (official, keyless).

    If `query` looks like a legislation.gov.uk URL, the specific section is
    fetched and returned as a single result whose snippet carries the section
    text. Otherwise the Atom search feed is used.
    """
    try:
        if "legislation.gov.uk" in query and "/" in query:
            api_url, ident = _legislation_uri_for_section(query)
            if not api_url:
                return []
            resp = _safe_get(api_url)
            resp.raise_for_status()
            # The response is XML (akn/legislation XML); strip tags for a snippet.
            import re as _re
            raw = resp.text
            text = _re.sub(r"<[^>]+>", " ", raw)
            text = _squash(text)
            return [{
                "title": f"legislation.gov.uk provision: {ident}",
                "authors": "legislation.gov.uk (The National Archives)",
                "date": "",
                "snippet": text[:1200],
                "url": query if query.startswith("http") else f"https://{api_url}",
                "source": "legislation.gov.uk",
                "source_type": "regulatory",
                "doi": "",
            }]
        url = "https://www.legislation.gov.uk/all/data.feed"
        params = {"title": query, "page-size": limit}
        resp = _safe_get(url, params=params)
        resp.raise_for_status()
        feed = feedparser.parse(resp.content)
        out = []
        for e in feed.entries:
            out.append({
                "title": _squash(e.get("title", "")),
                "authors": "legislation.gov.uk (The National Archives)",
                "date": (e.get("updated", "") or "")[:10],
                "snippet": _squash(e.get("summary", ""))[:500],
                "url": e.get("link", ""),
                "source": "legislation.gov.uk",
                "source_type": "regulatory",
                "doi": "",
            })
        return out
    except Exception as exc:
        log.warning("legislation.gov.uk search failed: %s", exc)
        return []


def search_find_case_law(query, limit):
    """Find Case Law (National Archives) — UK court judgments and tribunal decisions. Keyless."""
    try:
        url = "https://caselaw.nationalarchives.gov.uk/atom.xml"
        resp = _safe_get(url, params={"query": query, "per_page": limit})
        resp.raise_for_status()
        feed = feedparser.parse(resp.content)
        out = []
        for e in feed.entries:
            out.append({
                "title": _squash(e.get("title", "")),
                "authors": _squash(e.get("author", "")),
                "date": (e.get("published", "") or e.get("updated", "") or "")[:10],
                "snippet": _squash(e.get("summary", ""))[:500],
                "url": e.get("link", ""),
                "source": "Find Case Law",
                "source_type": "regulatory",
                "doi": "",
            })
        return out
    except Exception as exc:
        log.warning("Find Case Law search failed: %s", exc)
        return []


def search_gov_uk(query, limit):
    """GOV.UK search API — official UK government publications, consultations, announcements. Keyless."""
    try:
        url = "https://www.gov.uk/api/search.json"
        resp = _safe_get(url, params={"q": query, "count": limit})
        resp.raise_for_status()
        results = resp.json().get("results", [])
        out = []
        for it in results:
            link = it.get("link", "")
            out.append({
                "title": _squash(it.get("title", "")),
                "authors": _squash(it.get("organisations", [{}])[0].get("title", ""))
                if it.get("organisations") else "GOV.UK",
                "date": (it.get("public_timestamp", "") or "")[:10],
                "snippet": _squash(it.get("description", ""))[:500],
                "url": f"https://www.gov.uk{link}" if link.startswith("/") else link,
                "source": "GOV.UK",
                "source_type": "regulatory",
                "doi": "",
            })
        return out
    except Exception as exc:
        log.warning("GOV.UK search failed: %s", exc)
        return []


def search_data_gov_uk(query, limit):
    """data.gov.uk — UK open datasets catalogue. Keyless."""
    try:
        url = "https://data.gov.uk/api/search/search/"
        params = {"q": query, "results-per-page": limit}
        resp = _safe_get(url, params=params)
        resp.raise_for_status()
        results = resp.json().get("result", {}).get("results", [])
        out = []
        for it in results:
            out.append({
                "title": _squash(it.get("title", "")),
                "authors": _squash(it.get("organisation", {}).get("title", ""))
                if it.get("organisation") else "data.gov.uk",
                "date": (it.get("metadata_modified", "") or "")[:10],
                "snippet": _squash(it.get("notes", ""))[:500],
                "url": f"https://data.gov.uk{it.get('link', '')}" if str(it.get("link", "")).startswith("/") else it.get("link", ""),
                "source": "data.gov.uk",
                "source_type": "regulatory",
                "doi": "",
            })
        return out
    except Exception as exc:
        log.warning("data.gov.uk search failed: %s", exc)
        return []


def search_ons(query, limit):
    """ONS (Office for National Statistics) beta API — official UK statistics datasets. Keyless."""
    try:
        url = "https://api.beta.ons.gov.uk/v1/datasets"
        resp = _safe_get(url, params={"limit": limit})
        resp.raise_for_status()
        items = resp.json().get("items", [])
        needle = (query or "").lower()
        out = []
        for it in items:
            title = _squash(it.get("title", ""))
            desc = _squash(it.get("description", ""))
            # The datasets endpoint has no free-text search; filter locally.
            if needle and needle not in title.lower() and needle not in desc.lower():
                continue
            out.append({
                "title": title,
                "authors": "Office for National Statistics",
                "date": (it.get("release_date", "") or it.get("last_updated", "") or "")[:10],
                "snippet": desc[:500],
                "url": f"https://www.ons.gov.uk{it.get('uri', '')}" if str(it.get("uri", "")).startswith("/") else it.get("uri", ""),
                "source": "ONS",
                "source_type": "financial",
                "doi": "",
            })
        return out[:limit]
    except Exception as exc:
        log.warning("ONS search failed: %s", exc)
        return []


def search_hansard(query, limit):
    """UK Parliament Hansard — written/official report debates. Keyless."""
    try:
        url = "https://hansard-api.parliament.uk/search.json"
        resp = _safe_get(url, params={"queryParameters.searchTerm": query})
        resp.raise_for_status()
        results = resp.json().get("Results", []) or []
        out = []
        for it in results[:limit]:
            out.append({
                "title": _squash(it.get("Title", "") or it.get("ContributionText", ""))[:200],
                "authors": _squash(it.get("MemberName", "") or it.get("House", "UK Parliament")),
                "date": (it.get("SittingDate", "") or "")[:10],
                "snippet": _squash(it.get("ContributionText", "") or it.get("Summary", ""))[:500],
                "url": it.get("Url", "") or "https://hansard.parliament.uk/",
                "source": "UK Parliament Hansard",
                "source_type": "regulatory",
                "doi": "",
            })
        return out
    except Exception as exc:
        log.warning("Hansard search failed: %s", exc)
        return []


def search_companies_house(query, limit):
    """Companies House — UK company register. Needs COMPANIES_HOUSE_API_KEY (free). Omits when absent."""
    if not COMPANIES_HOUSE_API_KEY:
        log.info("Companies House skipped: no COMPANIES_HOUSE_API_KEY")
        return []
    try:
        url = "https://api.company-information.service.gov.uk/search/companies"
        resp = requests.get(
            url,
            params={"q": query, "items_per_page": limit},
            auth=(COMPANIES_HOUSE_API_KEY, ""),
            headers={"User-Agent": UA},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        items = resp.json().get("items", [])
        out = []
        for it in items:
            out.append({
                "title": _squash(it.get("title", "")),
                "authors": _squash(it.get("address_snippet", "")),
                "date": (it.get("date_of_creation", "") or "")[:10],
                "snippet": f"{_squash(it.get('company_type', ''))} {_squash(it.get('company_status', ''))} — {_squash(it.get('snippet', ''))}".strip(),
                "url": f"https://find-and-update.company-information.service.gov.uk{it.get('link', '')}",
                "source": "Companies House",
                "source_type": "financial",
                "doi": "",
            })
        return out
    except Exception as exc:
        log.warning("Companies House search failed: %s", exc)
        return []


def search_eur_lex(query, limit):
    """EUR-Lex — EU law (treaties, regulations, directives). Keyless SPARQL over the EU publications endpoint."""
    try:
        sparql = (
            "PREFIX cdm: <http://publications.europa.eu/ontology/cdm#> "
            "SELECT ?work ?title WHERE { "
            "?work cdm:work_date_document ?d . "
            "?exp cdm:expression_belongs_to_work ?work . "
            "?exp cdm:expression_title ?title . "
            f'FILTER(CONTAINS(LCASE(?title), LCASE("{query}") )) '
            "} LIMIT " + str(int(limit))
        )
        resp = _safe_get(
            "https://publications.europa.eu/webapi/rdf/sparql",
            params={"query": sparql, "format": "application/sparql-results+json"},
        )
        resp.raise_for_status()
        rows = resp.json().get("results", {}).get("bindings", [])
        out = []
        for r in rows:
            title = _squash(r.get("title", {}).get("value", ""))
            work = r.get("work", {}).get("value", "")
            out.append({
                "title": title,
                "authors": "European Union",
                "date": "",
                "snippet": "EUR-Lex legal act",
                "url": work or "https://eur-lex.europa.eu/",
                "source": "EUR-Lex",
                "source_type": "regulatory",
                "doi": "",
            })
        return out
    except Exception as exc:
        log.warning("EUR-Lex search failed: %s", exc)
        return []


def search_eurostat(query, limit):
    """Eurostat — EU official statistics (SDMX dissemination API). Keyless."""
    try:
        url = "https://ec.europa.eu/eurostat/api/dissemination/statistics/1.0/data/"
        # The dataset list is a separate catalogue; use it to find candidates.
        cat = _safe_get("https://ec.europa.eu/eurostat/api/dissemination/catalogue/datasets",
                        params={"format": "JSON", "lang": "EN"})
        cat.raise_for_status()
        data = cat.json()
        items = data.get("items") or data.get("datasets") or []
        needle = (query or "").lower()
        out = []
        for it in items:
            code = it.get("code") or it.get("id") or ""
            label = _squash(it.get("label") or it.get("name") or code)
            if needle and needle not in label.lower() and needle not in code.lower():
                continue
            out.append({
                "title": label,
                "authors": "Eurostat",
                "date": "",
                "snippet": f"Eurostat dataset {code}",
                "url": f"https://ec.europa.eu/eurostat/databrowser/view/{code}",
                "source": "Eurostat",
                "source_type": "financial",
                "doi": "",
            })
            if len(out) >= limit:
                break
        return out
    except Exception as exc:
        log.warning("Eurostat search failed: %s", exc)
        return []


def search_world_bank(query, limit):
    """World Bank Open Data — indicators catalogue. Keyless (optional WORLD_BANK_API_KEY raises limits)."""
    try:
        url = "https://api.worldbank.org/v2/indicator"
        params = {"format": "json", "per_page": 200}
        if WORLD_BANK_API_KEY:
            params["api_key"] = WORLD_BANK_API_KEY
        # Indicator endpoint is slow; give it more room than the default.
        resp = _safe_get(url, params=params, timeout=max(REQUEST_TIMEOUT, 45))
        resp.raise_for_status()
        payload = resp.json()
        rows = payload[1] if isinstance(payload, list) and len(payload) > 1 else []
        needle = (query or "").lower()
        out = []
        for it in rows or []:
            name = _squash(it.get("name", ""))
            if needle and needle not in name.lower():
                continue
            out.append({
                "title": name,
                "authors": "World Bank",
                "date": "",
                "snippet": _squash(it.get("sourceNote", ""))[:500],
                "url": f"https://data.worldbank.org/indicator/{it.get('id', '')}",
                "source": "World Bank Open Data",
                "source_type": "financial",
                "doi": "",
            })
            if len(out) >= limit:
                break
        return out
    except Exception as exc:
        log.warning("World Bank search failed: %s", exc)
        return []


def search_imf(query, limit):
    """IMF Data — via the SDMX 2.1 API used by the IMF data portal. Keyless."""
    try:
        url = "https://api.imf.org/external/sdmx/2.1/dataflow/IMF"
        resp = _safe_get(url, params={"format": "jsondata"}, timeout=max(REQUEST_TIMEOUT, 40))
        resp.raise_for_status()
        data = resp.json()
        rows = (
            data.get("data", {}).get("dataflows")
            or data.get("dataflows")
            or []
        )
        needle = (query or "").lower()
        out = []
        for it in rows:
            name = _squash(it.get("name") or it.get("Name") or "")
            ident = it.get("id") or it.get("Id") or ""
            if needle and needle not in name.lower() and needle not in str(ident).lower():
                continue
            out.append({
                "title": name or str(ident),
                "authors": "International Monetary Fund",
                "date": "",
                "snippet": _squash(it.get("description") or "")[:500],
                "url": "https://data.imf.org/",
                "source": "IMF",
                "source_type": "financial",
                "doi": "",
            })
            if len(out) >= limit:
                break
        return out
    except Exception as exc:
        log.warning("IMF search failed: %s", exc)
        return []


def search_oecd(query, limit):
    """OECD Data — SDMX 3.0 dataflows. Keyless."""
    try:
        url = "https://sdmx.oecd.org/public/rest/dataflow/OECD.SDD.NAD"
        resp = _safe_get(url, params={"format": "sdmx-3.0"}, timeout=max(REQUEST_TIMEOUT, 40))
        resp.raise_for_status()
        import re as _re
        text = resp.text
        # SDMX XML/JSON variants differ; pull Name elements defensively.
        names = _re.findall(r"<[^>]*Name[^>]*>\s*([^<]{3,200})\s*<", text)
        needle = (query or "").lower()
        out = []
        for n in names:
            clean = _squash(n)
            if needle and needle not in clean.lower():
                continue
            out.append({
                "title": clean,
                "authors": "OECD",
                "date": "",
                "snippet": "OECD dataflow",
                "url": "https://data.oecd.org/",
                "source": "OECD",
                "source_type": "financial",
                "doi": "",
            })
            if len(out) >= limit:
                break
        return out
    except Exception as exc:
        log.warning("OECD search failed: %s", exc)
        return []


def search_un_data(query, limit):
    """UN Data / UNCTAD — via the UN Data Portal (data.un.org) and UN Statistics SDMX API. Keyless."""
    try:
        url = "https://api.data.un.org/v1/datasets"
        resp = _safe_get(url, params={"limit": limit}, timeout=max(REQUEST_TIMEOUT, 40))
        resp.raise_for_status()
        data = resp.json()
        rows = data.get("data") or data.get("datasets") or data.get("results") or []
        out = []
        for it in rows[:limit]:
            out.append({
                "title": _squash(it.get("title") or it.get("name") or it.get("id", "")),
                "authors": "United Nations",
                "date": (it.get("updated", "") or "")[:10],
                "snippet": _squash(it.get("description", ""))[:500],
                "url": it.get("url") or "https://data.un.org/",
                "source": "UN Data / UNCTAD",
                "source_type": "financial",
                "doi": "",
            })
        return out
    except Exception as exc:
        log.warning("UN Data search failed: %s", exc)
        return []


def search_data_gov_us(query, limit):
    """data.gov (US) — Federal open-data catalogue via CKAN. Keyless."""
    try:
        url = "https://catalog.data.gov/api/3/action/package_search"
        resp = _safe_get(url, params={"q": query, "rows": limit})
        resp.raise_for_status()
        results = resp.json().get("result", {}).get("results", [])
        out = []
        for it in results:
            org = (it.get("organization") or {}).get("title", "") if isinstance(it.get("organization"), dict) else ""
            out.append({
                "title": _squash(it.get("title", "")),
                "authors": _squash(org) or "data.gov",
                "date": (it.get("metadata_modified", "") or "")[:10],
                "snippet": _squash(it.get("notes", ""))[:500],
                "url": f"https://catalog.data.gov/dataset/{it.get('name', '')}",
                "source": "data.gov (US)",
                "source_type": "regulatory",
                "doi": "",
            })
        return out
    except Exception as exc:
        log.warning("data.gov (US) search failed: %s", exc)
        return []


def search_courtlistener(query, limit):
    """CourtListener (US case law) — free, but the search API wants a token. Omits when absent."""
    if not COURTLISTENER_API_KEY:
        log.info("CourtListener skipped: no COURTLISTENER_API_KEY")
        return []
    try:
        url = "https://www.courtlistener.com/api/rest/v4/search/"
        resp = requests.get(
            url,
            params={"q": query, "type": "o"},
            headers={"Authorization": f"Token {COURTLISTENER_API_KEY}", "User-Agent": UA},
            timeout=REQUEST_TIMEOUT,
        )
        resp.raise_for_status()
        results = resp.json().get("results", [])
        out = []
        for it in results[:limit]:
            out.append({
                "title": _squash(it.get("caseName", "") or it.get("case_name", "")),
                "authors": _squash(it.get("court", "")),
                "date": (it.get("dateFiled", "") or "")[:10],
                "snippet": _squash(it.get("snippet", "") or it.get("text", ""))[:500],
                "url": f"https://www.courtlistener.com{it.get('absolute_url', '')}"
                if str(it.get("absolute_url", "")).startswith("/") else it.get("absolute_url", ""),
                "source": "CourtListener",
                "source_type": "regulatory",
                "doi": "",
            })
        return out
    except Exception as exc:
        log.warning("CourtListener search failed: %s", exc)
        return []


def search_wikidata(query, limit):
    """Wikidata — entity search; useful for resolving names, IDs and identifiers. Keyless."""
    try:
        url = "https://www.wikidata.org/w/api.php"
        resp = _safe_get(url, params={
            "action": "wbsearchentities",
            "search": query,
            "language": "en",
            "format": "json",
            "limit": limit,
        })
        resp.raise_for_status()
        rows = resp.json().get("search", [])
        out = []
        for it in rows:
            qid = it.get("id", "")
            out.append({
                "title": _squash(it.get("label", "") or qid),
                "authors": "Wikidata",
                "date": "",
                "snippet": _squash(it.get("description", ""))[:500],
                "url": it.get("concepturi") or f"https://www.wikidata.org/wiki/{qid}",
                "source": "Wikidata",
                "source_type": "academic",
                "doi": "",
            })
        return out
    except Exception as exc:
        log.warning("Wikidata search failed: %s", exc)
        return []


def search_wikipedia(query, limit):
    """Wikipedia REST — full-text search, then per-article summaries. Keyless. Fast corroboration only."""
    try:
        url = "https://en.wikipedia.org/w/rest.php/v1/search/page"
        resp = _safe_get(url, params={"q": query, "limit": limit})
        resp.raise_for_status()
        pages = resp.json().get("pages", [])
        out = []
        for p in pages[:limit]:
            title = p.get("title", "")
            out.append({
                "title": _squash(title),
                "authors": "Wikipedia",
                "date": (p.get("timestamp", "") or "")[:10],
                "snippet": _squash(p.get("excerpt", "") or p.get("description", ""))[:500],
                "url": f"https://en.wikipedia.org/wiki/{p.get('key', title).replace(' ', '_')}",
                "source": "Wikipedia",
                "source_type": "academic",
                "doi": "",
            })
        return out
    except Exception as exc:
        log.warning("Wikipedia search failed: %s", exc)
        return []

# Registry used by app.py — add a connector here and it shows up everywhere,
# including the frontend's source checklist, automatically.
CONNECTORS = {
    "arxiv": {"fn": search_arxiv, "label": "arXiv", "type": "academic", "needs_key": False},
    "crossref": {"fn": search_crossref, "label": "CrossRef", "type": "academic", "needs_key": False},
    "openalex": {"fn": search_openalex, "label": "OpenAlex", "type": "academic", "needs_key": False},
    "semantic_scholar": {"fn": search_semantic_scholar, "label": "Semantic Scholar", "type": "academic", "needs_key": False},
    "doaj": {"fn": search_doaj, "label": "DOAJ", "type": "academic", "needs_key": False},
    "europepmc": {"fn": search_europepmc, "label": "Europe PMC", "type": "academic", "needs_key": False},
    "core": {"fn": search_core, "label": "CORE", "type": "academic", "needs_key": True, "key_name": "CORE_API_KEY"},
    "sec_edgar": {"fn": search_sec_edgar, "label": "SEC EDGAR", "type": "regulatory", "needs_key": False},
    "federal_register": {"fn": search_federal_register, "label": "Federal Register", "type": "regulatory", "needs_key": False},
    "fred": {"fn": search_fred, "label": "FRED (Economic Data)", "type": "financial", "needs_key": True, "key_name": "FRED_API_KEY"},
    # --- primary / official sources (Task A) ---
    "legislation_gov_uk": {"fn": search_legislation_gov_uk, "label": "legislation.gov.uk", "type": "primary", "needs_key": False},
    "find_case_law": {"fn": search_find_case_law, "label": "Find Case Law (UK)", "type": "primary", "needs_key": False},
    "gov_uk": {"fn": search_gov_uk, "label": "GOV.UK", "type": "primary", "needs_key": False},
    "data_gov_uk": {"fn": search_data_gov_uk, "label": "data.gov.uk", "type": "primary", "needs_key": False},
    "ons": {"fn": search_ons, "label": "ONS", "type": "primary", "needs_key": False},
    "hansard": {"fn": search_hansard, "label": "UK Parliament Hansard", "type": "primary", "needs_key": False},
    "companies_house": {"fn": search_companies_house, "label": "Companies House", "type": "primary", "needs_key": True, "key_name": "COMPANIES_HOUSE_API_KEY"},
    "eur_lex": {"fn": search_eur_lex, "label": "EUR-Lex", "type": "primary", "needs_key": False},
    "eurostat": {"fn": search_eurostat, "label": "Eurostat", "type": "primary", "needs_key": False},
    "world_bank": {"fn": search_world_bank, "label": "World Bank Open Data", "type": "primary", "needs_key": False},
    "imf": {"fn": search_imf, "label": "IMF", "type": "primary", "needs_key": False},
    "oecd": {"fn": search_oecd, "label": "OECD", "type": "primary", "needs_key": False},
    "un_data": {"fn": search_un_data, "label": "UN Data / UNCTAD", "type": "primary", "needs_key": False},
    "data_gov_us": {"fn": search_data_gov_us, "label": "data.gov (US)", "type": "primary", "needs_key": False},
    "courtlistener": {"fn": search_courtlistener, "label": "CourtListener", "type": "primary", "needs_key": True, "key_name": "COURTLISTENER_API_KEY"},
    "wikidata": {"fn": search_wikidata, "label": "Wikidata", "type": "primary", "needs_key": False},
    "wikipedia": {"fn": search_wikipedia, "label": "Wikipedia", "type": "primary", "needs_key": False},
}
