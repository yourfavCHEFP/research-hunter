"""
Knowledge Vault — the command-center dashboard sitting over status.json.

Read-only against the pipeline: it never writes to 01_Raw_Research or
02_Curated_Data itself, it just visualizes what the Orchestrator has
already done and gives you one-click actions to move curated research
into your scripting workflow.

Run alongside the Orchestrator (separate terminal tab):
    python3 knowledge_vault.py
Then open http://localhost:5060
"""
import csv
import json
from pathlib import Path

from flask import Flask, jsonify, render_template, abort

BASE_DIR = Path(__file__).parent
STATUS_FILE = BASE_DIR / "status.json"

app = Flask(__name__)


def load_status():
    if not STATUS_FILE.exists():
        return {"items": {}, "last_updated": None}
    try:
        with open(STATUS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError):
        return {"items": {}, "last_updated": None}


INGESTION_PROMPT_TEMPLATE = """You are an elite, clinical macroeconomic researcher and structural analyst. I am going to provide you with raw research data, articles, and notes regarding {topic}. Your sole task in this step is to ingest this information and extract the underlying structural mechanics, financial vehicles, regulatory loopholes, and corporate plays. Do not summarize this like a generic AI essay. Break down the data into concrete operational leverage points, explicit wealth extraction mechanisms, and institutional structures. Acknowledge your understanding by providing a highly technical index of the core data points you have extracted. Do not write the script yet."""


@app.route("/")
def index():
    status = load_status()
    return render_template("vault.html", initial_status=status)


@app.route("/api/status")
def api_status():
    return jsonify(load_status())


@app.route("/api/preview/<item_id>")
def api_preview(item_id):
    status = load_status()
    entry = status.get("items", {}).get(item_id)
    if not entry or not entry.get("curated_csv"):
        abort(404, "No curated file for this item yet.")

    csv_path = BASE_DIR / entry["curated_csv"]
    if not csv_path.exists():
        abort(404, "Curated file is missing on disk.")

    rows = []
    with open(csv_path, "r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        for i, row in enumerate(reader):
            if i >= 8:
                break
            rows.append(row)

    return jsonify({"rows": rows, "path": entry["curated_csv"]})


@app.route("/api/prompt/<item_id>")
def api_prompt(item_id):
    status = load_status()
    entry = status.get("items", {}).get(item_id)
    if not entry:
        abort(404, "Unknown item.")
    topic = entry.get("query", item_id)
    prompt = INGESTION_PROMPT_TEMPLATE.format(topic=topic)
    return jsonify({"prompt": prompt, "topic": topic})


if __name__ == "__main__":
    import os
    debug_mode = os.environ.get("FLASK_DEBUG", "0") == "1"
    app.run(debug=debug_mode, port=int(os.environ.get("VAULT_PORT", 5060)))
