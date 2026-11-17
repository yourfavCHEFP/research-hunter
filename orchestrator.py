"""
Orchestrator — the connective tissue between Research Hunter and the rest
of the pipeline.

Run this as a long-lived background process (leave it running in its own
terminal tab). It watches ./01_Raw_Research for new JSON files — the exact
files Research Hunter writes when you click "Save to 01_Raw_Research" —
and for each one:

  1. Waits for the file to finish writing (size-stability check)
  2. Loads it, drops entries with no title/url, de-duplicates by URL
  3. Writes a cleaned CSV + JSON into ./02_Curated_Data — the CSV is
     directly openable in DataVet Pro for further tabular exploration
  4. Updates status.json with counts and a lifecycle stage
  5. Archives the original raw file into 01_Raw_Research/_archive/ so it
     is never reprocessed

Place this file (and knowledge_vault.py, templates/vault.html) directly
inside your existing research-hunter/ folder, next to app.py — it expects
01_Raw_Research to be a sibling directory, exactly where Research Hunter
already writes to.

Usage:
    python3 orchestrator.py
"""
import json
import logging
import shutil
import time
from datetime import datetime, timezone
from pathlib import Path
from threading import Lock

import pandas as pd
from watchdog.events import FileSystemEventHandler
from watchdog.observers import Observer

BASE_DIR = Path(__file__).parent
RAW_DIR = BASE_DIR / "01_Raw_Research"
ARCHIVE_DIR = RAW_DIR / "_archive"
CURATED_DIR = BASE_DIR / "02_Curated_Data"
STATUS_FILE = BASE_DIR / "status.json"
LOG_FILE = BASE_DIR / "orchestrator.log"

STABILITY_CHECK_INTERVAL = 0.4  # seconds between size checks
STABILITY_CHECK_COUNT = 3        # consecutive unchanged reads before trusting the file is fully written

_status_lock = Lock()

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s orchestrator: %(message)s",
    handlers=[logging.FileHandler(LOG_FILE), logging.StreamHandler()],
)
log = logging.getLogger("orchestrator")


def ensure_dirs():
    for d in (RAW_DIR, ARCHIVE_DIR, CURATED_DIR):
        d.mkdir(parents=True, exist_ok=True)


def load_status():
    if not STATUS_FILE.exists():
        return {"items": {}, "last_updated": None}
    try:
        with open(STATUS_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        log.warning("status.json unreadable (%s) — starting fresh", exc)
        return {"items": {}, "last_updated": None}


def save_status(status):
    """Atomic write: write to a temp file then replace, so a concurrent
    reader (Knowledge Vault) never sees a half-written status.json."""
    status["last_updated"] = datetime.now(timezone.utc).isoformat()
    tmp_path = STATUS_FILE.with_suffix(".tmp")
    with open(tmp_path, "w", encoding="utf-8") as f:
        json.dump(status, f, indent=2, ensure_ascii=False)
    tmp_path.replace(STATUS_FILE)


def update_item(item_id, **fields):
    with _status_lock:
        status = load_status()
        entry = status["items"].setdefault(item_id, {})
        entry.update(fields)
        entry["updated_at"] = datetime.now(timezone.utc).isoformat()
        status["items"][item_id] = entry
        save_status(status)


def wait_for_stable_file(path: Path, timeout=15):
    """Poll file size until it stops changing, so we never read a
    partially-written file. Returns False if it never stabilizes."""
    last_size = -1
    stable_reads = 0
    start = time.time()
    while time.time() - start < timeout:
        if not path.exists():
            return False
        size = path.stat().st_size
        if size == last_size and size > 0:
            stable_reads += 1
            if stable_reads >= STABILITY_CHECK_COUNT:
                return True
        else:
            stable_reads = 0
        last_size = size
        time.sleep(STABILITY_CHECK_INTERVAL)
    return False


def process_file(path: Path):
    item_id = path.stem
    log.info("Processing %s", path.name)

    if not wait_for_stable_file(path):
        log.warning("Timed out waiting for %s to finish writing — skipping this pass", path.name)
        return

    try:
        with open(path, "r", encoding="utf-8") as f:
            raw = json.load(f)
    except (json.JSONDecodeError, OSError) as exc:
        log.error("Could not read %s: %s", path.name, exc)
        update_item(item_id, stage="error", error=str(exc), source_file=str(path.relative_to(BASE_DIR)))
        return

    query = raw.get("query", item_id)
    results = raw.get("results", [])
    raw_count = len(results)

    update_item(
        item_id,
        query=query,
        stage="cleaning",
        source_file=str(path.relative_to(BASE_DIR)),
        raw_count=raw_count,
        created_at=raw.get("saved_at", datetime.now(timezone.utc).isoformat()),
    )

    if raw_count == 0:
        log.warning("%s has zero results — archiving without curation", path.name)
        archive_file(path)
        update_item(item_id, stage="empty", curated_count=0, duplicates_removed=0)
        return

    df = pd.DataFrame(results)

    # Drop entries with no title or no url — not useful for scripting.
    for col in ("title", "url"):
        if col not in df.columns:
            df[col] = ""
    before_drop = len(df)
    df = df[df["title"].astype(str).str.strip() != ""]
    df = df[df["url"].astype(str).str.strip() != ""]
    dropped_incomplete = before_drop - len(df)

    # De-duplicate by URL (the most reliable unique key across sources).
    before_dedupe = len(df)
    df = df.drop_duplicates(subset=["url"])
    duplicates_removed = before_dedupe - len(df)

    curated_count = len(df)

    stem = item_id
    curated_csv_path = CURATED_DIR / f"{stem}.csv"
    curated_json_path = CURATED_DIR / f"{stem}.json"

    df.to_csv(curated_csv_path, index=False)
    with open(curated_json_path, "w", encoding="utf-8") as f:
        json.dump(
            {
                "query": query,
                "curated_at": datetime.now(timezone.utc).isoformat(),
                "raw_count": raw_count,
                "curated_count": curated_count,
                "dropped_incomplete": dropped_incomplete,
                "duplicates_removed": duplicates_removed,
                "results": df.to_dict("records"),
            },
            f,
            indent=2,
            ensure_ascii=False,
        )

    archive_file(path)

    update_item(
        item_id,
        stage="ready_for_scripting",
        curated_count=curated_count,
        dropped_incomplete=dropped_incomplete,
        duplicates_removed=duplicates_removed,
        curated_csv=str(curated_csv_path.relative_to(BASE_DIR)),
        curated_json=str(curated_json_path.relative_to(BASE_DIR)),
        error=None,
    )

    log.info(
        "Curated %s: %d raw -> %d curated (%d incomplete dropped, %d duplicates removed)",
        path.name, raw_count, curated_count, dropped_incomplete, duplicates_removed,
    )


def archive_file(path: Path):
    dest = ARCHIVE_DIR / path.name
    try:
        shutil.move(str(path), str(dest))
    except (shutil.Error, OSError) as exc:
        log.warning("Could not archive %s: %s", path.name, exc)


class RawResearchHandler(FileSystemEventHandler):
    def on_created(self, event):
        if event.is_directory:
            return
        path = Path(event.src_path)
        if path.suffix != ".json":
            return
        if ARCHIVE_DIR in path.parents:
            return
        process_file(path)


def initial_scan():
    """Catch any files that were saved while the Orchestrator wasn't running."""
    pending = sorted(RAW_DIR.glob("*.json"))
    if not pending:
        log.info("No pending files in 01_Raw_Research on startup.")
        return
    log.info("Found %d pending file(s) from before startup — processing now.", len(pending))
    for path in pending:
        process_file(path)


def main():
    ensure_dirs()
    if not STATUS_FILE.exists():
        save_status({"items": {}})

    log.info("Orchestrator starting. Watching %s", RAW_DIR)
    initial_scan()

    handler = RawResearchHandler()
    observer = Observer()
    observer.schedule(handler, str(RAW_DIR), recursive=False)
    observer.start()

    print(f"\nOrchestrator is running — watching {RAW_DIR}")
    print("Leave this running. Drop research from Research Hunter and it routes automatically.")
    print("Ctrl+C to stop.\n")

    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        log.info("Shutting down (Ctrl+C).")
        observer.stop()
    observer.join()


if __name__ == "__main__":
    main()
