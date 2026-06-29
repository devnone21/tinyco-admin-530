"""
Admin dashboard backend.
- Reads MikroTik and PVE .md reports from DATA_DIR
- Queries connections.db for firewall snapshots
- Serves dashboard.html as root

Run (local only):  uvicorn main:app --host 127.0.0.1 --port 8000
Run (LAN):         uvicorn main:app --host 0.0.0.0 --port 8000
                   — no auth; put a reverse proxy in front if exposed beyond trusted LAN
"""

import re
import sqlite3
import glob
import os
from pathlib import Path
from fastapi import FastAPI, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles

# ── config ──────────────────────────────────────────────────────────────────
DATA_DIR = Path(os.getenv("DATA_DIR", "./data"))
CONNECTIONS_DB = Path(os.getenv("CONNECTIONS_DB", DATA_DIR / "connections.db"))
HTML_FILE = Path(__file__).parent / "dashboard.html"

app = FastAPI()

STATIC_DIR = Path(__file__).parent / "static"
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# ── helpers ─────────────────────────────────────────────────────────────────
def latest_report(prefix: str) -> str | None:
    pattern = str(DATA_DIR / f"{prefix}-*.md")
    files = sorted(glob.glob(pattern), reverse=True)
    if not files:
        return None
    return Path(files[0]).read_text(encoding="utf-8")


def extract_sections(md: str, keep: list[str]) -> str:
    """
    Return preamble (title + verdict) plus only the H2 sections in `keep`.
    ponytail: regex split on ## — no markdown lib needed.
    """
    # preamble = everything before first ##
    preamble = re.split(r"^## ", md, maxsplit=1, flags=re.MULTILINE)[0]

    chunks = re.split(r"^(## .+)$", md, flags=re.MULTILINE)
    sections = []
    for i in range(1, len(chunks) - 1, 2):
        heading = chunks[i]
        body    = chunks[i + 1]
        if any(k.lower() in heading.lower() for k in keep):
            sections.append(heading + body)

    return preamble + "\n".join(sections)


def db_query(sql: str, params: tuple = ()) -> list[dict]:
    if not CONNECTIONS_DB.exists():
        raise HTTPException(404, f"connections.db not found at {CONNECTIONS_DB}")
    con = sqlite3.connect(f"file:{CONNECTIONS_DB}?mode=ro", uri=True)
    con.row_factory = sqlite3.Row
    try:
        cur = con.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]
    finally:
        con.close()


# ── routes ───────────────────────────────────────────────────────────────────
@app.get("/", response_class=HTMLResponse)
def root():
    return HTML_FILE.read_text(encoding="utf-8")


@app.get("/favicon.ico", include_in_schema=False)
def favicon():
    return RedirectResponse(url="/static/icon-192.png")


@app.get("/api/mikrotik")
def mikrotik(full: bool = False):
    md = latest_report("mikrotik-health-check")
    if not md:
        raise HTTPException(404, "No MikroTik report found")
    summary = extract_sections(md, ["verdict", "host", "interfaces"])
    out = {"summary": summary}
    if full:
        out["full"] = md
    return out


@app.get("/api/proxmox")
def proxmox(full: bool = False):
    md = latest_report("pve-health-check")
    if not md:
        raise HTTPException(404, "No Proxmox report found")
    summary = extract_sections(md, ["verdict", "host", "guests", "storage"])
    out = {"summary": summary}
    if full:
        out["full"] = md
    return out


@app.get("/api/connections")
def connections():
    latest = db_query(
        "SELECT captured_at FROM connections ORDER BY captured_at DESC LIMIT 1"
    )
    if not latest:
        return {"captured_at": None, "top_src": [], "protocols": [], "tcp_states": []}

    ts = latest[0]["captured_at"]

    top_src = db_query("""
        SELECT src_addr,
               SUM(orig_bytes + repl_bytes) AS total_bytes,
               COUNT(*) AS conns
        FROM connections
        WHERE captured_at = ?
        GROUP BY src_addr
        ORDER BY total_bytes DESC
        LIMIT 10
    """, (ts,))

    protocols = db_query("""
        SELECT protocol, COUNT(*) AS cnt
        FROM connections
        WHERE captured_at = ?
        GROUP BY protocol
        ORDER BY cnt DESC
    """, (ts,))

    tcp_states = db_query("""
        SELECT tcp_state, COUNT(*) AS cnt
        FROM connections
        WHERE captured_at = ? AND protocol = 'tcp'
        GROUP BY tcp_state
        ORDER BY cnt DESC
    """, (ts,))

    return {
        "captured_at": ts,
        "top_src": top_src,
        "protocols": protocols,
        "tcp_states": tcp_states,
    }
