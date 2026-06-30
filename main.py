"""
Admin dashboard backend.
- Reads MikroTik and PVE .md reports from DATA_DIR
- Queries connections.db for firewall snapshots
- Serves dashboard.html as root

Run (local only):  uvicorn main:app --host 127.0.0.1 --port 6008
Run (LAN):         uvicorn main:app --host 0.0.0.0 --port 6008
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

from conn_security import analyze_security

# ── config ──────────────────────────────────────────────────────────────────
DATA_DIR = Path(os.getenv("DATA_DIR") or "./data")
CONNECTIONS_DB = Path(os.getenv("CONNECTIONS_DB") or DATA_DIR / "connections.db")
HTML_FILE = Path(__file__).parent / "dashboard.html"

app = FastAPI()

STATIC_DIR = Path(__file__).parent / "static"
if not STATIC_DIR.is_dir():
    raise RuntimeError(f"static directory not found at {STATIC_DIR}")
app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


# ── helpers ─────────────────────────────────────────────────────────────────
def latest_report(prefix: str) -> str | None:
    pattern = str(DATA_DIR / f"{prefix}-*.md")
    files = glob.glob(pattern)
    if not files:
        return None
    latest = max(files, key=lambda p: Path(p).stat().st_mtime)
    return Path(latest).read_text(encoding="utf-8")


def _section_key(heading: str) -> str:
    """First word of an H2 heading, lowercased (e.g. '## Verdict: OK' -> 'verdict')."""
    m = re.match(r"^##\s+(\w+)", heading)
    return m.group(1).lower() if m else ""


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
        key = _section_key(heading)
        if key in {k.lower() for k in keep}:
            sections.append(heading + body)

    return preamble + "\n".join(sections)


def db_query(sql: str, params: tuple = ()) -> list[dict]:
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


@app.get("/api/conn-analysis")
def conn_analysis(full: bool = False):
    md = latest_report("mikrotik-conn-analysis")
    if not md:
        raise HTTPException(404, "No connection analysis report found")
    summary = extract_sections(md, ["verdict", "methodology"])
    out = {"summary": summary}
    if full:
        out["full"] = md
    return out


def _verdict_from_md(md: str | None) -> str | None:
    if not md:
        return None
    m = re.search(r"^## Verdict:\s*(.+)$", md, re.MULTILINE)
    return m.group(1).strip() if m else None


_EMPTY_CONNECTIONS = {
    "captured_at": None,
    "verdict": None,
    "total_conns": 0,
    "baseline_conns": 0,
    "baseline_ratio": None,
    "rules": {},
    "watch": [],
    "syn_sent_no_reply": [],
    "top_src": [],
    "protocols": [],
    "tcp_states": [],
}


@app.get("/api/connections")
def connections():
    if not CONNECTIONS_DB.exists():
        return _EMPTY_CONNECTIONS

    latest = db_query(
        "SELECT captured_at FROM connections ORDER BY captured_at DESC LIMIT 1"
    )
    if not latest:
        return _EMPTY_CONNECTIONS

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

    security = analyze_security(db_query, ts)
    md_verdict = _verdict_from_md(latest_report("mikrotik-conn-analysis"))
    if md_verdict:
        security["verdict"] = md_verdict

    return {
        "captured_at": ts,
        "top_src": top_src,
        "protocols": protocols,
        "tcp_states": tcp_states,
        **security,
    }
