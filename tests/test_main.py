import sqlite3
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import conn_security
import main


CREATE_CONNECTIONS = """
CREATE TABLE connections (
    captured_at TEXT NOT NULL,
    id          TEXT NOT NULL,
    protocol    TEXT,
    src_addr    TEXT,
    src_port    INTEGER,
    dst_addr    TEXT,
    dst_port    INTEGER,
    tcp_state   TEXT,
    seen_reply  INTEGER,
    orig_bytes  INTEGER,
    repl_bytes  INTEGER,
    packets     INTEGER,
    timeout_s   INTEGER,
    srcnat      INTEGER,
    dying       INTEGER,
    PRIMARY KEY (captured_at, id)
)
"""


def _seed_db(db_path: Path, rows: list[tuple]) -> None:
    con = sqlite3.connect(db_path)
    con.execute(CREATE_CONNECTIONS)
    con.executemany(
        "INSERT INTO connections VALUES "
        "(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
        rows,
    )
    con.commit()
    con.close()


@pytest.fixture
def client(tmp_path, monkeypatch):
    data = tmp_path / "data"
    data.mkdir()
    monkeypatch.setattr(main, "DATA_DIR", data)
    monkeypatch.setattr(main, "CONNECTIONS_DB", data / "connections.db")
    return TestClient(main.app)


class TestExtractSections:
    def test_keeps_only_requested_sections(self):
        md = """# Title

## Verdict: HEALTHY
ok

## Host
host body

## Ghost routes
ghost body

## Interfaces
if body
"""
        out = main.extract_sections(md, ["verdict", "host", "interfaces"])
        assert "## Verdict" in out
        assert "## Host" in out
        assert "## Interfaces" in out
        assert "Ghost" not in out

    def test_verdict_heading_with_colon(self):
        md = "## Verdict: FINDINGS\ncontent\n## Host\nh\n"
        out = main.extract_sections(md, ["verdict"])
        assert "## Verdict: FINDINGS" in out
        assert "## Host" not in out

    def test_includes_preamble(self):
        md = "# Report\n\n_preamble_\n\n## Host\nh\n"
        out = main.extract_sections(md, ["host"])
        assert "# Report" in out
        assert "_preamble_" in out


class TestLatestReport:
    def test_picks_newest_by_mtime(self, tmp_path, monkeypatch):
        monkeypatch.setattr(main, "DATA_DIR", tmp_path)
        old = tmp_path / "mikrotik-health-check-2026-01-01.md"
        new = tmp_path / "mikrotik-health-check-2026-12-31.md"
        old.write_text("old", encoding="utf-8")
        new.write_text("new", encoding="utf-8")
        old.touch()
        new.touch()
        # Make old file newer on disk despite older date in name
        import os
        import time

        now = time.time()
        os.utime(old, (now + 10, now + 10))
        os.utime(new, (now, now))

        assert main.latest_report("mikrotik-health-check") == "old"


class TestConnectionsApi:
    def test_missing_db_returns_empty_payload(self, client):
        r = client.get("/api/connections")
        assert r.status_code == 200
        assert r.json() == main._EMPTY_CONNECTIONS

    def test_empty_db_returns_empty_payload(self, client):
        db = main.CONNECTIONS_DB
        con = sqlite3.connect(db)
        con.execute(CREATE_CONNECTIONS)
        con.commit()
        con.close()

        r = client.get("/api/connections")
        assert r.status_code == 200
        assert r.json() == main._EMPTY_CONNECTIONS

    def test_populated_db(self, client):
        ts = "2026-01-01T00:00:00+00:00"
        _seed_db(main.CONNECTIONS_DB, [
            (ts, "1", "tcp", "10.1.1.10", 1234, "8.8.8.8", 443,
             "established", 1, 100, 200, 1, 60, 1, 0),
        ])

        r = client.get("/api/connections")
        data = r.json()
        assert data["captured_at"] == ts
        assert len(data["top_src"]) == 1
        assert data["top_src"][0]["src_addr"] == "10.1.1.10"
        assert data["verdict"] == "NO FINDINGS"
        assert data["total_conns"] == 1
        assert "rules" in data
        assert data["rules"]["R1"]["status"] == "ok"

    def test_r1_finding(self, client):
        ts = "2026-01-01T00:00:00+00:00"
        rows = []
        for i in range(5):
            rows.append((
                ts, str(i), "tcp", "10.1.1.99", 4000 + i, "203.0.113.1", 443,
                "syn-sent", 0, 0, 0, 1, 60, 1, 0,
            ))
        _seed_db(main.CONNECTIONS_DB, rows)

        r = client.get("/api/connections")
        data = r.json()
        assert data["rules"]["R1"]["status"] == "finding"
        assert data["verdict"] == "FINDINGS"
        assert len(data["rules"]["R1"]["findings"]) == 1
        assert data["rules"]["R1"]["findings"][0]["src"] == "10.1.1.99"
        assert data["syn_sent_no_reply"][0]["count"] == 5

    def test_security_payload_shape(self, client):
        ts = "2026-01-01T00:00:00+00:00"
        _seed_db(main.CONNECTIONS_DB, [
            (ts, "1", "tcp", "10.1.1.10", 1234, "8.8.8.8", 443,
             "established", 1, 100, 200, 1, 60, 1, 0),
        ])
        data = client.get("/api/connections").json()
        for key in (
            "verdict", "total_conns", "baseline_conns", "baseline_ratio",
            "rules", "watch", "syn_sent_no_reply",
        ):
            assert key in data
        for rule_id in ("R1", "R2", "R3", "R5", "R6"):
            assert rule_id in data["rules"]
            assert "status" in data["rules"][rule_id]


class TestReportApi:
    def test_mikrotik_404_when_missing(self, client):
        assert client.get("/api/mikrotik").status_code == 404

    def test_mikrotik_summary(self, client, monkeypatch):
        path = main.DATA_DIR / "mikrotik-health-check-test.md"
        path.write_text(
            "# MikroTik\n\n## Verdict: HEALTHY\nok\n## Host\nh\n## Routes\nr\n",
            encoding="utf-8",
        )
        # Touch as newest
        import os
        import time

        now = time.time()
        os.utime(path, (now + 10, now + 10))

        r = client.get("/api/mikrotik")
        assert r.status_code == 200
        summary = r.json()["summary"]
        assert "## Verdict" in summary
        assert "## Host" in summary
        assert "## Routes" not in summary

    def test_conn_analysis_404_when_missing(self, client):
        assert client.get("/api/conn-analysis").status_code == 404

    def test_conn_analysis_summary(self, client):
        path = main.DATA_DIR / "mikrotik-conn-analysis-test.md"
        path.write_text(
            "# Conn analysis\n\n## Verdict: NO FINDINGS\nok\n"
            "## Methodology\nrules\n## Caveats\ncaveats\n",
            encoding="utf-8",
        )
        import os
        import time

        now = time.time()
        os.utime(path, (now + 10, now + 10))

        r = client.get("/api/conn-analysis")
        assert r.status_code == 200
        summary = r.json()["summary"]
        assert "## Verdict" in summary
        assert "## Methodology" in summary
        assert "Caveats" not in summary

    def test_conn_analysis_md_verdict_overrides_computed(self, client):
        ts = "2026-01-01T00:00:00+00:00"
        rows = []
        for i in range(5):
            rows.append((
                ts, str(i), "tcp", "10.1.1.99", 4000 + i, "203.0.113.1", 443,
                "syn-sent", 0, 0, 0, 1, 60, 1, 0,
            ))
        _seed_db(main.CONNECTIONS_DB, rows)

        path = main.DATA_DIR / "mikrotik-conn-analysis-test.md"
        path.write_text("## Verdict: NO FINDINGS 🟢\n", encoding="utf-8")
        import os
        import time

        now = time.time()
        os.utime(path, (now + 10, now + 10))

        data = client.get("/api/connections").json()
        assert data["rules"]["R1"]["status"] == "finding"
        assert "NO FINDINGS" in data["verdict"]


class TestConnSecurity:
    def test_compute_verdict(self):
        rules = {"R1": {"status": "ok"}, "R2": {"status": "finding"}}
        assert conn_security.compute_verdict(rules) == "FINDINGS"
        rules["R2"]["status"] = "ok"
        assert conn_security.compute_verdict(rules) == "NO FINDINGS"
