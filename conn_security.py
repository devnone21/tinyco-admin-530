"""
Security heuristics for MikroTik connection snapshots (v1 pure-local).

Rules mirror mikrotik-conn-analysis methodology (R1, R2, R3, R5, R6).
"""

from __future__ import annotations

from collections import defaultdict
from typing import Callable

QueryFn = Callable[[str, tuple], list[dict]]

# Internal LAN prefixes (from conn-analysis v1)
INTERNAL_PREFIXES = ("10.1.1.", "10.2.2.", "192.168.1.")

# R2 suspicious outbound ports
SUSPICIOUS_PORTS = frozenset({
    4444, 5555, 8080, 8333, 9001, 9030, 9150, 31337, 50050,
    *range(6660, 6670),
    *range(6881, 6890),
})

# R3 — extensible; empty until blocklist is added
MINING_POOL_IPS: frozenset[str] = frozenset()
MINING_POOL_HOSTS: frozenset[str] = frozenset()

# Well-known ports excluded from watch-list noise
WELL_KNOWN_PORTS = frozenset({
    53, 80, 123, 443, 853, 993, 995, 1883, 1884,
    3478, 5222, 5223, 5228, 5229, 7844,
})

R1_THRESHOLD = 5
R5_DISTINCT_IP_THRESHOLD = 100
R5_SYN_SENT_THRESHOLD = 3
R6_RATIO_THRESHOLD = 4.0
WATCH_BYTES_THRESHOLD = 10 * 1024 * 1024  # 10 MB


def is_internal(ip: str | None) -> bool:
    if not ip:
        return False
    return any(ip.startswith(p) for p in INTERNAL_PREFIXES)


def is_outbound(src: str | None, dst: str | None) -> bool:
    return is_internal(src) and not is_internal(dst)


def _rule_status(triggered: bool) -> str:
    return "finding" if triggered else "ok"


def _baseline(query: QueryFn) -> tuple[str | None, int]:
    rows = query(
        "SELECT captured_at, COUNT(*) AS cnt FROM connections "
        "GROUP BY captured_at ORDER BY captured_at ASC LIMIT 1",
        (),
    )
    if not rows:
        return None, 0
    return rows[0]["captured_at"], rows[0]["cnt"]


def _rows_for_snapshot(query: QueryFn, captured_at: str) -> list[dict]:
    return query("SELECT * FROM connections WHERE captured_at = ?", (captured_at,))


def _check_r1(rows: list[dict]) -> dict:
    counts: dict[str, int] = defaultdict(int)
    for r in rows:
        if (
            is_outbound(r.get("src_addr"), r.get("dst_addr"))
            and r.get("tcp_state") == "syn-sent"
            and r.get("seen_reply") == 0
        ):
            counts[r["src_addr"]] += 1

    worst_src, worst_cnt = None, 0
    findings = []
    for src, cnt in counts.items():
        if cnt > worst_cnt:
            worst_src, worst_cnt = src, cnt
        if cnt >= R1_THRESHOLD:
            findings.append({"src": src, "count": cnt})

    triggered = bool(findings)
    return {
        "status": _rule_status(triggered),
        "threshold": R1_THRESHOLD,
        "worst": {"src": worst_src, "count": worst_cnt, "threshold": R1_THRESHOLD},
        "findings": findings,
    }


def _check_r2(rows: list[dict]) -> dict:
    hits = []
    for r in rows:
        port = r.get("dst_port")
        if port is None or port not in SUSPICIOUS_PORTS:
            continue
        if is_outbound(r.get("src_addr"), r.get("dst_addr")):
            hits.append({
                "src": r.get("src_addr"),
                "dst": r.get("dst_addr"),
                "dst_port": port,
            })

    return {
        "status": _rule_status(bool(hits)),
        "hits": hits[:20],
        "hit_count": len(hits),
    }


def _check_r3(rows: list[dict]) -> dict:
    hits = []
    for r in rows:
        if not is_outbound(r.get("src_addr"), r.get("dst_addr")):
            continue
        dst = r.get("dst_addr") or ""
        if dst in MINING_POOL_IPS or dst in MINING_POOL_HOSTS:
            hits.append({"src": r.get("src_addr"), "dst": dst, "dst_port": r.get("dst_port")})

    return {
        "status": _rule_status(bool(hits)),
        "hits": hits[:20],
        "hit_count": len(hits),
    }


def _check_r5(rows: list[dict]) -> dict:
  # Per internal src + dst_port: distinct external dst IPs, and syn-sent w/o reply count
    distinct: dict[tuple[str, int], set[str]] = defaultdict(set)
    syn_no_reply: dict[tuple[str, int], set[str]] = defaultdict(set)

    for r in rows:
        src, dst, port = r.get("src_addr"), r.get("dst_addr"), r.get("dst_port")
        if not is_outbound(src, dst) or port is None:
            continue
        key = (src, port)
        distinct[key].add(dst)
        if r.get("tcp_state") == "syn-sent" and r.get("seen_reply") == 0:
            syn_no_reply[key].add(dst)

    findings = []
    worst = {"src": None, "dst_port": None, "distinct_ips": 0, "syn_no_reply": 0}
    for key, ips in distinct.items():
        src, port = key
        syn_cnt = len(syn_no_reply.get(key, set()))
        ip_cnt = len(ips)
        if ip_cnt > worst["distinct_ips"]:
            worst = {
                "src": src,
                "dst_port": port,
                "distinct_ips": ip_cnt,
                "syn_no_reply": syn_cnt,
            }
        if ip_cnt >= R5_DISTINCT_IP_THRESHOLD and syn_cnt >= R5_SYN_SENT_THRESHOLD:
            findings.append({
                "src": src,
                "dst_port": port,
                "distinct_ips": ip_cnt,
                "syn_no_reply": syn_cnt,
            })

    return {
        "status": _rule_status(bool(findings)),
        "threshold_distinct_ips": R5_DISTINCT_IP_THRESHOLD,
        "threshold_syn_no_reply": R5_SYN_SENT_THRESHOLD,
        "worst": worst,
        "findings": findings,
    }


def _check_r6(total_conns: int, baseline_conns: int) -> dict:
    ratio = round(total_conns / baseline_conns, 2) if baseline_conns else 0.0
    triggered = baseline_conns > 0 and ratio >= R6_RATIO_THRESHOLD
    return {
        "status": _rule_status(triggered),
        "ratio": ratio,
        "threshold": R6_RATIO_THRESHOLD,
        "total_conns": total_conns,
        "baseline_conns": baseline_conns,
    }


def _syn_sent_no_reply(rows: list[dict]) -> list[dict]:
    counts: dict[str, int] = defaultdict(int)
    for r in rows:
        if (
            is_outbound(r.get("src_addr"), r.get("dst_addr"))
            and r.get("tcp_state") == "syn-sent"
            and r.get("seen_reply") == 0
        ):
            counts[r["src_addr"]] += 1
    return [
        {"src_addr": src, "count": cnt}
        for src, cnt in sorted(counts.items(), key=lambda x: -x[1])
    ]


def _watch_list(rows: list[dict]) -> list[dict]:
    items = []
    for r in rows:
        if not is_outbound(r.get("src_addr"), r.get("dst_addr")):
            continue
        port = r.get("dst_port")
        total_bytes = (r.get("orig_bytes") or 0) + (r.get("repl_bytes") or 0)
        if port is None or port in WELL_KNOWN_PORTS or port in SUSPICIOUS_PORTS:
            continue
        if total_bytes < WATCH_BYTES_THRESHOLD:
            continue
        items.append({
            "severity": "info",
            "msg": f"High traffic on non-standard port {port}",
            "src": r.get("src_addr"),
            "dst": r.get("dst_addr"),
            "dst_port": port,
            "bytes": total_bytes,
        })

    items.sort(key=lambda x: x["bytes"], reverse=True)
    return items[:10]


def compute_verdict(rules: dict) -> str:
    if any(r.get("status") == "finding" for r in rules.values()):
        return "FINDINGS"
    return "NO FINDINGS"


def analyze_security(query: QueryFn, captured_at: str) -> dict:
    """Run all v1 security rules against a single snapshot."""
    rows = _rows_for_snapshot(query, captured_at)
    total_conns = len(rows)
    _, baseline_conns = _baseline(query)

    rules = {
        "R1": _check_r1(rows),
        "R2": _check_r2(rows),
        "R3": _check_r3(rows),
        "R5": _check_r5(rows),
        "R6": _check_r6(total_conns, baseline_conns),
    }

    baseline_ratio = (
        round(total_conns / baseline_conns, 2) if baseline_conns else None
    )

    return {
        "verdict": compute_verdict(rules),
        "total_conns": total_conns,
        "baseline_conns": baseline_conns,
        "baseline_ratio": baseline_ratio,
        "rules": rules,
        "watch": _watch_list(rows),
        "syn_sent_no_reply": _syn_sent_no_reply(rows),
    }
