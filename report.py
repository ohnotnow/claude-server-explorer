#!/usr/bin/env python3
"""
Fleet Security Dashboard & Server Detail Report Generator

Reads from the server-inventory SQLite database to produce self-contained
HTML reports via Jinja2 templates.

Usage:
    uv run report.py                          # Fleet dashboard
    uv run report.py --server elf             # Detailed single-server report
    uv run report.py -o custom-name.html      # Custom output filename
    uv run report.py --db /path/to/inventory.db  # Custom database path
"""

import argparse
import json
import sqlite3
import sys
from datetime import date, datetime
from pathlib import Path

from jinja2 import Environment, FileSystemLoader, select_autoescape

# ── Configuration ──────────────────────────────────────────

DB_DEFAULT = Path.home() / ".server-inventory" / "inventory.db"
TEMPLATE_DIR = Path(__file__).parent / "templates"

SEVERITIES = ["critical", "high", "medium", "low", "info"]
SEV = {
    "critical": {"color": "#D4351C", "bg": "#FDF3F1", "label": "Critical"},
    "high":     {"color": "#E87722", "bg": "#FEF5EC", "label": "High"},
    "medium":   {"color": "#C49200", "bg": "#FFF9E6", "label": "Medium"},
    "low":      {"color": "#005398", "bg": "#EDF4FA", "label": "Low"},
    "info":     {"color": "#558B2F", "bg": "#F1F8E9", "label": "Info"},
}


# ── Data Access ────────────────────────────────────────────

def connect(db_path: Path) -> sqlite3.Connection:
    if not db_path.exists():
        print(f"Database not found: {db_path}", file=sys.stderr)
        print("Run a server-explore or security-explore scan first.", file=sys.stderr)
        sys.exit(1)
    conn = sqlite3.connect(str(db_path))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.row_factory = sqlite3.Row
    return conn


def has_table(conn: sqlite3.Connection, name: str) -> bool:
    cur = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (name,)
    )
    return cur.fetchone() is not None


def query(conn, sql, params=()):
    return [dict(r) for r in conn.execute(sql, params).fetchall()]


def get_servers(conn):
    return query(conn, "SELECT * FROM servers ORDER BY hostname")


def get_findings(conn, hostname=None):
    if not has_table(conn, "findings"):
        return []
    order = """ORDER BY CASE severity
        WHEN 'critical' THEN 0 WHEN 'high' THEN 1
        WHEN 'medium' THEN 2 WHEN 'low' THEN 3 ELSE 4 END"""
    if hostname:
        return query(conn, f"SELECT * FROM findings WHERE hostname=? {order}", (hostname,))
    return query(conn, f"SELECT * FROM findings {order}")


def get_package_vulns(conn, hostname=None):
    if not has_table(conn, "package_vulns"):
        return []
    order = "ORDER BY on_kev DESC, epss_score DESC"
    if hostname:
        return query(conn, f"SELECT * FROM package_vulns WHERE hostname=? {order}", (hostname,))
    return query(conn, f"SELECT * FROM package_vulns {order}")


def get_config_checks(conn, hostname=None):
    if not has_table(conn, "config_checks"):
        return []
    order = """ORDER BY CASE result
        WHEN 'fail' THEN 0 WHEN 'warn' THEN 1
        WHEN 'skip' THEN 2 ELSE 3 END"""
    if hostname:
        return query(conn, f"SELECT * FROM config_checks WHERE hostname=? {order}", (hostname,))
    return query(conn, f"SELECT * FROM config_checks {order}")


def get_scans(conn, hostname=None):
    if not has_table(conn, "security_scans"):
        return []
    if hostname:
        return query(conn, "SELECT * FROM security_scans WHERE hostname=? ORDER BY scanned_at DESC", (hostname,))
    return query(conn, "SELECT * FROM security_scans ORDER BY scanned_at DESC")


def get_services(conn, hostname=None):
    if not has_table(conn, "services"):
        return []
    if hostname:
        return query(conn, "SELECT * FROM services WHERE hostname=?", (hostname,))
    return query(conn, "SELECT * FROM services")


def get_containers(conn, hostname=None):
    if not has_table(conn, "containers"):
        return []
    if hostname:
        return query(conn, "SELECT * FROM containers WHERE hostname=?", (hostname,))
    return query(conn, "SELECT * FROM containers")


def get_server_analysis(conn, hostname=None):
    if not has_table(conn, "server_analysis"):
        return {}
    if hostname:
        rows = query(conn, "SELECT * FROM server_analysis WHERE hostname=?", (hostname,))
        if rows:
            row = rows[0]
            row["recommendations"] = json.loads(row.get("recommendations") or "[]")
            row["security_recommendations"] = json.loads(row.get("security_recommendations") or "[]")
            return row
        return {}
    rows = query(conn, "SELECT * FROM server_analysis")
    result = {}
    for row in rows:
        row["recommendations"] = json.loads(row.get("recommendations") or "[]")
        row["security_recommendations"] = json.loads(row.get("security_recommendations") or "[]")
        result[row["hostname"]] = row
    return result


def get_fleet_analysis(conn):
    if not has_table(conn, "fleet_analysis"):
        return {}
    rows = query(conn, "SELECT * FROM fleet_analysis WHERE id=1")
    if rows:
        row = rows[0]
        row["recommendations"] = json.loads(row.get("recommendations") or "[]")
        return row
    return {}


# ── Calculations ───────────────────────────────────────────

def count_severity(findings: list) -> dict:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        s = f.get("severity", "info")
        if s in counts:
            counts[s] += 1
    return counts


def health_score(findings: list) -> int:
    weights = {"critical": 20, "high": 10, "medium": 3, "low": 1, "info": 0}
    counts = count_severity(findings)
    penalty = sum(counts[s] * weights[s] for s in SEVERITIES)
    return max(0, 100 - penalty)


def worst_severity(findings: list) -> str:
    counts = count_severity(findings)
    for s in SEVERITIES:
        if counts[s] > 0:
            return s
    return "info"


def score_colour(score) -> str:
    """Return a hex colour for a health score. Works as a Jinja2 filter too."""
    if isinstance(score, str):
        return "#666"
    if score >= 80:
        return SEV["info"]["color"]
    if score >= 60:
        return SEV["medium"]["color"]
    if score >= 40:
        return SEV["high"]["color"]
    return SEV["critical"]["color"]


def score_label(score: int) -> str:
    if score >= 90:
        return "Excellent"
    if score >= 80:
        return "Good"
    if score >= 60:
        return "Fair"
    if score >= 40:
        return "Needs work"
    if score >= 20:
        return "Poor"
    return "Critical"


def format_date(dt_str) -> str:
    if not dt_str:
        return "Unknown"
    try:
        dt = datetime.fromisoformat(str(dt_str).replace("Z", "+00:00"))
        return dt.strftime("%-d %b %Y")
    except (ValueError, AttributeError):
        return str(dt_str)


def epss_display(score) -> str:
    if score is None:
        return "—"
    return f"{score:.1%}"


def epss_class(score) -> str:
    if score is None:
        return "epss-low"
    if score >= 0.7:
        return "epss-high"
    if score >= 0.4:
        return "epss-med"
    return "epss-low"


def findings_by_host(all_findings: list) -> dict:
    grouped = {}
    for f in all_findings:
        grouped.setdefault(f["hostname"], []).append(f)
    return grouped


def fleet_stats(servers, all_findings):
    by_host = findings_by_host(all_findings)
    scores = {s["hostname"]: health_score(by_host.get(s["hostname"], [])) for s in servers}
    all_scores = list(scores.values()) or [100]
    return {
        "scores": scores,
        "avg": sum(all_scores) / len(all_scores),
        "best": max(all_scores),
        "worst": min(all_scores),
        "total": len(servers),
    }


# ── Jinja2 Setup ──────────────────────────────────────────

def create_env() -> Environment:
    env = Environment(
        loader=FileSystemLoader(str(TEMPLATE_DIR)),
        autoescape=select_autoescape(["html"]),
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["format_date"] = format_date
    env.filters["epss_display"] = epss_display
    env.filters["epss_class"] = epss_class
    env.filters["score_colour"] = score_colour
    env.globals["SEV"] = SEV
    env.globals["SEVERITIES"] = SEVERITIES
    return env


# ── Context Builders ──────────────────────────────────────

def build_fleet_context(conn) -> dict:
    servers = get_servers(conn)
    all_findings = get_findings(conn)
    all_analysis = get_server_analysis(conn)
    fleet = get_fleet_analysis(conn)
    by_host = findings_by_host(all_findings)
    now = date.today().strftime("%-d %B %Y")

    total_counts = count_severity(all_findings)
    fleet_sc = health_score(all_findings)
    healthy_count = sum(
        1 for s in servers
        if health_score(by_host.get(s["hostname"], [])) >= 80
    )

    # Build per-server card data
    server_data = []
    for srv in servers:
        h = srv["hostname"]
        srv_findings = by_host.get(h, [])
        srv_counts = count_severity(srv_findings)
        critical_high = [f for f in srv_findings if f.get("severity") in ("critical", "high")]

        # Build "other" summary for medium/low/info
        other_parts = []
        for s in ("medium", "low", "info"):
            c = srv_counts.get(s, 0)
            if c:
                other_parts.append(f"{c} {s}")

        srv_analysis = all_analysis.get(h, {})

        # Comma-separated list of severities this server has findings for
        severities_present = [s for s in SEVERITIES if srv_counts.get(s, 0) > 0]

        server_data.append({
            "hostname": h,
            "purpose": srv_analysis.get("purpose", ""),
            "os": srv.get("os_version") or srv.get("os") or "",
            "worst": worst_severity(srv_findings),
            "severities": ",".join(severities_present),
            "critical_high_findings": critical_high,
            "other_summary": " \u00b7 ".join(other_parts),
            "scanned": format_date(srv.get("last_scanned")),
        })

    # Fleet analysis paragraphs
    fleet_text = fleet.get("analysis", "")
    paragraphs = [p.strip() for p in fleet_text.strip().split("\n\n") if p.strip()] if fleet_text else []

    return {
        "title": "Fleet Security Report",
        "subtitle": "University of Glasgow \u00b7 College of Science and Engineering",
        "generated": now,
        "fleet_score": fleet_sc,
        "fleet_score_label": score_label(fleet_sc),
        "fleet_score_colour": score_colour(fleet_sc),
        "fleet_score_bg": SEV.get(
            "info" if fleet_sc >= 80 else "medium" if fleet_sc >= 60 else "high" if fleet_sc >= 40 else "critical",
            SEV["info"]
        )["bg"],
        "total_counts": total_counts,
        "healthy_count": healthy_count,
        "critical_findings": [f for f in all_findings if f.get("severity") == "critical"],
        "high_findings": [f for f in all_findings if f.get("severity") == "high"],
        "fleet_analysis_paragraphs": paragraphs,
        "fleet_recommendations": fleet.get("recommendations", []),
        "servers": server_data,
    }


def build_server_context(conn, hostname: str) -> dict:
    servers = get_servers(conn)
    srv = next((s for s in servers if s["hostname"] == hostname), None)

    if srv is None:
        print(f"Server '{hostname}' not found in database.", file=sys.stderr)
        available = [s["hostname"] for s in servers]
        if available:
            print(f"Available servers: {', '.join(available)}", file=sys.stderr)
        sys.exit(1)

    findings = get_findings(conn, hostname)
    vulns = get_package_vulns(conn, hostname)
    checks = get_config_checks(conn, hostname)
    scans = get_scans(conn, hostname)
    services = get_services(conn, hostname)
    containers = get_containers(conn, hostname)
    all_findings = get_findings(conn)
    srv_analysis = get_server_analysis(conn, hostname)

    counts = count_severity(findings)
    score = health_score(findings)
    now = date.today().strftime("%-d %B %Y")

    fstats = fleet_stats(servers, all_findings)
    rank_list = sorted(fstats["scores"].values(), reverse=True)
    rank = rank_list.index(score) + 1 if score in rank_list else "—"

    analysis_text = srv_analysis.get("analysis", "")
    paragraphs = [p.strip() for p in analysis_text.strip().split("\n\n") if p.strip()] if analysis_text else []

    # Config checks summary
    pass_count = sum(1 for c in checks if c.get("result") == "pass")
    fail_count = sum(1 for c in checks if c.get("result") == "fail")
    warn_count = sum(1 for c in checks if c.get("result") == "warn")
    summary_parts = []
    if pass_count:
        summary_parts.append(f"{pass_count} passed")
    if fail_count:
        summary_parts.append(f"{fail_count} failed")
    if warn_count:
        summary_parts.append(f"{warn_count} warnings")

    os_text = srv.get("os_version") or srv.get("os") or "Unknown"
    kernel = srv.get("kernel") or ""
    uptime = srv.get("uptime") or ""

    subtitle_parts = [os_text]
    if kernel:
        subtitle_parts.append(f"Kernel {kernel}")
    if uptime:
        subtitle_parts.append(f"Up {uptime}")

    return {
        "title": hostname,
        "subtitle": " \u00b7 ".join(subtitle_parts),
        "generated": now,
        "hostname": hostname,
        "score": score,
        "server_score_label": score_label(score),
        "server_score_colour": score_colour(score),
        "server_score_bg": SEV.get(
            "info" if score >= 80 else "medium" if score >= 60 else "high" if score >= 40 else "critical",
            SEV["info"]
        )["bg"],
        "counts": counts,
        "fleet": fstats,
        "rank": rank,
        "findings": findings,
        "vulns": vulns,
        "kev_count": sum(1 for v in vulns if v.get("on_kev")),
        "checks": checks,
        "checks_summary": " \u00b7 ".join(summary_parts),
        "scans": scans,
        "services": services,
        "containers": containers,
        "server_analysis_paragraphs": paragraphs,
        "server_recommendations": srv_analysis.get("recommendations", []),
        "security_analysis_paragraphs": [p.strip() for p in (srv_analysis.get("security_analysis") or "").strip().split("\n\n") if p.strip()],
        "security_recommendations": srv_analysis.get("security_recommendations", []),
    }


# ── CLI ────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Generate fleet security dashboards and server detail reports.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""examples:
  uv run report.py                     Fleet dashboard
  uv run report.py --server magicelf   Detailed report for a server
  uv run report.py -o report.html      Custom output filename
  uv run report.py --db /tmp/inv.db    Custom database path""",
    )
    parser.add_argument("--server", "-s", help="Generate a detailed report for a specific server")
    parser.add_argument("--db", type=Path, default=DB_DEFAULT, help=f"Path to inventory database (default: {DB_DEFAULT})")
    parser.add_argument("-o", "--output", help="Output filename (default: auto-generated)")
    args = parser.parse_args()

    conn = connect(args.db)
    env = create_env()
    today = date.today().isoformat()

    if args.server:
        ctx = build_server_context(conn, args.server)
        html = env.get_template("server.html").render(**ctx)
        default_name = f"server-report-{args.server}-{today}.html"
    else:
        ctx = build_fleet_context(conn)
        html = env.get_template("fleet.html").render(**ctx)
        default_name = f"fleet-report-{today}.html"

    output_path = Path(args.output) if args.output else Path(default_name)
    output_path.write_text(html)
    print(f"Report written to {output_path}")
    conn.close()


if __name__ == "__main__":
    main()
