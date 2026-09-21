"""
detect.py - run detection rules against the honeypot database.

Reads honeypot.db (built by load_db.py), applies five rules, prints the
alerts it finds, and writes them to alerts.json.

Usage:
    python detect.py                    # all rules, default thresholds
    python detect.py --min-severity high
    python detect.py --db other.db --out other_alerts.json
"""

import argparse
import hashlib
import json
import sqlite3
import sys
from datetime import datetime, timezone

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# Commands that mean the session went past looking around: pulling a file
# down, making it runnable, or hiding what it is doing.
PAYLOAD_MARKERS = [
    "wget", "curl", "tftp", "scp ", "chmod +x", "base64 -d",
    "nohup", "/dev/tcp/", "crontab",
]


def rule_brute_force(conn, attempts, minutes):
    """One host making a lot of attempts inside one time window.

    Cowrie timestamps look like 2026-09-08T05:12:33.123456Z, so cutting
    the string at 15 characters leaves 2026-09-08T05:1, which buckets
    events into 10 minute blocks without any date parsing.

    A host that sustains a burst for hours produces one alert, not one
    per window. The window count is kept as evidence, since a host that
    bursts for two hours matters more than one that bursts once.
    """
    rows = conn.execute("""
        SELECT src_ip,
               COUNT(*) AS windows,
               MAX(attempts) AS peak,
               SUM(attempts) AS total,
               MIN(window) AS first_window,
               MAX(window) AS last_window
        FROM (
            SELECT src_ip, substr(timestamp, 1, 15) AS window,
                   COUNT(*) AS attempts
            FROM logins
            GROUP BY src_ip, window
            HAVING attempts >= ?
        )
        GROUP BY src_ip
        ORDER BY total DESC
    """, (attempts,)).fetchall()

    alerts = []
    for r in rows:
        sustained = r["windows"] >= 3
        if r["windows"] == 1:
            detail = f"{r['total']} attempts in a single {minutes} minute window"
        else:
            detail = (f"{r['total']} attempts across {r['windows']} "
                      f"{minutes} minute windows, peaking at {r['peak']}")
        alerts.append({
            "rule": "brute_force_burst",
            "severity": "high" if (sustained or r["peak"] >= attempts * 5) else "medium",
            "src_ip": r["src_ip"],
            "detail": detail,
            "evidence": {"windows": r["windows"], "peak": r["peak"],
                         "total": r["total"],
                         "first_window": r["first_window"] + "0",
                         "last_window": r["last_window"] + "0"},
        })
    return alerts


def rule_password_spray(conn, min_users, max_per_user):
    """Many usernames, few passwords each.

    The opposite shape to brute force. Spraying stays under lockout
    thresholds by trying one or two passwords against a long user list.
    """
    rows = conn.execute("""
        SELECT src_ip,
               COUNT(DISTINCT username) AS users,
               COUNT(*) AS attempts,
               COUNT(*) * 1.0 / COUNT(DISTINCT username) AS per_user
        FROM logins
        GROUP BY src_ip
        HAVING users >= ? AND per_user <= ?
        ORDER BY users DESC
    """, (min_users, max_per_user)).fetchall()

    return [{
        "rule": "password_spray",
        "severity": "medium",
        "src_ip": r["src_ip"],
        "detail": (f"{r['users']} distinct usernames, "
                   f"{r['per_user']:.1f} attempts per username"),
        "evidence": {"usernames": r["users"], "attempts": r["attempts"]},
    } for r in rows]


def rule_shared_credentials(conn, min_hosts):
    """The same username and password pair tried by several hosts.

    Unrelated attackers do not land on the same pair by chance. Reuse
    across hosts means one list handed to many machines.

    This fires once with the worst offenders attached, rather than once
    per pair. A rule that produces hundreds of near-identical alerts
    trains people to ignore it.
    """
    rows = conn.execute("""
        SELECT username, password,
               COUNT(DISTINCT src_ip) AS hosts,
               COUNT(*) AS attempts
        FROM logins
        GROUP BY username, password
        HAVING hosts >= ?
        ORDER BY hosts DESC, attempts DESC
    """, (min_hosts,)).fetchall()

    if not rows:
        return []

    top = [{"username": r["username"], "password": r["password"],
            "hosts": r["hosts"], "attempts": r["attempts"]} for r in rows[:10]]
    worst = top[0]

    return [{
        "rule": "shared_credential_list",
        "severity": "low",
        "src_ip": None,
        "detail": (f"{len(rows)} credential pairs were each tried by "
                   f"{min_hosts} or more hosts; the most shared was "
                   f"{worst['username']} / {worst['password']} across "
                   f"{worst['hosts']} hosts"),
        "evidence": {"pairs_shared": len(rows), "top_pairs": top},
    }]


def rule_coordinated_network(conn, min_hosts, min_attempts):
    """Several hosts in one /24 attacking together.

    Per-IP blocking treats this as many separate problems. Grouping by
    network shows it is one operation and can be blocked as one.
    """
    rows = conn.execute("""
        SELECT rtrim(src_ip, '0123456789') || '0/24' AS network,
               COUNT(DISTINCT src_ip) AS hosts,
               COUNT(*) AS attempts
        FROM logins
        GROUP BY network
        HAVING hosts >= ? AND attempts >= ?
        ORDER BY attempts DESC
    """, (min_hosts, min_attempts)).fetchall()

    return [{
        "rule": "coordinated_network",
        "severity": "high",
        "src_ip": None,
        "detail": (f"{r['hosts']} hosts in {r['network']} made "
                   f"{r['attempts']} attempts between them"),
        "evidence": {"network": r["network"], "hosts": r["hosts"],
                     "attempts": r["attempts"]},
    } for r in rows]


def rule_payload_activity(conn):
    """A session that did something after getting in.

    Most sessions only fingerprint. Downloading or running a file is the
    point where a real compromise would have started, so these are the
    alerts worth waking someone for.

    Sessions are grouped by what they actually ran. Hundreds of sessions
    replaying byte-for-byte the same script are one campaign, not
    hundreds of incidents, so they produce one alert carrying the session
    and host counts. Alert fatigue is its own failure: a rule nobody can
    read is a rule nobody acts on.
    """
    where = " OR ".join("command LIKE ?" for _ in PAYLOAD_MARKERS)
    params = ["%" + m + "%" for m in PAYLOAD_MARKERS]
    rows = conn.execute(f"""
        SELECT session, src_ip, command
        FROM commands
        WHERE {where}
    """, params).fetchall()

    # First pass: what did each session run?
    sessions = {}
    for r in rows:
        entry = sessions.setdefault(
            r["session"], {"src_ip": r["src_ip"], "commands": set()})
        entry["commands"].add(r["command"])

    # Second pass: group sessions that ran exactly the same thing. The
    # signature is a hash of the commands, so two sessions match only if
    # their payloads are identical.
    campaigns = {}
    for session, entry in sessions.items():
        commands = tuple(sorted(entry["commands"]))
        signature = hashlib.sha1("\n".join(commands).encode()).hexdigest()[:12]
        camp = campaigns.setdefault(signature, {
            "commands": commands, "sessions": 0, "hosts": set()})
        camp["sessions"] += 1
        camp["hosts"].add(entry["src_ip"])

    alerts = []
    for signature, camp in campaigns.items():
        markers = sorted({m.strip() for c in camp["commands"]
                          for m in PAYLOAD_MARKERS if m in c})
        longest = max(camp["commands"], key=len)
        sample = longest if len(longest) <= 120 else longest[:117] + "..."
        hosts = sorted(camp["hosts"])

        detail = "ran " + ", ".join(markers)
        if camp["sessions"] > 1:
            detail += (f" in {camp['sessions']} sessions "
                       f"from {len(hosts)} host" + ("s" if len(hosts) > 1 else ""))

        alerts.append({
            "rule": "payload_activity",
            "severity": "critical",
            "src_ip": hosts[0] if len(hosts) == 1 else None,
            "detail": detail,
            "evidence": {"payload_id": signature, "markers": markers,
                         "sessions": camp["sessions"], "hosts": hosts[:10],
                         "host_count": len(hosts), "command": sample},
        })
    alerts.sort(key=lambda a: -a["evidence"]["sessions"])
    return alerts


def main():
    ap = argparse.ArgumentParser(description="Detection rules for honeypot data")
    ap.add_argument("--db", default="honeypot.db")
    ap.add_argument("--out", default="alerts.json")
    ap.add_argument("--min-severity", default="low",
                    choices=list(SEVERITY_ORDER))
    ap.add_argument("--burst-attempts", type=int, default=100,
                    help="attempts in one window that count as a burst")
    ap.add_argument("--burst-minutes", type=int, default=10)
    ap.add_argument("--spray-usernames", type=int, default=20)
    ap.add_argument("--spray-per-user", type=float, default=2.0)
    ap.add_argument("--shared-hosts", type=int, default=5)
    ap.add_argument("--network-hosts", type=int, default=3)
    ap.add_argument("--network-attempts", type=int, default=100)
    args = ap.parse_args()

    conn = sqlite3.connect(args.db)
    conn.row_factory = sqlite3.Row

    alerts = []
    alerts += rule_brute_force(conn, args.burst_attempts, args.burst_minutes)
    alerts += rule_password_spray(conn, args.spray_usernames, args.spray_per_user)
    alerts += rule_shared_credentials(conn, args.shared_hosts)
    alerts += rule_coordinated_network(conn, args.network_hosts,
                                       args.network_attempts)
    alerts += rule_payload_activity(conn)
    conn.close()

    floor = SEVERITY_ORDER[args.min_severity]
    alerts = [a for a in alerts if SEVERITY_ORDER[a["severity"]] >= floor]
    alerts.sort(key=lambda a: -SEVERITY_ORDER[a["severity"]])

    counts = {}
    for a in alerts:
        counts[a["severity"]] = counts.get(a["severity"], 0) + 1

    print(f"{len(alerts)} alerts", end="")
    if counts:
        print(" (" + ", ".join(f"{n} {s}" for s, n in
                               sorted(counts.items(),
                                      key=lambda kv: -SEVERITY_ORDER[kv[0]])) + ")")
    else:
        print()

    for a in alerts:
        where = a["src_ip"] or a["evidence"].get("network", "-")
        print(f"\n[{a['severity'].upper():8}] {a['rule']}")
        print(f"  source: {where}")
        print(f"  {a['detail']}")

    report = {
        "generated": datetime.now(timezone.utc).isoformat(),
        "database": args.db,
        "alert_count": len(alerts),
        "by_severity": counts,
        "alerts": alerts,
    }
    with open(args.out, "w") as f:
        json.dump(report, f, indent=2)
    print(f"\nWrote {args.out}")

    # Exit code 1 when anything critical fired, so a scheduler or a shell
    # script can react without reading the JSON.
    return 1 if counts.get("critical") else 0


if __name__ == "__main__":
    sys.exit(main())