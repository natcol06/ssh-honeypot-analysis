"""
Load Cowrie honeypot JSON logs into a SQLite database.

Usage:
    python load_db.py                 # reads ./data, writes honeypot.db
    python load_db.py mylogs out.db   # custom folder and database name

Handles plain .json files and rotated .json.gz files.
Bad lines are skipped and counted.
"""

import gzip
import json
import os
import sqlite3
import sys


def open_log(path):
    """Open a log file whether or not it is gzipped."""
    if path.endswith(".gz"):
        return gzip.open(path, "rt", errors="replace")
    return open(path, "r", errors="replace")


def find_logs(folder):
    """Return every Cowrie JSON log in the folder, sorted by name.

    sample.json is skipped: it is a copy of lines from the real logs,
    committed so the tool runs on a fresh clone, so counting it would
    double up those lines.
    """
    names = []
    for name in os.listdir(folder):
        if ".json" in name and not name.startswith("sample"):
            names.append(os.path.join(folder, name))
    return sorted(names)


def make_tables(conn):
    """Create the three tables. Dropping first makes reruns safe."""
    conn.executescript("""
        DROP TABLE IF EXISTS sessions;
        DROP TABLE IF EXISTS logins;
        DROP TABLE IF EXISTS commands;

        CREATE TABLE sessions (
            session        TEXT PRIMARY KEY,
            src_ip         TEXT,
            start_time     TEXT,
            client_version TEXT
        );

        CREATE TABLE logins (
            session   TEXT,
            src_ip    TEXT,
            username  TEXT,
            password  TEXT,
            success   INTEGER,
            timestamp TEXT
        );

        CREATE TABLE commands (
            session   TEXT,
            src_ip    TEXT,
            command   TEXT,
            timestamp TEXT
        );
    """)


def load(folder="data", db_path="honeypot.db"):
    conn = sqlite3.connect(db_path)
    make_tables(conn)

    sessions = {}          # session id -> row, filled in as events arrive
    logins = []
    commands = []
    bad_lines = 0
    files = find_logs(folder)

    if not files:
        print("No .json logs found in " + folder)
        return

    for path in files:
        with open_log(path) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    bad_lines += 1
                    continue

                kind = event.get("eventid", "")
                sid = event.get("session")
                ip = event.get("src_ip")
                when = event.get("timestamp")

                # Every event tells us something about its session.
                if sid and sid not in sessions:
                    sessions[sid] = [sid, ip, when, None]

                if kind == "cowrie.client.version" and sid in sessions:
                    sessions[sid][3] = event.get("version")

                elif kind == "cowrie.login.success":
                    logins.append((sid, ip, event.get("username"),
                                   event.get("password"), 1, when))

                elif kind == "cowrie.login.failed":
                    logins.append((sid, ip, event.get("username"),
                                   event.get("password"), 0, when))

                elif kind == "cowrie.command.input":
                    commands.append((sid, ip, event.get("input"), when))

    conn.executemany("INSERT OR REPLACE INTO sessions VALUES (?,?,?,?)",
                     sessions.values())
    conn.executemany("INSERT INTO logins VALUES (?,?,?,?,?,?)", logins)
    conn.executemany("INSERT INTO commands VALUES (?,?,?,?)", commands)

    # Indexes keep the dashboard queries fast as the data grows.
    conn.executescript("""
        CREATE INDEX idx_logins_ip   ON logins(src_ip);
        CREATE INDEX idx_logins_user ON logins(username);
        CREATE INDEX idx_logins_time ON logins(timestamp);
        CREATE INDEX idx_cmds_ip     ON commands(src_ip);
    """)
    conn.commit()

    print("Files read:      " + str(len(files)))
    print("Sessions:        " + str(len(sessions)))
    print("Login attempts:  " + str(len(logins)))
    print("Commands:        " + str(len(commands)))
    if bad_lines:
        print("Skipped lines:   " + str(bad_lines))
    print("Wrote " + db_path)
    conn.close()


if __name__ == "__main__":
    folder = sys.argv[1] if len(sys.argv) > 1 else "data"
    db_path = sys.argv[2] if len(sys.argv) > 2 else "honeypot.db"
    load(folder, db_path)
