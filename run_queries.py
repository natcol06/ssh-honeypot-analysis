"""
Run every query in queries.sql against honeypot.db and print the results.

Usage:
    python run_queries.py
"""

import sqlite3

DB = "honeypot.db"
SQL_FILE = "queries.sql"


def statements(text):
    """Split the file on semicolons and drop comment-only chunks."""
    for chunk in text.split(";"):
        lines = [l for l in chunk.splitlines() if l.strip()]
        code = [l for l in lines if not l.strip().startswith("--")]
        if code:
            label = lines[0].strip()
            yield label, chunk


def main():
    conn = sqlite3.connect(DB)
    text = open(SQL_FILE).read()

    for label, sql in statements(text):
        print("")
        print("=" * 60)
        print(label)
        print("=" * 60)
        cur = conn.execute(sql)
        headers = [d[0] for d in cur.description]
        rows = cur.fetchall()
        print(" | ".join(headers))
        for row in rows:
            print(" | ".join(str(v) for v in row))

    conn.close()


if __name__ == "__main__":
    main()
