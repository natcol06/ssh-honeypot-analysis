"""
parse_same.py - Python twin of cpp/parse.cpp, for a fair speed comparison.

Does exactly the same work as the C++ version: reads the same files,
counts the same things, prints the same report. Nothing more.

Run from the cpp folder:
    python parse_same.py            (reads ../data)
    python parse_same.py some/dir
"""

import json
import os
import sys
import time
from collections import Counter


def find_logs(folder):
    files = []
    for name in os.listdir(folder):
        path = os.path.join(folder, name)
        if os.path.isfile(path) and ".json" in name and not name.startswith("sample"):
            files.append(path)
    return sorted(files)


def shorten(s, max_len=60):
    return s if len(s) <= max_len else s[: max_len - 3] + "..."


def print_top(title, counts, n=10):
    print()
    print(title)
    for value, count in counts.most_common(n):
        print(f"  {count:>7}  {shorten(value)}")


def main():
    folder = sys.argv[1] if len(sys.argv) > 1 else "../data"
    start = time.perf_counter()

    files = find_logs(folder)
    if not files:
        print(f"No .json logs found in {folder}", file=sys.stderr)
        return 1

    attempts_by_ip, usernames, passwords, commands = (
        Counter(), Counter(), Counter(), Counter())
    sessions, connected_hosts = set(), set()
    total_attempts = total_commands = bad_lines = lines_read = 0

    for path in files:
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                lines_read += 1
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    bad_lines += 1
                    continue

                kind = event.get("eventid", "")
                ip = event.get("src_ip", "")
                session = event.get("session", "")

                if session:
                    sessions.add(session)
                if ip:
                    connected_hosts.add(ip)

                if kind in ("cowrie.login.success", "cowrie.login.failed"):
                    attempts_by_ip[ip] += 1
                    usernames[event.get("username", "")] += 1
                    passwords[event.get("password", "")] += 1
                    total_attempts += 1
                elif kind == "cowrie.command.input":
                    commands[event.get("input", "")] += 1
                    total_commands += 1

    ms = (time.perf_counter() - start) * 1000

    print("SSH Honeypot Report (Python)")
    print("============================")
    print(f"Files read:          {len(files)}")
    print(f"Lines read:          {lines_read}")
    if bad_lines:
        print(f"Skipped lines:       {bad_lines}")
    print(f"Sessions:            {len(sessions)}")
    print(f"Hosts connected:     {len(connected_hosts)}")
    print(f"Hosts tried a login: {len(attempts_by_ip)}")
    print(f"Login attempts:      {total_attempts}")
    print(f"Commands captured:   {total_commands}")

    print_top("Top source IPs", attempts_by_ip)
    print_top("Top usernames", usernames)
    print_top("Top passwords", passwords)
    print_top("Top commands", commands)

    print(f"\nTime: {ms:.1f} ms")
    return 0


if __name__ == "__main__":
    sys.exit(main())