import json
import glob
from collections import Counter

def load_events(pattern="data/cowrie.json*"):
    """Read every Cowrie log file and yield one dict per event."""
    files = sorted(glob.glob(pattern))
    if not files:
        raise SystemExit(f"No files matched {pattern}")

    bad_lines = 0
    for path in files:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    yield json.loads(line)
                except json.JSONDecodeError:
                    bad_lines += 1

    if bad_lines:
        print(f"Skipped {bad_lines} malformed lines")


def main():
    total = 0
    event_types = Counter()
    unique_ips = set()
    logins = 0

    for event in load_events():
        total += 1
        event_types[event.get("eventid", "unknown")] += 1

        ip = event.get("src_ip")
        if ip:
            unique_ips.add(ip)

        if event.get("eventid", "").startswith("cowrie.login"):
            logins += 1

    print(f"\nTotal events:     {total:,}")
    print(f"Login attempts:   {logins:,}")
    print(f"Unique source IPs: {len(unique_ips):,}")

    print("\nEvent types:")
    for name, count in event_types.most_common():
        print(f"  {count:>8,}  {name}")


if __name__ == "__main__":
    main()