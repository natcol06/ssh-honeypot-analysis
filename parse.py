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


def show(title, counter, total=None, limit=15):
    print(f"\n{title}")
    print("-" * len(title))
    for name, count in counter.most_common(limit):
        if isinstance(name, tuple):
            name = " / ".join(name)
        label = repr(name) if name == "" else name
        if total:
            pct = 100 * count / total
            print(f"  {count:>7,}  {pct:>5.1f}%  {label}")
        else:
            print(f"  {count:>7,}  {label}")


def main():
    total = 0
    event_types = Counter()
    unique_ips = set()
    usernames = Counter()
    passwords = Counter()
    credentials = Counter()
    commands = Counter()
    ip_attempts = Counter()
    clients = Counter()

    for event in load_events():
        total += 1
        eid = event.get("eventid", "unknown")
        event_types[eid] += 1

        ip = event.get("src_ip")
        if ip:
            unique_ips.add(ip)

        if eid.startswith("cowrie.login"):
            user = event.get("username", "")
            pwd = event.get("password", "")
            usernames[user] += 1
            passwords[pwd] += 1
            credentials[(user, pwd)] += 1
            if ip:
                ip_attempts[ip] += 1

        elif eid == "cowrie.command.input":
            cmd = event.get("input", "").strip()
            if cmd:
                commands[cmd] += 1

        elif eid == "cowrie.client.version":
            version = event.get("version", "")
            if version:
                clients[version] += 1

    logins = sum(usernames.values())

    print(f"\nTotal events:      {total:,}")
    print(f"Login attempts:    {logins:,}")
    print(f"Unique source IPs: {len(unique_ips):,}")

    subnets = Counter()
    for ip, count in ip_attempts.items():
        subnets[".".join(ip.split(".")[:3]) + ".0/24"] += count

    show("Top usernames", usernames, logins)
    show("Top passwords", passwords, logins)
    show("Top credential pairs", credentials, logins)
    show("Busiest source IPs", ip_attempts, logins)
    show("Busiest /24 networks", subnets, logins)
    show("SSH client banners", clients)
    show("Top commands run by attackers", commands, limit=25)

    top_two = sum(c for _, c in subnets.most_common(2))
    print(f"\nTop 2 networks: {top_two:,} of {logins:,} attempts "
          f"({100*top_two/logins:.1f}%)")
    print(f"Distinct /24 networks: {len(subnets):,}")
    print(f"Unique IPs: {len(unique_ips):,}")
    
if __name__ == "__main__":
    main()