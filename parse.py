import json
import glob
from collections import Counter
from datetime import datetime


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
        name = " ".join(str(name).split())
        if len(name) > 100:
            name = name[:97] + "..."
        label = repr(name) if name == "" else name
        if total:
            pct = 100 * count / total
            print(f"  {count:>7,}  {pct:>5.1f}%  {label}")
        else:
            print(f"  {count:>7,}  {label}")

def parse_time(value):
    """Cowrie writes ISO timestamps ending in Z."""
    if not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None

def main():
    
    MY_IPS = {"208.71.27.71"}
    
    total = 0
    event_types = Counter()
    unique_ips = set()
    usernames = Counter()
    passwords = Counter()
    credentials = Counter()
    commands = Counter()
    ip_attempts = Counter()
    clients = Counter()
    by_hour = Counter()
    by_day = Counter()
    first_seen = {}

    for event in load_events():
        total += 1
        eid = event.get("eventid", "unknown")
        event_types[eid] += 1

        ip = event.get("src_ip")
        if ip in MY_IPS:
            continue
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

            ts = parse_time(event.get("timestamp"))
            if ts:
                by_hour[ts.strftime("%Y-%m-%d %H:00")] += 1
                by_day[ts.strftime("%Y-%m-%d")] += 1
                if ip and (ip not in first_seen or ts < first_seen[ip]):
                    first_seen[ip] = ts

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
    
    print("\nAttempts per day")
    print("----------------")
    for day in sorted(by_day):
        bar = "#" * int(40 * by_day[day] / max(by_day.values()))
        print(f"  {day}  {by_day[day]:>6,}  {bar}")

    print("\nBusiest hours")
    print("-------------")
    for hour, count in by_hour.most_common(12):
        print(f"  {hour}  {count:>6,}")

    if first_seen:
        earliest = min(first_seen.values())
        latest = max(first_seen.values())
        span = latest - earliest
        print(f"\nFirst login attempt:  {earliest}")
        print(f"Last login attempt:   {latest}")
        print(f"Collection span:      {span}")
    
    burst_hours = {"2026-09-08 05:00", "2026-09-08 06:00", "2026-09-08 07:00"}
    burst_ips = Counter()
    for event in load_events():
        if not event.get("eventid", "").startswith("cowrie.login"):
            continue
        ts = parse_time(event.get("timestamp"))
        if ts and ts.strftime("%Y-%m-%d %H:00") in burst_hours:
            burst_ips[event.get("src_ip")] += 1
    show("Who drove the Sept 8 05:00-07:00 burst", burst_ips, limit=10)
    
    NOISY = "120.25.246.192"
    clean_by_day = Counter()
    for event in load_events():
        if not event.get("eventid", "").startswith("cowrie.login"):
            continue
        if event.get("src_ip") == NOISY:
            continue
        ts = parse_time(event.get("timestamp"))
        if ts:
            clean_by_day[ts.strftime("%Y-%m-%d")] += 1

    print(f"\nAttempts per day, excluding {NOISY}")
    print("-" * 40)
    for day in sorted(clean_by_day):
        print(f"  {day}  {clean_by_day[day]:>6,}")
    
if __name__ == "__main__":
    main()