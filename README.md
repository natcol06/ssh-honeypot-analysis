# SSH Honeypot Analysis

A Cowrie SSH honeypot on a public VPS, plus a Python tool that
turns its logs into findings about who attacks an unknown machine
and how fast.

# Status

Collecting. Deployed 2026-09-08. Analysis tool in progress.

# Early numbers

- First scan arrived **5 minutes 4 seconds** after the host went live
- Login attempts began within the first hour on an IP that did not
  exist that morning

# Setup

- $6/mo Ubuntu 22.04 VPS
- Real SSH moved to a nonstandard port, key auth only, root password
  login disabled
- Cowrie 3.0.13 running as an unprivileged user on port 2222
- iptables redirects port 22 to 2222, so scanners hit the door they
  expect

Strictly observational. Inbound traffic to a machine I own. Nothing
outbound, no scanning, no active response.

# Planned

- JSON parser into SQLite
- Detection rules: brute force bursts, password spraying, credential
  replay across hosts, repeat offenders
- Source network and country enrichment
- Findings write-up