"""
SSH Honeypot Dashboard

Reads honeypot.db (built by load_db.py) and shows the main findings.

Usage:
    streamlit run app.py
"""

import sqlite3

import pandas as pd
import streamlit as st

DB = "honeypot.db"

st.set_page_config(page_title="SSH Honeypot Dashboard", layout="wide")


@st.cache_data
def run(sql, params=()):
    """Run a query and hand back a DataFrame. Cached so the page stays fast."""
    conn = sqlite3.connect(DB)
    df = pd.read_sql_query(sql, conn, params=params)
    conn.close()
    return df


st.title("SSH Honeypot Dashboard")
st.caption(
    "Cowrie honeypot on a public VPS. Every number below comes from a SQL "
    "query against the collected logs."
)

# ---------------------------------------------------------------- headline
totals = run("""
    SELECT
        (SELECT COUNT(*) FROM logins)                 AS attempts,
        (SELECT COUNT(DISTINCT src_ip) FROM logins)   AS hosts,
        (SELECT COUNT(*) FROM commands)               AS commands,
        (SELECT COUNT(*) FROM sessions)               AS sessions
""").iloc[0]

c1, c2, c3, c4 = st.columns(4)
c1.metric("Login attempts", f"{totals.attempts:,}")
c2.metric("Unique source hosts", f"{totals.hosts:,}")
c3.metric("Commands captured", f"{totals.commands:,}")
c4.metric("Sessions", f"{totals.sessions:,}")

# ------------------------------------------------------------- per network
st.header("Two networks did most of the work")
st.write(
    "Counted per host the traffic looks spread out. Counted per /24 network "
    "it collapses into a couple of operations."
)

networks = run("""
    SELECT rtrim(src_ip, '0123456789') || '0/24' AS network,
           COUNT(*) AS attempts,
           COUNT(DISTINCT src_ip) AS hosts
    FROM logins
    GROUP BY network
    ORDER BY attempts DESC
    LIMIT 10
""")
networks["share"] = (
    networks.attempts / totals.attempts * 100
).round(1).astype(str) + "%"

left, right = st.columns([1, 1])
left.dataframe(networks, hide_index=True, use_container_width=True)
right.bar_chart(networks.set_index("network").attempts)

# ------------------------------------------------------------ top sources
st.header("Busiest source hosts")
top_ips = run("""
    SELECT src_ip, COUNT(*) AS attempts
    FROM logins
    GROUP BY src_ip
    ORDER BY attempts DESC
    LIMIT 15
""")
st.bar_chart(top_ips.set_index("src_ip").attempts)

# ------------------------------------------------------------- over time
st.header("Attempts over time")
st.write(
    "One host ran a single large job in a three hour window. Hiding it "
    "shows what the rest of the internet was doing."
)

noisiest = top_ips.iloc[0].src_ip
hide = st.checkbox(f"Hide the busiest host ({noisiest})", value=False)

if hide:
    hourly = run("""
        SELECT substr(timestamp, 1, 13) AS hour, COUNT(*) AS attempts
        FROM logins
        WHERE src_ip != ?
        GROUP BY hour ORDER BY hour
    """, (noisiest,))
    daily = run("""
        SELECT substr(timestamp, 1, 10) AS day, COUNT(*) AS attempts
        FROM logins
        WHERE src_ip != ?
        GROUP BY day ORDER BY day
    """, (noisiest,))
else:
    hourly = run("""
        SELECT substr(timestamp, 1, 13) AS hour, COUNT(*) AS attempts
        FROM logins GROUP BY hour ORDER BY hour
    """)
    daily = run("""
        SELECT substr(timestamp, 1, 10) AS day, COUNT(*) AS attempts
        FROM logins GROUP BY day ORDER BY day
    """)

st.line_chart(hourly.set_index("hour").attempts)
st.write("By day:")
st.dataframe(daily, hide_index=True)

# ------------------------------------------------------------ credentials
st.header("Credentials tried")
u_col, p_col = st.columns(2)

users = run("""
    SELECT username, COUNT(*) AS tries
    FROM logins GROUP BY username ORDER BY tries DESC LIMIT 15
""")
passwords = run("""
    SELECT password, COUNT(*) AS tries
    FROM logins GROUP BY password ORDER BY tries DESC LIMIT 15
""")
u_col.subheader("Usernames")
u_col.dataframe(users, hide_index=True, use_container_width=True)
p_col.subheader("Passwords")
p_col.dataframe(passwords, hide_index=True, use_container_width=True)

pairs = run("""
    SELECT username || ' / ' || password AS pair, COUNT(*) AS tries
    FROM logins GROUP BY pair ORDER BY tries DESC LIMIT 10
""")
st.write(
    "The most common username and password pair was tried "
    f"{int(pairs.tries.max()):,} times out of {totals.attempts:,} attempts. "
    "Little repetition means a dictionary sweep, not targeted guessing."
)
st.dataframe(pairs, hide_index=True)

# ---------------------------------------------------------------- clients
st.header("Client software")
clients = run("""
    SELECT client_version, COUNT(*) AS sessions
    FROM sessions
    WHERE client_version LIKE 'SSH-%'
    GROUP BY client_version ORDER BY sessions DESC LIMIT 10
""")
st.dataframe(clients, hide_index=True, use_container_width=True)

# --------------------------------------------------------------- commands
st.header("What attackers typed")
commands = run("""
    SELECT command, COUNT(*) AS times
    FROM commands GROUP BY command ORDER BY times DESC LIMIT 15
""")
st.dataframe(commands, hide_index=True, use_container_width=True)

busy_sessions = run("""
    SELECT c.session, s.src_ip, COUNT(*) AS command_count
    FROM commands c
    JOIN sessions s ON s.session = c.session
    GROUP BY c.session, s.src_ip
    HAVING command_count > 1
    ORDER BY command_count DESC
    LIMIT 20
""")
st.write("Sessions that ran more than one command:")
st.dataframe(busy_sessions, hide_index=True, use_container_width=True)

# -------------------------------------------------------------- query box
st.header("Run your own query")
sql = st.text_area(
    "SQL",
    "SELECT username, COUNT(*) AS tries\nFROM logins\nGROUP BY username\n"
    "ORDER BY tries DESC\nLIMIT 10;",
    height=140,
)
if st.button("Run"):
    try:
        st.dataframe(run(sql), hide_index=True)
    except Exception as err:
        st.error(str(err))
