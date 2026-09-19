-- Starter queries for the honeypot database.
-- Run them with:  sqlite3 honeypot.db < queries.sql
-- or one at a time inside:  sqlite3 honeypot.db

-- 1. Top source IPs by login attempts
SELECT src_ip, COUNT(*) AS attempts
FROM logins
GROUP BY src_ip
ORDER BY attempts DESC
LIMIT 10;

-- 2. Attempts grouped by /24 network.
-- rtrim strips the trailing digits, so 109.160.32.14 becomes 109.160.32.
SELECT
    rtrim(src_ip, '0123456789') || '0/24' AS network,
    COUNT(*) AS attempts,
    COUNT(DISTINCT src_ip) AS hosts
FROM logins
GROUP BY network
ORDER BY attempts DESC
LIMIT 10;

-- 3. Most tried usernames and passwords
SELECT username, COUNT(*) AS tries
FROM logins
GROUP BY username
ORDER BY tries DESC
LIMIT 15;

SELECT password, COUNT(*) AS tries
FROM logins
GROUP BY password
ORDER BY tries DESC
LIMIT 15;

-- 4. Attempts per hour, which shows the burst from one host
SELECT substr(timestamp, 1, 13) AS hour, COUNT(*) AS attempts
FROM logins
GROUP BY hour
ORDER BY hour;

-- 5. Same as above but with the one noisy host removed.
-- Change the IP to whichever host dominates your data.
SELECT substr(timestamp, 1, 10) AS day, COUNT(*) AS attempts
FROM logins
WHERE src_ip != '120.25.246.192'
GROUP BY day
ORDER BY day;

-- 6. Client software banners
SELECT client_version, COUNT(*) AS sessions
FROM sessions
GROUP BY client_version
ORDER BY sessions DESC;

-- 7. Sessions that did more than just fingerprint.
-- A JOIN pulls the IP from sessions next to the command count.
SELECT c.session, s.src_ip, COUNT(*) AS command_count
FROM commands c
JOIN sessions s ON s.session = c.session
GROUP BY c.session, s.src_ip
HAVING command_count > 1
ORDER BY command_count DESC
LIMIT 20;
