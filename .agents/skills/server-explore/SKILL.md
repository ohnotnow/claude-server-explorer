---
name: server-explore
description: Explore a Linux server's configuration, set up, oddities for IT security staff.  Use this to find out about a server, what's running on it, and "what's weird about it"
allowed-tools: "Read,Bash(ssh:*)"
argument-hint: "[user@]hostname"
version: "0.1.0"
author: "ohnotnow <https://github.com/ohnotnow>"
license: "MIT"
---

# Server Explorer

SSH into the server and build a picture of what it does.

If the user has not supplied a hostname, prompt them to enter one before proceeding.

## Database Setup

Before starting discovery, ensure the inventory database exists on the current server:

```bash
mkdir -p ~/.server-inventory
```

If `~/.server-inventory/inventory.db` does not exist, create it by running this schema exactly:

```sql
CREATE TABLE servers (
    hostname TEXT PRIMARY KEY,
    ip TEXT,
    os TEXT,
    os_version TEXT,
    kernel TEXT,
    uptime TEXT,
    last_scanned TEXT DEFAULT (datetime('now')),
    notes TEXT
);

CREATE TABLE services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL REFERENCES servers(hostname),
    port INTEGER,
    protocol TEXT DEFAULT 'tcp',
    process TEXT,
    description TEXT,
    UNIQUE(hostname, port, protocol)
);

CREATE TABLE containers (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL REFERENCES servers(hostname),
    container_name TEXT,
    image TEXT,
    ports TEXT,
    status TEXT,
    UNIQUE(hostname, container_name)
);

CREATE TABLE software (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL REFERENCES servers(hostname),
    path TEXT,
    name TEXT,
    version TEXT,
    UNIQUE(hostname, path)
);

CREATE TABLE filesystems (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL REFERENCES servers(hostname),
    mount TEXT,
    device TEXT,
    size TEXT,
    used TEXT,
    fs_type TEXT,
    UNIQUE(hostname, mount)
);

CREATE TABLE cron_jobs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL REFERENCES servers(hostname),
    user TEXT,
    schedule TEXT,
    command TEXT,
    UNIQUE(hostname, user, command)
);
```

## Discovery

Use `ssh $ARGUMENTS <command>` for each step.  If the users ssh keys have permission to run commands, then so will you.

**Run each SSH command as a separate, sequential Bash call. Never run SSH commands in parallel** — see AGENTS.md for why. Parallel calls get cancelled when any one returns non-zero, which SSH commands do routinely.

1. **Identity**: hostname, OS/distro, uptime, kernel version
2. **Listening services**: `ss -tlnp` — what ports are open and what processes own them
3. **Running services**: `systemctl list-units --type=service --state=running`
4. **Docker**: if docker is present, list running containers and their port mappings
5. **Interesting software**: check `/opt/`, `/usr/local/bin/`, `/usr/local/sbin/` for non-standard installs
6. **Filesystem layout**: `df -h`, note any unusual mounts (NFS, CIFS, large data volumes)
7. **Cron jobs**: check system and user crontabs for scheduled work
8. **Custom scripts and local tooling**: for any scripts in `/usr/local/bin` or similar, read the contents (not compiled binaries). Note what they do, what they connect to, and whether they contain embedded credentials.
9. **Config files in home directories**: if you find configuration files (`.conf`, `.env`, `.ini`, `.yaml`) in user home directories, check their permissions. Files containing secrets (private keys, passwords, tokens) should not be world-readable.
10. **Follow your nose**: if anything looks interesting or unusual, dig deeper. Check config files, look at what's actually in docker containers, read systemd unit files for custom services. List commands and surface commands only tell you what exists — reading the actual files tells you what things *do*.

Record findings once you are done to the database.

## Output

The audience for these reports is experienced sysadmins and IT security managers. They are quick to dismiss AI-generated output that overstates, speculates, or pads findings. Be precise, be evidence-based, and if you are not sure about something, say so rather than asserting it confidently.

Finish with a concise summary: what does this server appear to be *for*? Highlight notable services, anything weird, anything that might need attention. Write it like a paragraph for a team wiki, then list the standout details.

## Manager Analysis (for the dashboard report)

After completing the scan and recording findings to the database, write a brief server summary to the `server_analysis` table. This table may already exist — create it only if it doesn't:

```sql
CREATE TABLE IF NOT EXISTS server_analysis (
    hostname TEXT PRIMARY KEY REFERENCES servers(hostname),
    purpose TEXT,
    analysis TEXT,
    security_analysis TEXT,
    recommendations TEXT,
    security_recommendations TEXT,
    updated_at TEXT DEFAULT (datetime('now'))
);
```

Insert or update the server's entry:

```sql
INSERT OR REPLACE INTO server_analysis (hostname, purpose, analysis)
VALUES ('hostname', 'One-sentence description', 'A short paragraph for a manager audience');
```

- `purpose`: one sentence describing what the server is for
- `analysis`: a short paragraph summarising the server for a manager who does not SSH into servers

If the server is straightforward and well-maintained, say so plainly — do not manufacture concerns.

## Save the Report

Once you have presented the findings, ask the user if they would like the report saved as a local markdown file. Suggest a filename based on the hostname and date, e.g. `server-report-elf-2026-04-11.md`. Save it to the current working directory unless the user specifies somewhere else.
