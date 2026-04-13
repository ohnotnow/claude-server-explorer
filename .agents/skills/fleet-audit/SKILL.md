---
name: fleet-audit
description: Batch server audit — runs server-explore and security-explore for every server in a list, generates all reports. No prompting, no questions.
allowed-tools: "Read,Bash(ssh:*),Bash(sqlite3:*),Bash(uv:*),Bash(open:*),Bash(mkdir:*)"
argument-hint: "servers.txt | server1, server2, server3 | 'just check elf and muffin'"
version: "0.1.0"
author: "ohnotnow <https://github.com/ohnotnow>"
license: "MIT"
---

# Fleet Audit

Batch-run a full server exploration and security assessment for multiple servers. This is the "go away and do all of them" skill — no interactive prompts, no questions, just results.

## Parsing the Server List

The user's input (`$ARGUMENTS`) can be any of:

1. **A filename** — e.g. `servers.txt`. Read the file; each non-empty, non-comment line is a hostname (or `user@hostname`). Lines starting with `#` are comments.
2. **A comma/space-separated list** — e.g. `elf, cordelia, muffin` or `elf cordelia muffin`.
3. **Natural language** — e.g. `just check elf and muffin` or `can we do elf, cordelia and muffin please?`. Extract the hostnames from the text.
4. **Nothing** — default to reading `servers.txt` in the current directory.

If a filename is given but doesn't exist, tell the user and stop. If no arguments and no `servers.txt`, tell the user and stop.

Once you have the list, print it clearly before starting:

> **Fleet audit starting for 3 servers: elf, cordelia, muffin**

## Running the Scans

For each server in the list, run the following steps **sequentially**. Complete one server fully before moving to the next.

**Run each SSH command as a separate, sequential Bash call. Never run SSH commands in parallel** — see AGENTS.md for why.

### Step 1: Server Exploration

Read the server-explore skill file to get the current discovery instructions:

```
.Codex/skills/server-explore/skill.md
```

Follow its **Database Setup** and **Discovery** sections for this server. Record findings to the database as instructed. Then follow its **Manager Analysis** section to write the `server_analysis` table entry.

**Do not** ask the user if they want a markdown report — just save one automatically using the naming convention `server-report-{hostname}-{date}.md`.

### Step 2: Security Assessment

Read the security-explore skill file to get the current security check instructions:

```
.Codex/skills/security-explore/skill.md
```

Follow its **Database Setup**, **Connectivity & Proxy**, **A Note on Privileges**, and **Discovery** sections for this server. Record findings, package vulns, and config checks to the database as instructed. Then follow its **Manager Analysis** section to update the `server_analysis` table entry with security fields.

**Do not** ask the user if they want a markdown report — just save one automatically using the naming convention `security-report-{hostname}-{date}.md`.

### Step 3: Server HTML Report

Generate the HTML report for this server:

```bash
uv run report.py --server {hostname}
```

### Step 4: Progress Update

After completing each server, print a short progress line:

> **[2/5] cordelia done — 1 critical, 3 high, 4 medium**

This keeps the user informed without being noisy.

## After All Servers

Once every server has been scanned:

1. **Generate the fleet HTML report**:
   ```bash
   uv run report.py
   ```

2. **Print a summary table** showing all servers, their finding counts by severity, and their health scores.

3. **Open the fleet report** in the browser:
   ```bash
   open fleet-report-{date}.html
   ```

## Error Handling

If a server is unreachable (SSH times out or fails), log it as a skipped server and move on to the next one. Do not let one unreachable server stop the whole run. At the end, list any servers that were skipped and why.

## What NOT to Do

- Do not ask the user any questions during the run. Make reasonable assumptions.
- Do not ask about saving markdown files — always save them.
- Do not stop to present findings interactively — just record and move on.
- Do not run SSH commands in parallel (see AGENTS.md).
- Do not skip the security scan if the server exploration found nothing interesting — always run both.
