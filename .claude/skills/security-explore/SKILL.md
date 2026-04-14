---
name: security-explore
description: Explore a Linux server's security posture to provide reporting to IT security staff.  Use this to find vulnerabilities, misconfigurations, and other issues when asked.
allowed-tools: "Read,Bash(ssh:*),Bash(curl:*),Bash(python3:*),Bash(mkdir:*),Bash(sqlite3:*)"
argument-hint: "[user@]hostname"
version: "0.1.0"
author: "ohnotnow <https://github.com/ohnotnow>"
license: "AGPL-3.0"
---

# Security Explorer

SSH into the server and perform a security-focused assessment.

This complements reactive tools like Rapid7 and Defender which flag known CVEs after the fact. Security Explorer takes a more holistic look: what's exposed, what's misconfigured, what would an attacker notice, and what quick wins are available. Think of it as a proactive health check rather than a vulnerability scanner.

If the user has not supplied a hostname, prompt them to enter one before proceeding.

## Database Setup

Before starting, ensure the inventory database exists on the current machine:

```bash
mkdir -p ~/.server-inventory
```

If `~/.server-inventory/inventory.db` does not already contain the security tables below, create them. The `servers` table is shared withe `/server-explore` skill — create it only if it doesn't already exist.

```sql
CREATE TABLE IF NOT EXISTS servers (
    hostname TEXT PRIMARY KEY,
    ip TEXT,
    os TEXT,
    os_version TEXT,
    kernel TEXT,
    uptime TEXT,
    last_scanned TEXT DEFAULT (datetime('now')),
    notes TEXT
);

CREATE TABLE security_scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL REFERENCES servers(hostname),
    scanned_at TEXT DEFAULT (datetime('now')),
    summary TEXT
);

CREATE TABLE findings (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL REFERENCES servers(hostname),
    scan_id INTEGER REFERENCES security_scans(id),
    severity TEXT CHECK(severity IN ('critical', 'high', 'medium', 'low', 'info')),
    category TEXT,
    title TEXT,
    detail TEXT,
    remediation TEXT,
    status TEXT DEFAULT 'open' CHECK(status IN ('open', 'acknowledged', 'remediated', 'accepted_risk')),
    found_at TEXT DEFAULT (datetime('now')),
    remediated_at TEXT,
    UNIQUE(hostname, category, title)
);

CREATE TABLE package_vulns (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL REFERENCES servers(hostname),
    scan_id INTEGER REFERENCES security_scans(id),
    package_name TEXT,
    installed_version TEXT,
    fixed_version TEXT,
    cve_id TEXT,
    on_kev INTEGER DEFAULT 0,
    epss_score REAL,
    severity TEXT,
    UNIQUE(hostname, package_name, cve_id)
);

CREATE TABLE config_checks (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    hostname TEXT NOT NULL REFERENCES servers(hostname),
    scan_id INTEGER REFERENCES security_scans(id),
    category TEXT,
    check_name TEXT,
    result TEXT CHECK(result IN ('pass', 'fail', 'warn', 'skip')),
    detail TEXT,
    UNIQUE(hostname, check_name)
);
```

## Connectivity & Proxy

External API lookups (KEV catalogue, EPSS scores) run on the **local machine**, not on the remote server. This avoids needing `curl` or `python3` on the remote server and means every server gets full KEV/EPSS coverage regardless of its own network access.

Package index refreshes (`apt update`, `dnf check-update`, etc.) still run on the remote server via SSH. If a server sits on a private subnet without direct internet access, its package manager may need a proxy — but that is typically configured on the server itself (e.g. `/etc/apt/apt.conf.d/` or `/etc/yum.conf`). If `apt update` fails due to connectivity, check whether the server has a proxy configured. If not, look for a `proxy` line in `.server-explorer.conf` in the project root and pass it via SSH:

```bash
ssh $ARGUMENTS "http_proxy=http://proxy:port https_proxy=http://proxy:port sudo apt update"
```

If there is no config file or proxy line, ask the user. If no proxy is available, skip the package index refresh and note it in findings — the rest of the scan still works without it.

## A Note on Privileges

Some checks need root access. Where a command requires elevated privileges, try it with `sudo`. If sudo is not available, skip the check and record a finding noting that the check was skipped and why. Never let a missing privilege block the whole scan — partial results are far better than none.

## Discovery

Use `ssh $ARGUMENTS <command>` for each step.

**Run each SSH command as a separate, sequential Bash call. Never run SSH commands in parallel** — see CLAUDE.md for why. Parallel calls get cancelled when any one returns non-zero, which SSH commands do routinely.

### 1. System Identity

Gather hostname, OS/distro, kernel version, and uptime. This gives context for everything that follows.

Check whether the kernel version is current for the distro — a very old kernel on a relatively recent distro is a sign that patching has stalled, and kernel vulnerabilities tend to be severe.

### 2. Patch Gap

This is the single most important check. How far behind is this server on security updates?

- **apt-based** (Debian, Ubuntu): Run `apt update` (refreshes the package index only — does not install anything), then `apt list --upgradable`. Check whether `unattended-upgrades` is installed and enabled.
- **yum/dnf-based** (RHEL, CentOS, Rocky, Alma, Fedora): `dnf check-update --security` or `yum updateinfo list security` shows security-specific updates, often with CVE IDs.
- **apk-based** (Alpine): `apk update` then `apk version -l '<'`.

Count the pending security updates. More than a handful suggests patching is not keeping pace. If you can determine the oldest pending update, note it — that tells you how long the gap has been growing.

Also check: is automatic patching configured? Look for `unattended-upgrades` on Debian/Ubuntu or `dnf-automatic` on RHEL-family systems. If automatic patching is not set up, flag it as a recommendation.

#### CVE extraction for apt-based systems

`apt` does not include CVE IDs in its upgrade output, unlike `dnf`/`yum`. Without CVE IDs the KEV and EPSS lookups in steps 3 and 4 have nothing to work with. Extract them using one of these approaches:

**If `debsecan` is installed** on the server (check with `which debsecan` via SSH), run it:

```bash
ssh $ARGUMENTS "debsecan --only-fixed --format detail"
```

This lists every CVE fixed by an available update, one per line, with the package name and fix version. Parse the output to build a map of CVE IDs to packages.

**Otherwise**, query the Debian Security Tracker API locally. First, get the release codename and map upgradable packages to their source package names:

```bash
ssh $ARGUMENTS "lsb_release -cs"
ssh $ARGUMENTS "apt list --upgradable 2>/dev/null | tail -n +2 | cut -d/ -f1 | xargs dpkg-query -W -f '\${source:Package}\n' 2>/dev/null | sort -u"
```

Then fetch CVE data for each unique source package on the local machine:

```bash
curl -s "https://security-tracker.debian.org/tracker/source-package/<source_package>.json"
```

The JSON is keyed by CVE ID. For each CVE, check `releases.<codename>` — if `status` is `"resolved"` and the `fixed_version` is among the available upgrades, that CVE is fixed by a pending update. To keep API calls manageable when backlogs are large, prioritise security-critical source packages (openssh, openssl, linux, sudo, systemd, curl, docker) and work outward.

Collect the CVE IDs from either approach for use in the KEV and EPSS steps below, and record each one as a row in the `package_vulns` table.

#### Kernel CVE extraction

For **standard distro kernels** (Debian's `linux` package, Ubuntu, RHEL, etc.), kernel CVEs are handled by the normal vendor tooling — the Debian Security Tracker, `dnf check-update --security`, and so on. No special steps are needed; the CVE extraction in the previous section covers the kernel just like any other package.

**Vendor-patched kernels** (Raspberry Pi, Oracle UEK, and similar) need a different approach. These kernels come from a separate source tree and use their own version scheme — for example, RPi kernels have epoch-prefixed versions like `1:6.6.31-1+rpt1` rather than standard Debian versioning like `6.1.147-1`. The Debian Security Tracker's fix versions refer to the Debian `linux` package, so `dpkg --compare-versions` will silently give wrong results against a vendor kernel.

**How to tell which you're on:** check the output of `uname -r`. Standard distro kernels look like `6.1.0-28-amd64` or `5.15.0-91-generic`. Vendor-patched kernels have distinctive suffixes — `+rpt1` for Raspberry Pi, `uek` for Oracle, and so on. If `uname -r` contains a vendor suffix, use the kernel.org approach below.

##### Kernel.org CVE lookup (vendor-patched kernels only)

The kernel.org CVE git repository tracks fix versions per upstream branch, which makes it reliable regardless of how the vendor packages its kernel.

1. Get the running kernel's upstream version on the server:

```bash
ssh $ARGUMENTS "uname -r | sed 's/+.*//' | sed 's/-.*//' "
```

This strips the vendor/distro suffix to give the upstream version (e.g. `6.6.31` or `6.12.34`).

2. Determine the kernel's major.minor branch (e.g. `6.6` or `6.12`).

3. For each kernel CVE to check (at minimum, check all Linux kernel entries from the KEV catalogue — see step 3), fetch the fix data locally:

```bash
curl -s "https://git.kernel.org/pub/scm/linux/security/vulns.git/plain/cve/published/<year>/<CVE-ID>.json"
```

4. In the returned JSON, look through **all** `containers.cna.affected[]` blocks (there are usually two — one with git commits, one with semver data). In the semver entries, find entries where `versionType` is `"semver"`, `status` is `"unaffected"`, and `lessThanOrEqual` matches the kernel branch (e.g. `"6.6.*"`). The `version` field of that entry is the first fixed version in that branch.

5. Compare the server's upstream kernel version against the fix version. If the server is running an older version, it is vulnerable.

If the kernel.org CVE repo does not have an entry for a given CVE (common for CVEs older than ~2023), the vulnerability predates the 6.x kernel series and is not relevant to current kernels.

Record any kernel CVEs found as rows in `package_vulns` with `package_name` set to `linux-kernel`.

### 3. Known Exploited Vulnerabilities (KEV)

The CISA KEV catalog lists vulnerabilities confirmed to be under active exploitation in the wild. Anything matching this list is an emergency — not theoretical, not "might be exploited one day," but actively being used by attackers right now.

**This lookup runs locally, not on the remote server.** Download the catalog on the local machine (it is a free, public JSON file — no API key required):

```bash
curl -s "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
```

This is a local Bash call — do **not** run it via SSH. Running it locally means the remote server needs no outbound HTTP access for this check, and for fleet audits the catalog is fetched once and reused across all servers.

Each entry has `cveID`, `vendorProject`, `product`, `vulnerabilityName`, and `knownRansomwareCampaignUse` fields.

Cross-reference against:
- CVE IDs from the patch gap check (yum/dnf report these directly; for apt-based systems, use the CVE extraction step above)
- Installed software names and versions against the `vendorProject` and `product` fields

Any match is a **critical** finding. If `knownRansomwareCampaignUse` is "Known", escalate further — this means ransomware gangs are actively using it.

### 4. EPSS Scoring

For CVEs found in step 2, check their EPSS (Exploit Prediction Scoring System) score. EPSS gives a probability between 0 and 1 that a vulnerability will be exploited in the next 30 days. It is a free API run by FIRST.org — no API key required.

**This lookup also runs locally.** Call the EPSS API on the local machine:

```bash
curl -s "https://api.first.org/data/v1/epss?cve=CVE-2024-XXXXX"
```

You can batch multiple CVEs in one request:

```bash
curl -s "https://api.first.org/data/v1/epss?cve=CVE-2024-1234,CVE-2024-5678"
```

Use EPSS to prioritise the update queue:
- **Above 0.7**: high priority — likely to be exploited soon
- **0.4 to 0.7**: medium priority — worth doing promptly
- **Below 0.4**: lower priority — schedule normally

This turns "we have 47 pending updates, where do we start?" into a ranked list.

### 5. Attack Surface

What is listening on this server, and who can reach it?

- `ss -tlnp` — all listening TCP ports and the process that owns each one
- `ss -ulnp` — all listening UDP ports
- Check which services are bound to `0.0.0.0` or `::` (reachable from the network) versus `127.0.0.1` or `::1` (localhost only). Any service bound to all interfaces that does not need to be is unnecessary exposure.
- Check firewall rules: `iptables -L -n`, `nft list ruleset`, or `firewall-cmd --list-all`. If there is no firewall configured at all, that is a finding.
- Investigate any service you do not recognise — check its unit file, its config, what it does.

### 6. Authentication & Access

- **SSH configuration** (check `/etc/ssh/sshd_config` and `/etc/ssh/sshd_config.d/`):
  - `PasswordAuthentication yes` — finding. SSH keys only is far safer.
  - `PermitRootLogin yes` — finding. `prohibit-password` is acceptable.
  - What authentication methods are permitted?
  - Is the SSH daemon itself up to date?
- **User accounts**:
  - List users with login shells from `/etc/passwd`. Are there accounts that should not exist or belong to people who have left?
  - Check `lastlog` for accounts that have never been used or have not logged in for a very long time.
  - Look at `/etc/shadow` (if readable) for accounts with no password expiry set.
- **Sudo configuration**: Read `/etc/sudoers` and `/etc/sudoers.d/*`. Watch for `NOPASSWD` on broad permissions, or `ALL=(ALL) ALL` granted to unexpected users or groups.
- **Authorised SSH keys**: Check `~/.ssh/authorized_keys` for every user with a login shell. Stale keys belonging to former staff or contractors are a very common finding.

### 7. Container Security

If Docker or Podman is present:

- **Running as root?** `docker inspect <container>` — check the `User` field. Containers running as root that do not need to be are a risk.
- **Image age**: `docker inspect <container>` — check the `Created` date of the image. Images older than 90 days likely have unpatched vulnerabilities in their base layers.
- **Secrets in environment variables**: `docker inspect <container>` — look through the `Env` array for anything that looks like a password, API key, token, or database connection string. Distinguish between how the secrets got there:
  - Passed via `-e` flags on the command line: higher risk — visible in `ps aux` output and shell history. Recommend switching to `--env-file`.
  - Passed via `--env-file`: standard practice — not visible in process listings, but still visible in `docker inspect`. Lower risk, but note that anyone with Docker access can see them.
  - In both cases the secrets end up in the container's metadata. The only way to fully hide them from `docker inspect` is to mount the secrets file as a read-only volume and have the application read it directly, or to use Docker Swarm secrets. For most setups, `--env-file` with sensible file permissions on the `.env` file is adequate — note this in the remediation rather than implying it is broken.
- **Port exposure**: Are container ports published to `0.0.0.0` when `127.0.0.1` would suffice?
- **Docker socket**: Is `/var/run/docker.sock` mounted into any container? This effectively grants root access to the host — flag it as high severity.

### 8. Filesystem & Secrets

- **Sensitive file permissions**: Check `/etc/shadow`, `/etc/gshadow`, SSH host keys, any `.env` files, database configuration files. These should not be world-readable.
- **Credentials in common places**: Look through `/etc/*.conf`, `/opt/*/config*`, `/home/*/.env`, `/root/.bash_history` (people sometimes paste passwords as command-line arguments, and they end up in history).
- **Private keys in unexpected places**: Search for `*.pem`, `*.key`, `id_rsa` files outside of expected locations. Keep the search scope practical — do not try to scan every byte of a multi-terabyte data volume.
- **Temp directories**: Glance at `/tmp` and `/var/tmp` for anything that looks out of place.
- **SUID/SGID binaries**: `find / -perm -4000 -o -perm -2000 -type f 2>/dev/null`. Compare against the expected set for the distro. Unexpected SUID binaries are a significant finding — they can be used for privilege escalation.

**Secret redaction rule**: When inspecting files that may contain credentials (`.env`, `.bash_history`, config files, private keys, `/etc/shadow`), report only the *presence*, *location*, and *permissions* of sensitive material — never quote actual passwords, tokens, key material, or password hashes in findings, database records, or report output. For example, report "`.env` at `/opt/myapp/.env` is world-readable and contains `DB_PASSWORD`" — not the password itself. This applies to all output: conversation text, database `findings` rows, and anything that ends up in HTML reports.

### 9. Scheduled Tasks

- System crontabs: `/etc/crontab`, `/etc/cron.d/*`, `/etc/cron.daily/*`, etc.
- Per-user crontabs: `crontab -l -u <user>` for each user with a login shell
- Systemd timers: `systemctl list-timers --all`

For each scheduled task, check:
- Does it run as root? Is that actually necessary?
- Does it download or execute anything from a remote URL? (supply chain risk — if that URL is compromised, so is this server)
- Are the scripts it calls writable by non-root users? (a non-root user could modify the script and it would run as root next time — privilege escalation)

### 10. Logging & Detection

Would anyone actually notice if this server were compromised?

- **Audit daemon**: Is `auditd` installed and running? Are there audit rules beyond the defaults? (`auditctl -l`)
- **Central logging**: Are logs being shipped somewhere? Check rsyslog or syslog-ng config for remote targets, or look for log shipping agents (filebeat, fluentd, promtail, etc.). A server whose logs only exist locally is a server where an attacker can cover their tracks.
- **Brute force protection**: Is `fail2ban` or equivalent installed and active? `fail2ban-client status` shows what jails are running and how many bans have occurred.
- **Jisc protective DNS** (JANET members): Check `/etc/resolv.conf` — are the nameservers Jisc's protective DNS service? If not, this is a low-effort win. Jisc's DNS blocks connections to known-malicious domains, which helps if the server is compromised and tries to call home.
- **Security agents**: Are Rapid7, OSSEC, Wazuh, CrowdStrike, or similar installed and running? Note their presence and whether they appear healthy (process running, recent log entries).

### 11. Follow Your Nose

If anything looks unusual or interesting during the checks above, dig deeper. Read the config files for services you do not recognise. Look at what is actually running inside docker containers. Check systemd unit files for custom services. Run `ss -tnp` to see what active network connections the server has right now — what is it talking to?

The above checklist covers the common ground, but every server is different. Use your judgement.

## Severity Classification

Classify each finding on this scale:

| Severity | Meaning | Examples | Timeframe |
|----------|---------|----------|-----------|
| **Critical** | Actively exploited or directly grants access | Package on the KEV list, exposed credentials, unauthenticated remote access | Fix today |
| **High** | Known CVE with high EPSS (>0.7), serious misconfiguration | Password SSH on a public-facing server, Docker socket mounted in container, no firewall | Fix this week |
| **Medium** | Moderate risk, pending security updates | EPSS 0.4–0.7 CVEs, overly broad sudo rules, unexpected SUID binaries | Plan it in |
| **Low** | Best practice, defence in depth | Enable unattended-upgrades, set up fail2ban, use Jisc protective DNS | When there is time |
| **Info** | Context, not a problem | Security agents running, OS version, notable but benign configuration | Record it |

## Recording Findings

Record everything to the database once discovery is complete.

1. Insert or update the `servers` row
2. Create a `security_scans` row to mark this scan
3. Record each discrete finding in `findings` with severity, category, plain-English detail, and suggested remediation
4. Record each package vulnerability in `package_vulns` with CVE ID, KEV match status, and EPSS score where available
5. Record each configuration check in `config_checks` as pass, fail, warn, or skip

Use `INSERT OR REPLACE` so that re-running the scan updates existing records rather than creating duplicates. This means the database tracks the current state, and repeated scans show whether things are improving.

## Output

The audience for these reports is experienced sysadmins and IT security managers. They are quick to dismiss AI-generated output that overstates, speculates, or pads findings. A single hyperbolic claim will make them distrust the entire report. Follow these principles:

- **State what you observed, not what you infer.** Say "459 packages pending, oldest security update is from deb12u3 to deb12u9" — not "this server has never been patched". If you do not have evidence for a claim, do not make it.
- **Qualify exploitability claims.** Do not say "any exploit will work". Say "the kernel is N versions behind and multiple CVEs in that range are on the KEV list". Let the reader draw the conclusion.
- **Cite your evidence for external lookups.** When reporting KEV or EPSS matches, note what you matched against (package name, version) and the date the catalog was fetched. This makes findings verifiable rather than something the reader has to take on trust.

Finish with a structured security report written for sysadmins, not security consultants.

### Traffic Light Summary

Start with a count of findings by severity:

> **2 critical · 5 high · 8 medium · 3 low · 4 info**

### Critical and High Findings

List each one with:
- What is wrong, in plain English
- Why it matters (what could actually happen)
- What to do about it (specific commands where possible)

### Be Specific About Duplicates and Redundancies

When flagging duplicates or redundancies of any kind — SSH keys, packages, firewall rules, cron entries — always include enough detail for the sysadmin to act without repeating the investigation. That means: which items are duplicated, where they are (file paths, line numbers), and which to keep or remove. "You have a duplicate SSH key" is not actionable. "Lines 3 and 17 in `/home/deploy/.ssh/authorized_keys` are identical (`ssh-ed25519 AAAA...Qx7f deploy@oldlaptop`) — remove one" is. The same principle applies to redundant packages (which versions, which paths), overlapping firewall rules, or duplicate cron jobs.

### Quick Wins

Things that can be fixed in minutes. Give the actual commands to run. Examples:
- "Run `dnf update --security` to clear the 12 pending security patches"
- "Add `PasswordAuthentication no` to `/etc/ssh/sshd_config` and restart sshd"
- "Set Jisc protective DNS in `/etc/resolv.conf`"

### What an Attacker Would See

Describe the attack path as a sequence of concrete steps, not a dramatic narrative. Each step should reference a specific finding from the report. Avoid sweeping claims about what "would" or "will" work — describe what is *exposed* and what *could* be attempted based on the evidence you gathered.

### Recommendations

Longer-term improvements worth planning: enabling automatic patching, centralising logs, tightening firewall rules, replacing old container images, and so on.

Write it like a report a colleague would actually read and act on — not a compliance document that gets filed and forgotten.

## Manager Analysis (for the dashboard report)

After completing the scan and recording findings to the database, write a brief manager-friendly summary to the `server_analysis` table. These tables may already exist — create them only if they don't:

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

CREATE TABLE IF NOT EXISTS fleet_analysis (
    id INTEGER PRIMARY KEY CHECK (id = 1),
    analysis TEXT,
    recommendations TEXT,
    updated_at TEXT DEFAULT (datetime('now'))
);
```

Insert or update the server's entry. Use `ON CONFLICT` to update only the columns this skill owns, so a prior server-explore scan's data is preserved. The `recommendations` and `security_recommendations` columns store JSON arrays as text:

```sql
INSERT INTO server_analysis (hostname, security_analysis, security_recommendations)
VALUES ('hostname',
    'A short paragraph summarising security posture for a manager audience',
    '["First recommendation", "Second recommendation"]')
ON CONFLICT(hostname) DO UPDATE SET
    security_analysis = excluded.security_analysis,
    security_recommendations = excluded.security_recommendations,
    updated_at = datetime('now');
```

For the **fleet-wide analysis** (only when scanning multiple servers in one session, or when the user asks for a fleet summary):

```sql
INSERT OR REPLACE INTO fleet_analysis (id, analysis, recommendations)
VALUES (1, 'Fleet-wide summary paragraph', '["First recommendation", "Second recommendation"]');
```

**Guidelines for writing the analysis:**

- Write for a manager who does not SSH into servers. No jargon, no CVE IDs, no command-line instructions. Plain English.
- **If a server is healthy, say so.** A clean bill of health is a finding too. "This server is well-maintained, patching is current, and there are no significant concerns" is a perfectly good analysis. Do not manufacture concerns to fill the space. Managers trust a report that occasionally says "this one's fine" far more than one that always finds fault.
- Focus on *what matters* and *what to do about it*, not on listing everything you checked.
- The fleet-wide analysis should identify patterns and systemic issues ("three servers have no firewall", "patching is inconsistent across the fleet") rather than repeating individual server findings.
- Fleet recommendations should be ranked by impact — what single action would improve the most servers?

## Save the Report

Once you have presented the findings, ask the user if they would like the report saved as a local markdown file. Suggest a filename based on the hostname and date, e.g. `security-report-elf-2026-04-11.md`. Save it to the current working directory unless the user specifies somewhere else.
