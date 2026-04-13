# Claude Server Explorer

Claude Code skills for poking around Linux servers, plus a reporting tool so the findings don't just bitrot in a terminal.

> **This is a proof of concept.** It grew out of ideas sparked by Anthropic's [Preparing your security program for AI-accelerated offense](https://claude.com/blog/preparing-your-security-program-for-ai-accelerated-offense) post, mixed with some thinking of our own about what a practical AI-assisted server audit might look like. Treat it as a starting point for your own work, not a finished production system. The checks are opinionated, the severity ratings are debatable, and your environment will have its own quirks. Fork it, gut it, rewrite the bits that don't fit — that's the point.

## What's in the box

`/server-explore` — SSHs into a server and figures out what's actually running on it. Services, containers, cron jobs, filesystems, interesting software. Everything goes into a local SQLite database. It's the "what does this box actually do?" audit.

`/security-explore` — The paranoid sibling. Patch gap analysis, CISA KEV cross-referencing, EPSS scoring, SSH hardening, firewall checks, container hygiene, credential exposure, logging coverage. Findings get severity ratings and land in the same database. The "should we be worried?" audit.

`/fleet-audit` — Give it a file of hostnames or just list them however you like, and it runs both skills across every server. Saves markdown and HTML reports, opens the fleet dashboard when it's done. You walk away, come back to a dashboard.

`report.py` — Turns the database into HTML you can actually show people. Fleet dashboard for management meetings, detailed per-server breakdowns for when someone asks awkward questions about a specific box.

## Prerequisites

- [Claude Code](https://claude.ai/code)
- SSH access to the servers you want to scan (key-based)
- [uv](https://docs.astral.sh/uv/) for the report generator
- Nothing to install on the servers themselves.

## Setup

```bash
git clone git@github.com:ohnotnow/claude-server-explorer.git
cd claude-server-explorer
```

The skills live in `.claude/skills/` and Claude Code picks them up automatically when you're in this directory.

## Usage

### Single server

Open Claude Code here and run a skill:

```
/server-explore user@hostname
/security-explore user@hostname
```

It SSHs in, runs its checks, and writes findings to `~/.server-inventory/inventory.db`. At the end it'll ask if you want a local markdown file too.

### Multiple servers

```
/fleet-audit servers.txt
/fleet-audit elf, cordelia, muffin
/fleet-audit can we just check elf and muffin?
```

Runs both scans for every server, saves reports, opens the dashboard. In `servers.txt`, one hostname per line -- lines starting with `#` are comments. Or just type the hostnames in whatever format makes sense for your ssh/dns/setup.

### Reports

Fleet dashboard (all servers):

```bash
uv run report.py
```

One specific server:

```bash
uv run report.py --server hostname
```

Both spit out a single HTML file you can open in a browser or email around.

```
Options:
  --server, -s    Detailed report for one server
  --db            Path to database (default: ~/.server-inventory/inventory.db)
  -o, --output    Output filename (default: auto-generated)
```

### Proxy support

External API lookups (CISA KEV catalogue, EPSS scores) run on your local machine, so they work regardless of the remote server's network access.

Package index refreshes (`apt update`, `dnf check-update`) still run on the remote server. If your servers sit behind private subnets (common in `.ac.uk` and other JANET-connected environments), their package managers may need a proxy. Most servers already have this configured, but if not, copy the example config and add your proxy URL:

```bash
cp .server-explorer.conf.example .server-explorer.conf
# then edit .server-explorer.conf and uncomment/set the proxy line
```

The skill will use this proxy for remote package index commands when direct connectivity fails.

## How it works

```
SSH into server ──> Run checks ──> SQLite database ──> HTML reports
```

One SQLite database holds everything. Re-scanning a server updates its records rather than duplicating them, so the reports always show the latest state.

Report templates are Jinja2 (`templates/`), so you can restyle things without touching Python.

## Customising

Skills are markdown files in `.claude/skills/`. Want to add a check or change a severity threshold? Edit the file.

Report templates are in `templates/` with CSS at `templates/css/styles.css`. The Python is just plumbing -- all the presentation lives in the templates.

## Locking it down -- the sysadmin starter pack

Some of the skills need `sudo` over SSH -- checking which process owns a port, reading `/etc/shadow`, inspecting firewall rules. The obvious first question is "what can it actually do on my box?"

Short answer: you create a dedicated user with a sudoers file that only permits specific read-only commands. No package installs, no service restarts, no file writes.

### 1. Create a `claude` user

```bash
# System account, no password, SSH key only
sudo useradd -r -m -s /bin/bash claude
sudo passwd -l claude  # lock the password -- key-only access
sudo mkdir -p /home/claude/.ssh
sudo chmod 700 /home/claude/.ssh

# Add the public key that Claude Code will use to connect.
# Basic version -- key only:
sudo tee /home/claude/.ssh/authorized_keys <<< "ssh-ed25519 AAAA... claude-code"

# Or the locked-down version with the command wrapper (see step 7):
# sudo tee /home/claude/.ssh/authorized_keys <<< 'command="/usr/local/bin/claude-validate.sh",no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding ssh-ed25519 AAAA... claude-code'
sudo chmod 600 /home/claude/.ssh/authorized_keys
sudo chown -R claude:claude /home/claude/.ssh
```

You do need `/bin/bash` here, not `/usr/sbin/nologin` -- sshd uses the login shell to run remote commands. The locked password and key-only access are what keep things secure; there is no password to brute force.

### 2. Install the sudoers file

There is a ready-made sudoers file in [`examples/sudoers-claude`](examples/sudoers-claude) with comments on every entry.

```bash
sudo cp examples/sudoers-claude /etc/sudoers.d/claude
sudo chmod 0440 /etc/sudoers.d/claude
sudo visudo -c   # always validate!
```

### 3. What it allows

Commands are grouped by purpose:

| Category | What it does | Example commands |
|----------|-------------|-----------------|
| Network | See which process owns each port | `ss -tlnp`, `ss -ulnp` |
| Packages | Refresh package index (not install) | `apt update`, `apt list --upgradable` |
| Firewall | Read firewall rules | `iptables -L -n`, `nft list ruleset` |
| Auth/access | Check for stale accounts, weak sudo rules | `cat /etc/shadow`, `cat /etc/sudoers` |
| Docker | Inspect containers (read-only) | `docker ps`, `docker inspect` |
| Files | Find SUID binaries and exposed secrets | `find / -perm -4000` |
| Cron | Read scheduled jobs | `crontab -l -u <user>` |
| Security tools | Check if auditd/fail2ban are running | `auditctl -l`, `fail2ban-client status` |

### 4. What it can't do

Equally important -- the sudoers file deliberately blocks:

- Package management (`apt install`, `apt remove`, `dnf install`)
- Service control (`systemctl start/stop/restart`)
- File modification (`rm`, `mv`, `cp`, `tee`, `chmod`, `chown`)
- User management (`useradd`, `userdel`, `usermod`)
- Mounting filesystems
- Rebooting the server
- Arbitrary root commands

### 5. The `find` question

The one entry worth a second look is `sudo find`. The skills use it to hunt for SUID binaries and exposed `.env` files, but `find -exec` can run arbitrary commands as root.

If that makes you uncomfortable, just delete the line from the sudoers file. The skill notices the missing permission, skips the check, and notes it was skipped. Everything else carries on.

### 6. Test it

Try the user out before pointing it at anything you care about:

```bash
# These should work
ssh claude@yourserver sudo ss -tlnp
ssh claude@yourserver sudo cat /etc/shadow
ssh claude@yourserver sudo docker ps

# These should be denied
ssh claude@yourserver sudo apt install curl
ssh claude@yourserver sudo systemctl restart nginx
ssh claude@yourserver sudo rm -rf /
```

### 7. Belt and braces -- the SSH command wrapper (optional)

The sudoers file controls what `sudo` can do, but the claude user can still run non-sudo commands freely (listing directories, reading files, etc.). If you want a hard limit on *every* command -- not just the privileged ones -- there is a wrapper script for that.

It uses the `command=` option in `authorized_keys`. When sshd sees a key with `command="/some/script"`, it runs that script instead of whatever the remote side asked for. The original command goes into `$SSH_ORIGINAL_COMMAND`, so the script can inspect it and decide whether to let it through.

Install the wrapper:

```bash
sudo cp examples/claude-validate.sh /usr/local/bin/claude-validate.sh
sudo chmod 755 /usr/local/bin/claude-validate.sh
```

Then update `authorized_keys` to use it:

```
command="/usr/local/bin/claude-validate.sh",no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding ssh-ed25519 AAAA... claude-code
```

The `no-*` options stop the key being used for tunnelling, getting a terminal, or forwarding agents -- even if someone nicks the private key.

The wrapper itself ([`examples/claude-validate.sh`](examples/claude-validate.sh)) does three things:

1. Allowlists command names -- only binaries the skills actually use (`ss`, `cat`, `docker`, `systemctl`, etc.) are permitted. Anything else is rejected. Notably, `curl` and `python3` are **not** on the list -- external API lookups (KEV, EPSS) run on the local machine, not the remote server.
2. Denylists dangerous subcommands -- `apt` might be allowed, but `apt install` is not. Same for `systemctl restart`, `docker run`, `rm`, `chmod`, etc.
3. Logs everything -- both allowed and denied commands go to syslog tagged `claude-ssh`, so you have a full audit trail.

This is best-effort shell parsing. It handles the compound commands the skills construct (pipes, chains, semicolons), but shell syntax has a lot of dark corners and it will not catch every edge case. That is fine -- it is an outer fence. The sudoers file underneath still governs what `sudo` can do.

With both layers active, a command has to pass two checks:

```
ssh claude@server "sudo ss -tlnp"
  |
  authorized_keys command= triggers the wrapper
  |
  wrapper checks: is "sudo" allowed? is "ss" allowed? any denied patterns? -> OK
  |
  bash runs the command
  |
  sudo checks: is "ss" in the sudoers file for claude? -> OK
  |
  ss -tlnp runs
```

### RHEL / Rocky / Alma notes

The example sudoers uses Debian/Ubuntu paths. On RHEL-family systems, run `which ss`, `which iptables`, etc. and adjust accordingly. The commands are the same.

## Scaling up

Once you've scanned a few servers it will become a total pita unless you have decent ssh keys/access/whatever set up. If every server has different credentials and/or auth method, each new scan means fscking around in 1Password or emailing someone to get access.

A solution might be shared SSH keys in a 1Password vault (or setting up something like HashiCorp Vault). 1Password's cli SSH agent serves the key automagically.

## Licence

Copyright (c) 2026 ohnotnow. Licensed under the GNU AGPL-3.0 — see [LICENSE](LICENSE).
