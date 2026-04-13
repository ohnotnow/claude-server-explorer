#!/bin/bash
# /usr/local/bin/claude-validate.sh
#
# SSH command validator for the claude user. Set as command= in authorized_keys:
#
#   command="/usr/local/bin/claude-validate.sh",no-pty,no-port-forwarding,no-X11-forwarding,no-agent-forwarding ssh-ed25519 AAAA... claude-code
#
# Every SSH command is checked against an allowlist before execution.
# Denied commands are logged to syslog and rejected.
#
# Install:
#   sudo cp claude-validate.sh /usr/local/bin/claude-validate.sh
#   sudo chmod 755 /usr/local/bin/claude-validate.sh

set -euo pipefail

CMD="$SSH_ORIGINAL_COMMAND"

# --- No interactive sessions ---
if [ -z "$CMD" ]; then
    echo "Interactive sessions not permitted for this account." >&2
    exit 1
fi

# --- Allowed commands ---
# These are the binaries the server-explore and security-explore skills actually use.
# Add or remove as needed. Only the basename matters -- /usr/bin/cat and cat both match.
ALLOWED_COMMANDS=(
    # System identity
    hostname uname uptime nproc id whoami

    # Reading files and directories
    cat ls head tail wc stat file du

    # Searching and filtering
    grep find sort uniq tr cut paste bc

    # Networking
    ss netstat ip

    # Services and scheduling
    systemctl crontab journalctl lastlog

    # Package queries
    apt dpkg dpkg-query dnf yum apk

    # Docker (read-only -- write subcommands blocked below)
    docker

    # Firewall
    iptables nft ufw firewall-cmd

    # Security tools
    auditctl fail2ban-client wg

    # SSH version checks
    ssh sshd

    # Misc
    echo which free df

    # sudo itself (what it can run is controlled by the sudoers file)
    sudo

    # transmission (only if you use it)
    transmission-remote
)

# --- Dangerous operations ---
# Even if the command name is allowed, these specific subcommands are blocked.
# Patterns are extended regex matched against the full command string.
DENIED_PATTERNS=(
    # Package installation/removal
    'apt\s+(install|remove|purge|autoremove|full-upgrade|dist-upgrade)'
    'apt-get\s+(install|remove|purge|autoremove|full-upgrade|dist-upgrade)'
    'dnf\s+(install|remove|erase|upgrade|downgrade)'
    'yum\s+(install|remove|erase|upgrade|downgrade)'
    'apk\s+(add|del)'

    # Service modification
    'systemctl\s+(start|stop|restart|reload|enable|disable|mask|unmask|daemon-reload)'

    # Docker write operations
    'docker\s+(run|exec|rm|rmi|stop|kill|pull|push|build|create|commit|tag|load|save|prune|cp)'

    # User/permission modification
    'useradd|userdel|usermod|groupadd|groupdel|passwd|chpasswd'
    'chmod|chown|chgrp'

    # File destruction
    '\brm\s'
    '\brmdir\s'
    '\bmkdir\s'
    '\bmv\s'
    '\bcp\s'
    'mkfs|fdisk|parted'

    # System control
    'reboot|shutdown|halt|poweroff|init\s+[0-6]'
    'mount\s|umount\s'

    # Writing to files (but allow /dev/null for stderr suppression)
    '>[^/&]|>>[^/&]'

    # Network tools that could be used offensively
    '\bwget\s'
    '\bnc\s|\bncat\s|\bnetcat\s'
    '\bdd\s'
)

# --- Validation ---

log_denied() {
    logger -t claude-ssh "DENIED [${SSH_CLIENT%% *}]: $1 -- $CMD"
    echo "Command not permitted: $1" >&2
    exit 1
}

log_allowed() {
    logger -t claude-ssh "ALLOWED [${SSH_CLIENT%% *}]: $CMD"
}

# Check denied patterns first (these override the allowlist)
for pattern in "${DENIED_PATTERNS[@]}"; do
    if echo "$CMD" | grep -qE "$pattern"; then
        log_denied "matches denied pattern: $pattern"
    fi
done

# Build a regex of allowed command names for matching
allowed_re=""
for cmd in "${ALLOWED_COMMANDS[@]}"; do
    [ -n "$allowed_re" ] && allowed_re="$allowed_re|"
    allowed_re="$allowed_re$cmd"
done

# Extract command-position words from the compound command.
# These are the first word after: start of string, |, ;, &&, ||, $( or `
# We strip sudo since it's just a prefix -- the real command follows it.
# This is best-effort parsing -- shell syntax is complex. The sudoers file
# is the real safety net for anything running under sudo.
cmd_words=$(
    echo "$CMD" \
    | sed 's/sudo\s\+//g' \
    | grep -oE '(^|[|;&(])\s*/?\S+' \
    | sed 's/^[|;&( ]*//' \
    | sed 's|.*/||' \
    | sort -u
)

for word in $cmd_words; do
    # Skip shell builtins and constructs that appear as "commands"
    case "$word" in
        for|do|done|if|then|else|fi|while|until|"case"|"esac"|in) continue ;;
        echo|test|true|false|"["|"[[") continue ;;
        2\>*|/dev/null) continue ;;
        "") continue ;;
    esac

    if ! echo "$word" | grep -qE "^($allowed_re)$"; then
        log_denied "unknown command: $word"
    fi
done

# --- Execute ---
log_allowed
exec /bin/bash -c "$CMD"
