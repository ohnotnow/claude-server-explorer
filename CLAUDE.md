# Claude Server Explorer

## SSH Commands Must Run Sequentially

**Do not run SSH commands as parallel Bash tool calls.** When multiple Bash calls run in parallel and any one exits non-zero, all the others are cancelled immediately. SSH commands frequently return non-zero exit codes even when they produce useful output (e.g. `grep` finding nothing, `dpkg-query` with no match, `apt list` writing to stderr). This causes repeated cancellations, wasted work, and noisy error output.

Run each `ssh <host> <command>` as its own sequential Bash call. It is slower but reliable. Local commands (sqlite3, file reads, etc.) can still be parallelised safely.
