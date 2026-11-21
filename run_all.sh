#!/usr/bin/env bash
# run_all.sh <web|files|board> - the whole Linux playbook in the safe order.
#   sudo ./run_all.sh web          (add  DRY_RUN=1  to preview)
# Order: backup -> audit (read-only) -> accounts -> ssh -> base -> role-specific -> firewall (with rollback) -> verify
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; . "$DIR/lib/common.sh"; need_root
ROLE="${1:-}"; case "$ROLE" in web|files|board) ;; *) echo "usage: sudo $0 <web|files|board>"; exit 1;; esac
export TS GDDC_HOME
pause() { [ -t 0 ] && [ "${YES:-0}" != 1 ] && read -r -p "$1 [ENTER to continue, Ctrl-C to stop] "; }
"$DIR/01_backup.sh";                         pause "Backup done."
"$DIR/02_audit.sh" | tail -15;               pause "Audit done (full report in $GDDC_HOME). Read the [FLAG]s."
"$DIR/03_accounts.sh";                       pause "Share the new passwords with the team, then continue."
"$DIR/04_ssh.sh";                            pause "Open a SECOND SSH session to test, then continue."
"$DIR/05_base_hardening.sh"
"$DIR/roles/$ROLE.sh"
"$DIR/06_firewall.sh" "$ROLE"
"$DIR/verify.sh" "$ROLE"
echo; ok "Finished. Start the watcher in another terminal:  sudo $DIR/monitor.sh"
