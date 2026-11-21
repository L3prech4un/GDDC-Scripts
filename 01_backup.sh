#!/usr/bin/env bash
# 01_backup.sh - back up configs + take a baseline BEFORE changing anything.
# (File-level backups only. Do NOT revert VM snapshots - that is a penalty per the packet.)
# Usage: sudo ./01_backup.sh
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; . "$DIR/lib/common.sh"; need_root

hdr "Backing up configuration"
OUT="$GDDC_HOME/backup-$(hostname)-$TS.tar.gz"
PATHS=(/etc /root/.ssh /root/.bashrc /root/.profile /var/spool/cron /var/www /srv /home)
EXIST=(); for p in "${PATHS[@]}"; do [ -e "$p" ] && EXIST+=("$p"); done
tar --warning=no-file-changed -czf "$OUT" "${EXIST[@]}" 2>/dev/null
chmod 600 "$OUT"; ok "Config/web/home backup -> $OUT ($(du -h "$OUT" | cut -f1))"

hdr "Taking baseline (used by monitor.sh to spot changes)"
B="$GDDC_HOME/baseline"; mkdir -p "$B"; chmod 700 "$B"
cp /etc/passwd "$B/passwd"; cp /etc/group "$B/group"
awk -F: '{print $1":"($2==""?"EMPTY":($2 ~ /^[!*]/?"LOCKED":"SET"))}' /etc/shadow >"$B/shadow.state"
ss -Htulnp 2>/dev/null | awk '{print $1,$5}' | sort -u >"$B/listeners"
ps -eo user,comm --no-headers | sort -u >"$B/procs"
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | sort >"$B/suid"
{ find /etc /usr/local /opt /root /var/spool/cron -xdev -type f -print0 2>/dev/null | xargs -0 sha256sum 2>/dev/null; } | sort -k2 >"$B/etc.sha256"
[ -d /var/www ] && find /var/www -type f -print0 2>/dev/null | xargs -0 sha256sum 2>/dev/null | sort -k2 >"$B/www.sha256"
dpkg -l >"$B/dpkg.list" 2>/dev/null
iptables-save >"$B/iptables.rules" 2>/dev/null; nft list ruleset >"$B/nft.rules" 2>/dev/null
systemctl list-unit-files --state=enabled --no-pager >"$B/enabled.units" 2>/dev/null
ok "Baseline saved in $B"
echo; info "Backups live in $GDDC_HOME (root-only). Per-run file backups: $BACKUP_DIR"
