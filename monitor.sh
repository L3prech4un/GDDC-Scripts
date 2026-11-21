#!/usr/bin/env bash
# monitor.sh - lightweight blue-team watcher. Run in a spare terminal/tmux:  sudo ./monitor.sh [seconds]
# Compares against the baseline from 01_backup.sh and shouts when something changes:
# new users / UID-0 / password state, new listeners, new SUID files, changed /etc & webroot files,
# new cron/systemd units, new outbound connections, new processes in temp dirs, firewall tampering.
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; . "$DIR/lib/common.sh"; need_root
INT="${1:-30}"; B="$GDDC_HOME/baseline"
[ -d "$B" ] || { warn "no baseline - running 01_backup.sh first"; "$DIR/01_backup.sh" >/dev/null; }
ALERTLOG="$GDDC_HOME/alerts.log"
alert() { echo "${C_R}[ALERT $(date +%T)]${C_0} $*"; echo "$(date '+%F %T') $*" >>"$ALERTLOG"; command -v logger >/dev/null && logger -t gddc-alert "$*"; }
SEEN=$(mktemp); trap 'rm -f "$SEEN"' EXIT
once() { grep -qxF -- "$1" "$SEEN" && return 1; echo "$1" >>"$SEEN"; return 0; }   # alert only the first time per item
info "watching every ${INT}s - alerts also go to $ALERTLOG   (Ctrl-C to stop)"
while true; do
  # accounts
  diff <(cut -d: -f1,3,7 "$B/passwd" | sort) <(getent passwd | cut -d: -f1,3,7 | sort) | grep '^[<>]' | while read -r l; do once "pw:$l" && alert "passwd change: $l"; done
  awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd | while read -r u; do once "uid0:$u" && alert "UID-0 account appeared: $u"; done
  awk -F: '{print $1":"($2==""?"EMPTY":($2 ~ /^[!*]/?"LOCKED":"SET"))}' /etc/shadow | diff "$B/shadow.state" - | grep '^>' | while read -r l; do once "sh:$l" && alert "shadow state change: $l"; done
  # network
  ss -Htulnp 2>/dev/null | awk '{print $1,$5}' | sort -u | diff "$B/listeners" - | grep '^>' | while read -r l; do once "ls:$l" && alert "NEW LISTENER: ${l#> }  $(ss -Htulnp | grep -F "${l##* }" | awk '{print $7}' | head -1)"; done
  ss -Htnp state established 2>/dev/null | awk '{print $4" "$5" "$6}' | grep -vE '(172\.16\.|127\.0\.0\.1|\[::1\])' | while read -r l; do once "ext:$l" && alert "outbound/external connection: $l"; done
  # files
  find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | sort | diff "$B/suid" - | grep '^>' | while read -r l; do once "suid:$l" && alert "NEW SUID/SGID: ${l#> }"; done
  find /etc /usr/local /opt /root /var/spool/cron -xdev -type f -print0 2>/dev/null | xargs -0 sha256sum 2>/dev/null | sort -k2 | diff "$B/etc.sha256" - | grep '^>' | awk '{print $3}' | while read -r f; do once "etc:$f" && alert "file changed/new: $f"; done
  if [ -f "$B/www.sha256" ]; then
    find /var/www -type f -print0 2>/dev/null | xargs -0 sha256sum 2>/dev/null | sort -k2 | diff "$B/www.sha256" - | grep '^>' | awk '{print $3}' | while read -r f; do once "www:$f" && alert "WEB FILE changed/new: $f"; done
  fi
  # processes
  for p in /proc/[0-9]*; do e=$(readlink "$p/exe" 2>/dev/null) || continue
    case "$e" in *"(deleted)"*|/tmp/*|/dev/shm/*|/var/tmp/*) once "pe:$e:${p#/proc/}" && alert "process from temp/deleted binary: pid=${p#/proc/} $e";; esac; done
  ps -eo pid,user:12,args --no-headers | grep -E '\b(nc|ncat|socat)\b.*(-e|-c|exec)|bash -i|/dev/tcp/' | grep -v grep | while read -r l; do once "rs:$l" && alert "reverse-shell-like process: $l"; done
  # firewall
  if nft list table inet gddc >/dev/null 2>&1 || [ -f /etc/gddc/fw.v4 ]; then
    if have nft && ! nft list table inet gddc >/dev/null 2>&1 && [ -f /etc/gddc/fw.nft ]; then once "fw-gone:$(date +%H)" && alert "GDDC firewall table is GONE - reload: nft -f /etc/gddc/fw.nft"; fi
  fi
  # logins
  who | awk '{print $1,$2,$5}' | while read -r l; do once "who:$l" && info "login session: $l"; done
  sleep "$INT"
done
