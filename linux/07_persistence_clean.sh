#!/usr/bin/env bash
# 07_persistence_clean.sh - REMEDIATION counterpart to 02_audit.sh (which only reports).
# Moves suspicious items to a quarantine dir (NEVER deletes) and strips malicious lines (file backed up first).
# Asks y/N per item unless YES=1.   Run 02_audit.sh first and read its [FLAG]s.
# Env: YES=1  DRY_RUN=1  SKIP="cron units hooks shellrc suid temp procs"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; . "$DIR/lib/common.sh"; need_root
Q="$GDDC_HOME/quarantine-persist/$TS"; mkdir -p "$Q"; chmod 700 "$Q"
SUSP_RE='(/dev/tcp/|/dev/udp/|nc +-[a-z]*e|ncat |bash +-i|sh +-i|mkfifo|socat |python[0-9.]* .*socket|perl .*socket|ruby .*socket|(curl|wget)[^|;]*\|[[:space:]]*(ba)?sh|base64 +-d|eval .*(base64|curl|wget)|LD_PRELOAD|alias +(sudo|ps|ss|netstat|cat|su|ssh)=|history +-c|HISTFILE=/dev/null)'
skip() { echo " ${SKIP:-} " | grep -q " $1 "; }
ask() { [ "${YES:-0}" = 1 ] && return 0; [ -t 0 ] || return 1; local a; read -r -p "     quarantine/fix this? [y/N] " a; [[ "$a" =~ ^[yY] ]]; }
quar() { local f=$1; [ -e "$f" ] || return 0; run chattr -ia "$f" 2>/dev/null; mkdir -p "$Q$(dirname "$f")"; run mv "$f" "$Q$f" && ok "quarantined $f -> $Q$f"; }
strip_lines() { local f=$1; [ -f "$f" ] || return 0; grep -qE "$SUSP_RE" "$f" 2>/dev/null || return 0
  warn "suspicious lines in $f:"; grep -nE "$SUSP_RE" "$f" | cut -c1-200 | sed 's/^/     /'
  if ask; then backup_file "$f"; run chattr -ia "$f" 2>/dev/null; [ "$DRY_RUN" = 1 ] || sed -i -E "\#${SUSP_RE}#d" "$f"; ok "removed lines from $f (backup in $BACKUP_DIR)"; fi; }

if ! skip cron; then hdr "cron / at"
  mapfile -t L < <(nonpkg /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*)
  for f in "${L[@]}"; do [ -f "$f" ] || continue; warn "cron script not owned by a package: $f"; head -5 "$f" | cut -c1-160 | sed 's/^/     /'; ask && quar "$f"; done
  for f in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* /var/spool/cron/*; do [ -f "$f" ] && strip_lines "$f"; done
  for f in /var/spool/cron/crontabs/* /var/spool/cron/*; do [ -f "$f" ] && [ "$(basename "$f")" != root ] && [ -n "$(grep -vE '^\s*(#|$)' "$f")" ] && warn "non-root crontab has entries: $f"; done
  have atq && for j in $(atq 2>/dev/null | awk '{print $1}'); do warn "at job $j pending"; ask && run atrm "$j"; done
fi

if ! skip units; then hdr "systemd units"
  mapfile -t U < <(find /etc/systemd/system /usr/lib/systemd/system -maxdepth 2 -type f \( -name '*.service' -o -name '*.timer' -o -name '*.socket' \) 2>/dev/null | sort -u)
  for f in "${U[@]}"; do n=$(basename "$f"); [ "$n" = gddc-firewall.service ] && continue
    if [ -n "$(nonpkg "$f")" ] || grep -qE '^Exec(Start|StartPre|StartPost)=.*(/tmp/|/dev/shm|/var/tmp|/home/|bash -c|sh -c|nc |ncat|socat|curl|wget|base64)' "$f"; then
      warn "suspicious unit: $f"; grep -E '^Exec' "$f" | cut -c1-160 | sed 's/^/     /'
      if ask; then run systemctl disable --now "$n" >/dev/null 2>&1; quar "$f"; run systemctl daemon-reload; fi
    fi; done
fi

if ! skip hooks; then hdr "boot / login / network hooks not owned by a package"
  [ -f /etc/rc.local ] && strip_lines /etc/rc.local
  mapfile -t H < <(nonpkg /etc/init.d/* /etc/profile.d/* /etc/update-motd.d/* /etc/apt/apt.conf.d/* /etc/network/if-up.d/* /etc/network/if-pre-up.d/* /etc/NetworkManager/dispatcher.d/* /etc/udev/rules.d/* /etc/xdg/autostart/* /etc/ld.so.conf.d/*)
  for f in "${H[@]}"; do [ -f "$f" ] || continue; warn "hook not owned by a package: $f"; head -4 "$f" | cut -c1-160 | sed 's/^/     /'; ask && quar "$f"; done
  grep -rnE 'Pre-Invoke|Post-Invoke' /etc/apt/apt.conf.d/ 2>/dev/null | grep -v 'ubuntu-advantage\|update-notifier\|motd\|dpkg-compat' | while read -r l; do warn "apt hook (edit by hand): $l"; done
fi

if ! skip shellrc; then hdr "shell startup files"
  for f in /etc/profile /etc/bash.bashrc /etc/environment /root/.bashrc /root/.profile /root/.bash_login /root/.bash_logout /home/*/.bashrc /home/*/.profile /home/*/.bash_profile /home/*/.bash_logout; do strip_lines "$f"; done
fi

if ! skip suid; then hdr "SUID/SGID abuse"
  GTFO='^(bash|sh|dash|zsh|ksh|python[0-9.]*|perl|ruby|node|php|lua|find|vim|vi|nano|less|more|awk|gawk|nmap|tcpdump|env|cp|mv|tar|zip|unzip|base64|xxd|systemctl|docker|gdb|strace|tee|dd|busybox|ed|ftp|socat|nc|ncat|openssl|rsync|make|git|man|time|timeout|nice)$'
  mapfile -t S < <(find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null)
  for f in "${S[@]}"; do b=$(basename "$f")
    if echo "$b" | grep -qE "$GTFO" || [ -n "$(nonpkg "$f")" ]; then warn "SUID/SGID: $f"; if ask; then run chmod u-s,g-s "$f" && ok "stripped SUID/SGID bit from $f"; fi; fi; done
fi

if ! skip temp; then hdr "temp-dir executables / hidden files"
  mapfile -t T < <(find /tmp /var/tmp /dev/shm -xdev \( -name 'systemd-private-*' -o -name '.X11-unix' -o -name '.ICE-unix' -o -name '.font-unix' -o -name '.XIM-unix' -o -name '.Test-unix' \) -prune -o -type f \( -perm /111 -o -name '.*' \) -print 2>/dev/null)
  for f in "${T[@]}"; do warn "temp file: $f ($(file -b "$f" 2>/dev/null | cut -c1-60))"; ask && quar "$f"; done
fi

if ! skip procs; then hdr "suspicious processes"
  for p in /proc/[0-9]*; do pid=${p#/proc/}; [ "$pid" = $$ ] && continue; e=$(readlink "$p/exe" 2>/dev/null) || continue
    case "$e" in *"(deleted)"*|/tmp/*|/dev/shm/*|/var/tmp/*) warn "pid $pid runs from $e: $(tr '\0' ' ' <"$p/cmdline" 2>/dev/null | cut -c1-120)"; ask && run kill -9 "$pid";; esac; done
  ps -eo pid,user:12,args --no-headers | grep -E '\b(nc|ncat|socat)\b.*(-e|-c|exec)|bash -i|/dev/tcp/' | grep -v grep | while read -r pid rest; do [ "$pid" = $$ ] && continue; warn "reverse-shell-like: $pid $rest" ; done
fi
ok "Persistence cleanup finished. Quarantine: $Q   (restore with: mv \"$Q/<path>\" /<path>)"
warn "Re-run 02_audit.sh afterwards, then restart anything you stopped that a scored service needs."
