#!/usr/bin/env bash
# 11_integrity.sh - rootkit / trojaned-binary hunt that 02_audit.sh does not do:
#   hidden PIDs, hidden listeners (ss vs /proc/net/tcp), PATH-shadowed or scripted system tools, LD_PRELOAD in live processes,
#   odd kernel modules, full package verification, optional repair by reinstalling modified packages.
# Env: REPAIR=1 (apt-get --reinstall packages whose binaries were modified; needs working apt)  FULL=1 (verify every package)  RUN_RK=1 (run rkhunter/chkrootkit if installed)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; . "$DIR/lib/common.sh"; need_root
REPORT="$GDDC_HOME/integrity-$(hostname)-$TS.txt"; exec > >(tee -a "$REPORT") 2>&1
F=0; flag() { F=$((F+1)); echo "${C_R}[FLAG]${C_0} $*"; }

hdr "Hidden processes (in /proc but not in ps)"
for pass in 1 2; do
  comm -13 <(ps -e -o pid= | tr -d ' ' | sort) <(ls /proc | grep -E '^[0-9]+$' | sort) | while read -r p; do [ -r "/proc/$p/cmdline" ] && kill -0 "$p" 2>/dev/null && echo "$p"; done >"/tmp/.gddc-h$pass"; sleep 1
done
comm -12 <(sort /tmp/.gddc-h1) <(sort /tmp/.gddc-h2) | while read -r p; do flag "pid $p visible in /proc but hidden from ps: $(tr '\0' ' ' </proc/$p/cmdline | cut -c1-100)"; done; rm -f /tmp/.gddc-h1 /tmp/.gddc-h2

hdr "Hidden listeners (/proc/net/tcp vs ss)"
procp=$( { cat /proc/net/tcp /proc/net/tcp6; } 2>/dev/null | while read -r _ la _ st _; do [ "$st" = 0A ] && printf '%d\n' "0x${la##*:}"; done | sort -un)
ssp=$(ss -Htln 2>/dev/null | awk '{print $4}' | sed 's/.*://' | sort -un)
for p in $(comm -23 <(echo "$procp") <(echo "$ssp")); do flag "tcp/$p listening per /proc/net/tcp but missing from ss (tampered ss?)"; done

hdr "System tools: shadowed, scripted, or not from a package"
for b in ps ss netstat ls lsof find top w who last ssh sshd sudo su login passwd cat grep ip systemctl journalctl chmod chown mount kill; do
  mapfile -t paths < <(type -a "$b" 2>/dev/null | awk '{print $NF}' | sort -u); [ ${#paths[@]} -gt 1 ] && for x in "${paths[@]}"; do case "$x" in /usr/local/*|/opt/*|/tmp/*|/home/*|/var/*) flag "$b is shadowed by $x";; esac; done
  p=$(command -v "$b" 2>/dev/null) || continue; p=$(readlink -f "$p")
  [ "$(head -c2 "$p" 2>/dev/null)" = '#!' ] && case "$b" in ls|ps|ss|cat|grep|find|chmod|chown|kill|mount|w|who|last|sudo|su|login|passwd|sshd|ssh) flag "$p is a SCRIPT, not a binary";; esac
  [ -n "$(nonpkg "$p")" ] && flag "$p not owned by any package"
done
for d in /usr/local/bin /usr/local/sbin; do ls -A "$d" 2>/dev/null | head -20 | sed "s|^|   $d/|"; done

hdr "LD_PRELOAD / LD_LIBRARY_PATH in live processes"
for p in /proc/[0-9]*; do tr '\0' '\n' <"$p/environ" 2>/dev/null | grep -qE '^LD_(PRELOAD|LIBRARY_PATH)=' && flag "pid ${p#/proc/} has LD_* in environment: $(tr '\0' '\n' <"$p/environ" | grep -E '^LD_' | head -1)"; done
[ -s /etc/ld.so.preload ] && flag "/etc/ld.so.preload: $(cat /etc/ld.so.preload)"

hdr "Kernel modules"
lsmod | awk 'NR>1{print $1}' | while read -r m; do mp=$(modinfo -n "$m" 2>/dev/null); case "$mp" in ""|/tmp/*|/dev/shm/*|/home/*|/var/*|/root/*) flag "module $m has odd/missing path: '${mp:-none}'";; esac; done
[ -r /proc/sys/kernel/tainted ] && echo "kernel taint: $(cat /proc/sys/kernel/tainted) (0 is clean; 4096/8192 = out-of-tree/unsigned module)"

hdr "Package verification"
if have debsums && [ "${FULL:-0}" = 1 ]; then debsums -c 2>/dev/null | while read -r l; do flag "debsums mismatch: $l"; done
elif have dpkg; then
  if [ "${FULL:-0}" = 1 ]; then dpkg -V 2>/dev/null; else dpkg -V $(dpkg-query -W -f='${Package}\n' | grep -E '^(coreutils|procps|iproute2|net-tools|openssh-.*|sudo|passwd|login|util-linux|bash|libpam.*|findutils|grep|libc-bin|libc6|systemd|apache2.*|nginx.*|vsftpd|samba.*|lsof|openssl|php.*-cli|mysql-server.*|mariadb-server.*|dash|diffutils|sed|gawk|mawk)$') 2>/dev/null; fi | grep -E '^..5' | grep -vE '^..5.......\s+c ' >/tmp/.gddc-mod
  while read -r l; do flag "modified package file: $l"; done </tmp/.gddc-mod
  if [ "${REPAIR:-0}" = 1 ] && [ -s /tmp/.gddc-mod ]; then
    pk=$(awk '{print $NF}' /tmp/.gddc-mod | while read -r f; do dpkg -S "$f" 2>/dev/null | cut -d: -f1; done | sort -u | tr '\n' ' '); info "reinstalling: $pk"
    DEBIAN_FRONTEND=noninteractive timeout 240 apt-get install --reinstall -y $pk 2>&1 | tail -5 || warn "apt failed (offline / dead repo?) - copy the binary from a clean identical host or the VM's package cache in /var/cache/apt/archives"
  fi; rm -f /tmp/.gddc-mod
fi

if [ "${RUN_RK:-0}" = 1 ]; then hdr "rkhunter / chkrootkit"
  have rkhunter && rkhunter --check --sk --rwo 2>/dev/null | head -40; have chkrootkit && chkrootkit 2>/dev/null | grep -Ei 'infected|vulnerable|suspect' ; have rkhunter || have chkrootkit || info "neither installed (apt install rkhunter chkrootkit, if apt works)"
fi
hdr "SUMMARY"; echo "[FLAG] items: $F   report: $REPORT"
echo "If tools like ps/ss were tampered with, use busybox or /proc directly, and reinstall the package (REPAIR=1)."
