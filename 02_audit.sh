#!/usr/bin/env bash
# 02_audit.sh - READ-ONLY hunt for persistence / misconfig. Changes nothing.
# Output is also saved to /root/gddc/audit-<host>-<ts>.txt . Look for lines starting with [FLAG].
# Env: FULL=1 verify ALL packages (slow), RECENT_DAYS=3, EXPECT_PORTS="22 80 443 21 139 445"
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; . "$DIR/lib/common.sh"; need_root
REPORT="$GDDC_HOME/audit-$(hostname)-$TS.txt"
exec > >(tee -a "$REPORT") 2>&1
RECENT_DAYS="${RECENT_DAYS:-3}"
EXPECT_PORTS="${EXPECT_PORTS:-22 80 443 21 139 445}"
FLAGS=0
flag() { FLAGS=$((FLAGS+1)); echo "${C_R}[FLAG]${C_0} $*"; }
sec()  { echo; echo "${C_B}######## $* ########${C_0}"; }
SUSP_RE='(/dev/tcp/|/dev/udp/|nc +-[a-z]*e|ncat |bash +-i|sh +-i|mkfifo|socat |python[0-9.]* .*socket|perl .*socket|ruby .*socket|(curl|wget)[^|;]*\|[[:space:]]*(ba)?sh|base64 +-d|eval .*(base64|curl|wget)|LD_PRELOAD|alias +(sudo|ps|ss|netstat|cat|su|ssh)=|history +-c|HISTFILE=/dev/null)'

sec "System"; hostname; uname -a; uptime; echo "Date: $(date)"; who

sec "Accounts: UID 0, empty passwords, system accounts with shells"
awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd | while read -r u; do flag "extra UID-0 account: $u"; done
awk -F: '$2==""{print $1}' /etc/shadow | while read -r u; do flag "EMPTY password: $u"; done
getent passwd | awk -F: '$3<1000 && $1!="root" && $7 ~ /(bash|zsh|ksh|fish|\/sh|dash)$/ {print $1" ("$7")"}' | while read -r l; do flag "system account has login shell: $l"; done
echo "-- login-capable accounts:"
getent passwd | awk -F: '$7!="" && $7 !~ /(nologin|false)$/ {printf "  %-16s uid=%-6s home=%-22s %s\n",$1,$3,$6,$7}'
echo "-- not in scored list but UID>=1000 (ask White/Black team before removing):"
getent passwd | awk -F: '$3>=1000 && $3<60000{print $1}' | while read -r u; do is_scored "$u" || echo "  $u"; done

sec "sudo / privileged groups"
grep -rhvE '^\s*(#|$|Defaults)' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | sed 's/^/  /'
grep -rE 'NOPASSWD' /etc/sudoers /etc/sudoers.d/ 2>/dev/null | while read -r l; do flag "NOPASSWD sudo rule: $l"; done
for g in sudo wheel admin adm docker lxd disk shadow root; do getent group "$g" | awk -F: '$4!=""{print "  group "$1": "$4}'; done

sec "SSH authorized_keys / sshd config tricks"
while read -r f; do [ -s "$f" ] && { flag "authorized_keys present: $f"; awk '{print "     " $1, substr($2,1,20) "...", $3}' "$f"; }; done \
  < <(find / -xdev \( -name 'authorized_keys' -o -name 'authorized_keys2' \) -type f 2>/dev/null)
[ -e /etc/ssh/sshrc ] && flag "/etc/ssh/sshrc exists (runs on every login)"
find /root /home -maxdepth 3 -name rc -path '*/.ssh/*' 2>/dev/null | while read -r f; do flag "per-user ssh rc file exists: $f"; done
echo "-- effective sshd settings:"
sshd -T 2>/dev/null | grep -Ei '^(port|permitrootlogin|passwordauthentication|permitemptypasswords|pubkeyauthentication|authorizedkeysfile|authorizedkeyscommand|forcecommand|permituserenvironment|allowusers|denyusers|gatewayports|allowtcpforwarding|usepam) ' | sed 's/^/  /'
grep -nEi '^\s*(Match|ForceCommand|AuthorizedKeysCommand|AuthorizedKeysFile|PermitUserEnvironment|PermitEmptyPasswords)' /etc/ssh/sshd_config /etc/ssh/sshd_config.d/* 2>/dev/null | while read -r l; do flag "sshd directive to review: $l"; done

sec "Cron / at / systemd timers"
for f in /etc/crontab /etc/cron.d/* /var/spool/cron/crontabs/* /var/spool/cron/*; do
  [ -f "$f" ] || continue; c=$(grep -vE '^\s*(#|$|SHELL=|PATH=|MAILTO=)' "$f" 2>/dev/null); [ -n "$c" ] && { echo "--- $f"; echo "$c" | sed 's/^/   /'; }
done
for f in $(nonpkg /etc/cron.d/* /etc/cron.hourly/* /etc/cron.daily/* /etc/cron.weekly/* /etc/cron.monthly/*); do flag "cron script not owned by any package: $f"; done
have atq && [ -n "$(atq 2>/dev/null)" ] && flag "pending at jobs: $(atq | tr '\n' ';')"
systemctl list-timers --all --no-pager 2>/dev/null | head -25

sec "systemd units / init / profile hooks not owned by packages"
for f in $(find /etc/systemd/system /usr/lib/systemd/system -maxdepth 2 -type f \( -name '*.service' -o -name '*.timer' -o -name '*.socket' \) 2>/dev/null | sort -u); do
  if [ -n "$(nonpkg "$f")" ]; then flag "unit not owned by a package: $f"; grep -E '^(ExecStart|ExecStartPre|ExecStartPost)' "$f" | sed 's/^/       /'; fi
done
grep -rlE '^Exec(Start|StartPre|StartPost)=.*(/tmp/|/dev/shm|/var/tmp|/home/|bash -c|sh -c|nc |ncat|socat|curl|wget|base64)' /etc/systemd /usr/lib/systemd /lib/systemd 2>/dev/null | while read -r f; do flag "unit with suspicious ExecStart: $f"; done
for f in $(nonpkg /etc/rc.local /etc/init.d/* /etc/profile.d/* /etc/update-motd.d/* /etc/apt/apt.conf.d/* /etc/network/if-up.d/* /etc/network/if-pre-up.d/* /etc/NetworkManager/dispatcher.d/* /etc/udev/rules.d/* /etc/xdg/autostart/*); do
  [ -f "$f" ] && flag "hook file not owned by a package: $f"; done
[ -s /etc/rc.local ] && { echo "-- /etc/rc.local:"; grep -vE '^\s*(#|$)' /etc/rc.local | sed 's/^/   /'; }
grep -rnE 'Pre-Invoke|Post-Invoke|Update-Pre-Invoke' /etc/apt/apt.conf.d/ 2>/dev/null | grep -v 'ubuntu-advantage\|update-notifier\|motd\|dpkg-compat' | while read -r l; do flag "apt hook: $l"; done
grep -rnE '^\s*install\s+\S+\s+/' /etc/modprobe.d/ 2>/dev/null | while read -r l; do flag "modprobe install hook: $l"; done

sec "Shell startup files with suspicious content"
for f in /etc/profile /etc/profile.d/* /etc/bash.bashrc /etc/environment /root/.bashrc /root/.profile /root/.bash_login /root/.bash_logout /home/*/.bashrc /home/*/.profile /home/*/.bash_profile /home/*/.bash_logout; do
  [ -f "$f" ] && grep -nE "$SUSP_RE" "$f" 2>/dev/null | sed "s|^|$f:|" | while read -r l; do flag "suspicious shell hook: $l"; done; done

sec "Preload / PAM / library tricks"
[ -s /etc/ld.so.preload ] && flag "/etc/ld.so.preload is NOT empty: $(cat /etc/ld.so.preload)"
grep -rn 'LD_PRELOAD\|LD_LIBRARY_PATH' /etc/environment /etc/profile /etc/profile.d /etc/bash.bashrc 2>/dev/null | while read -r l; do flag "LD_* in startup file: $l"; done
for f in $(nonpkg /etc/ld.so.conf.d/*); do flag "ld.so.conf.d entry not from package: $f"; done
grep -rnE 'pam_exec|pam_script|pam_python|sufficient[[:space:]]+pam_permit' /etc/pam.d 2>/dev/null | grep -v '^\S*:\s*#' | while read -r l; do flag "risky PAM line: $l"; done
grep -rn 'nullok' /etc/pam.d 2>/dev/null | grep -v ':\s*#' | head -3 | while read -r l; do warn "PAM allows empty passwords (nullok): $l"; done
find /lib /usr/lib -path "*security/pam_*.so" 2>/dev/null | while read -r f; do [ -n "$(nonpkg "$f")" ] && flag "PAM module not owned by package: $f"; done

sec "SUID/SGID binaries & file capabilities"
GTFO='^(bash|sh|dash|zsh|ksh|python[0-9.]*|perl|ruby|node|php|lua|find|vim|vi|nano|less|more|awk|gawk|nmap|tcpdump|env|cp|mv|tar|zip|unzip|base64|xxd|systemctl|docker|gdb|strace|tee|dd|busybox|ed|ftp|socat|nc|ncat|openssl|rsync|make|git|man|time|timeout|nice)$'
find / -xdev -type f \( -perm -4000 -o -perm -2000 \) 2>/dev/null | while read -r f; do
  b=$(basename "$f")
  if echo "$b" | grep -qE "$GTFO"; then flag "SUID/SGID shell-capable binary: $f"
  elif [ -n "$(nonpkg "$f")" ]; then flag "SUID/SGID binary not owned by a package: $f"; fi
done
have getcap && getcap -r / 2>/dev/null | grep -E 'cap_setuid|cap_sys_admin|cap_dac_override|cap_sys_ptrace' | while read -r l; do flag "dangerous capability: $l"; done

sec "Immutable / append-only attributes (attackers use these to protect implants)"
if have lsattr; then
  lsattr -R /etc /root /home /var/www /usr/local /opt /var/spool/cron /lib/systemd 2>/dev/null | awk 'NF==2 && length($1)>=5 && (substr($1,5,1)=="i" || substr($1,6,1)=="a") {print $2}' | while read -r f; do flag "immutable/append-only: $f   (fix: chattr -ia '$f')"; done
fi

sec "Permissions on critical files"
stat -c '%a %U:%G %n' /etc/passwd /etc/shadow /etc/group /etc/sudoers /etc/ssh/sshd_config 2>/dev/null
find /etc /usr/bin /usr/sbin /bin /sbin /usr/lib -xdev -type f -perm -0002 2>/dev/null | head -20 | while read -r f; do flag "world-writable system file: $f"; done

sec "Processes"
ps -eo pid,user:14,lstart,args --no-headers | grep -vE '\[.*\]$' | grep -E '\b(nc|ncat|netcat|socat|chisel|ligolo|frpc|xmrig|pwncat|msfconsole|meterpreter)\b|/dev/tcp|bash -i' | grep -v grep | while read -r l; do flag "suspicious process: $l"; done
for p in /proc/[0-9]*; do e=$(readlink "$p/exe" 2>/dev/null) || continue
  case "$e" in *"(deleted)"*|/tmp/*|/dev/shm/*|/var/tmp/*) flag "process running from deleted/temp binary: pid=${p#/proc/} exe=$e cmd=$(tr '\0' ' ' <"$p/cmdline" 2>/dev/null | cut -c1-120)";; esac; done
echo "-- top-level process tree (condensed):"; ps -eo user:12,pid,ppid,comm --sort=user --no-headers | awk '$1!="root" || $3==1' | head -40

sec "Network: listeners (flagging unexpected), connections, firewall"
ss -Htulnp 2>/dev/null | while read -r proto _ _ _ laddr _ proc; do
  port=${laddr##*:}; addr=${laddr%:*}
  case "$addr" in 127.*|"[::1]"|::1) continue;; esac
  echo " $proto $laddr $proc"
  echo " $EXPECT_PORTS" | grep -qw -- "$port" || flag "unexpected listener: $proto $laddr $proc"
done
echo "-- established connections to non-172.16 hosts or from odd ports:"
ss -Htnp state established 2>/dev/null | awk '{print $3" -> "$4" "$5}' | grep -vE '(172\.16\.|127\.0\.0\.1|\[::1\])' | while read -r l; do flag "external connection: $l"; done
echo "-- iptables / nft / ufw rules currently loaded:"
iptables-save 2>/dev/null | grep -vE '^(#|:|\*|COMMIT)' | head -40; nft list ruleset 2>/dev/null | head -60; have ufw && ufw status 2>/dev/null | head -5
iptables-save 2>/dev/null | grep -E 'DNAT|REDIRECT|TPROXY' | while read -r l; do flag "NAT redirect rule: $l"; done
grep -vE '^\s*(#|$)' /etc/hosts | grep -vE '^(127\.|::1|ff0|fe00)' | while read -r l; do flag "non-default /etc/hosts entry: $l"; done
echo "-- resolv.conf:"; grep -vE '^\s*#' /etc/resolv.conf

sec "Package integrity (dpkg --verify; config files excluded)"
if have dpkg; then
  if [ "${FULL:-0}" = 1 ]; then PK=(); else PK=(coreutils procps iproute2 net-tools openssh-server openssh-client sudo passwd login util-linux bash libpam-modules libpam-runtime libpam0g findutils grep libc-bin systemd apache2 nginx vsftpd samba); fi
  dpkg -V "${PK[@]}" 2>/dev/null | grep -vE '^..5.......\s+c ' | grep -E '^..5' | while read -r l; do flag "modified package file: $l"; done
  echo "(done - use FULL=1 to verify every package)"
fi

sec "Recent changes (last $RECENT_DAYS days) in sensitive locations"
find /etc /usr/local /opt /root /home /var/spool/cron /lib/systemd /usr/lib/systemd -xdev -type f -mtime -"$RECENT_DAYS" 2>/dev/null | grep -vE '/(\.cache|\.local/share|\.viminfo|\.lesshst|\.bash_history)|/etc/(mtab|resolv|adjtime|ld.so.cache)' | head -60
echo "-- executables / hidden dirs in temp locations:"
find /tmp /var/tmp /dev/shm -xdev \( -type f -perm /111 -o -name '.*' -o -name '...' \) 2>/dev/null | head -30 | while read -r f; do flag "temp-dir executable/hidden: $f"; done
find / -xdev \( -name '.. *' -o -name '...' -o -name '.. ' \) 2>/dev/null | head | while read -r f; do flag "suspicious dir name: $f"; done
for f in /etc/hosts.equiv /root/.rhosts /home/*/.rhosts /root/.netrc /home/*/.netrc; do [ -e "$f" ] && flag "legacy trust file: $f"; done

sec "Kernel modules"
lsmod | awk 'NR>1{print $1}' | grep -iE 'diamorphine|reptile|rootkit|syshook|hide|knark|adore|suterusu' | while read -r m; do flag "rootkit-ish kernel module: $m"; done
ls /etc/modules-load.d/ 2>/dev/null

if [ -d /var/www ] || [ -d /srv/www ]; then
  sec "Web content (see roles/lib_web.sh for the detailed scan)"
  . "$DIR/roles/lib_web.sh"; web_scan_all
fi

sec "SUMMARY"
echo "Total [FLAG] items: $FLAGS   Report: $REPORT"
echo "Review every flag. Delete implants only after confirming they aren't needed by a scored service."
