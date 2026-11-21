#!/usr/bin/env bash
# 10_ir.sh - incident-response helper.  sudo ./10_ir.sh <command> [args]
#   sessions              who is logged in / recent logins / ssh connections
#   kick <pts/N|user>     kill a login session (or all of a user's processes)
#   shells [kill]         find (and optionally kill) reverse-shell-like connections
#   attackers             top source IPs: SSH failures, web probing, FTP failures
#   block <ip...>         drop an IP now (also saved to blocklist)     unblock <ip>    reapply
#   who-changed <file>    auditd: who touched this file?  (needs 05_base_hardening.sh auditd rules)
#   report                write a markdown incident summary for injects / the Gold Team interview
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; . "$DIR/lib/common.sh"; need_root
cmd="${1:-help}"; shift 2>/dev/null || true; BL="$GDDC_HOME/blocklist.txt"
auth_log() { if [ -r /var/log/auth.log ]; then cat /var/log/auth.log; elif [ -r /var/log/secure ]; then cat /var/log/secure; else journalctl -u ssh -u sshd --no-pager 2>/dev/null; fi; }
web_logs() { ls /var/log/apache2/access.log /var/log/nginx/access.log /var/log/httpd/access_log 2>/dev/null; }
top_ips() { grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | sort | uniq -c | sort -rn | head -${1:-10}; }
fw_block() { local ip=$1
  if have nft && nft list table inet gddc >/dev/null 2>&1; then nft list chain inet gddc input 2>/dev/null | grep -q "ip saddr $ip drop" || nft insert rule inet gddc input ip saddr "$ip" drop
  elif have iptables; then iptables -C INPUT -s "$ip" -j DROP 2>/dev/null || iptables -I INPUT 1 -s "$ip" -j DROP; fi; ss -K dst "$ip" >/dev/null 2>&1 || true; }
case "$cmd" in
 sessions) hdr "logged in"; w; hdr "recent logins"; last -n 15 -a 2>/dev/null; hdr "established SSH"; ss -Htn state established '( sport = :22 )' 2>/dev/null;;
 kick) t="${1:?usage: kick <pts/N|user>}"; me=$(tty 2>/dev/null | sed 's|/dev/||')
   [ "$t" = "$me" ] && { bad "that is YOUR session"; exit 1; }
   case "$t" in pts/*|tty*) pkill -KILL -t "$t" && ok "killed session $t";; *) pkill -KILL -u "$t" && ok "killed all processes of $t";; esac;;
 shells) ss -Htnp state established 2>/dev/null | grep -E 'users:\(\("(bash|sh|dash|zsh|nc|ncat|netcat|socat|python[0-9.]*|perl|ruby|php|node)"' | while read -r l; do bad "reverse-shell-like: $l"
     [ "${1:-}" = kill ] && { pid=$(echo "$l" | grep -oP 'pid=\K[0-9]+' | head -1); [ -n "$pid" ] && kill -9 "$pid" && ok "killed pid $pid"; }; done
   echo "(re-run with 'shells kill' to kill; then 'block <peer ip>')";;
 attackers) hdr "SSH failures by source"; auth_log | grep -E 'Failed password|Invalid user|authentication failure|Connection closed by (invalid|authenticating)' | top_ips 15
   hdr "Web probing by source (4xx/5xx or exploit-looking URIs)"; for f in $(web_logs); do echo "# $f"; grep -Ei '" (4|5)[0-9]{2} |\.\./|%2e%2e|union.*select|cmd=|/bin/(ba)?sh|base64|wp-login|phpmyadmin|\.php\?.*=http' "$f" | top_ips 10; done
   hdr "FTP failures"; grep -h 'FAIL LOGIN' /var/log/vsftpd.log 2>/dev/null | top_ips 10;;
 block) [ $# -ge 1 ] || { echo "usage: block <ip...>"; exit 1; }; TN="$(detect_team_net)"
   for ip in "$@"; do [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || { bad "not an IPv4: $ip"; continue; }
     [ -n "$TN" ] && [ "${ip%.*}" = "${TN%.*}" ] && [ "${FORCE:-0}" != 1 ] && { bad "$ip is in YOUR team subnet (jumpboxes/teammates) - refusing (FORCE=1 to override)"; continue; }
     fw_block "$ip"; echo "$ip" >>"$BL"; sort -u -o "$BL" "$BL"; ok "blocked $ip"; done
   warn "If the scoreboard drops after a block, it may have been the scoring engine: ./10_ir.sh unblock <ip>";;
 unblock) ip="${1:?usage: unblock <ip>}"
   if have nft && nft list table inet gddc >/dev/null 2>&1; then for h in $(nft -a list chain inet gddc input | grep "ip saddr $ip drop" | awk '{print $NF}'); do nft delete rule inet gddc input handle "$h"; done
   else iptables -D INPUT -s "$ip" -j DROP 2>/dev/null; fi; [ -f "$BL" ] && sed -i "/^$ip\$/d" "$BL"; ok "unblocked $ip";;
 reapply) [ -f "$BL" ] && while read -r ip; do [ -n "$ip" ] && fw_block "$ip"; done <"$BL"; ok "blocklist re-applied";;
 who-changed) f="${1:?usage: who-changed <file>}"; if have ausearch; then ausearch -f "$f" -i 2>/dev/null | grep -E 'type=SYSCALL|type=PATH' | tail -20; else warn "auditd not installed"; fi; stat "$f";;
 report) R="$GDDC_HOME/incident-report-$(hostname)-$TS.md"
   { echo "# Incident summary - $(hostname) - $(date '+%F %T')"; echo
     echo "## Detections (monitor/watchdog alerts)"; [ -s "$GDDC_HOME/alerts.log" ] && sed 's/^/- /' "$GDDC_HOME/alerts.log" | tail -60 || echo "- none recorded"
     echo; echo "## Top SSH attacker IPs"; auth_log | grep -E 'Failed password|Invalid user' | top_ips 10 | sed 's/^/- /'
     echo; echo "## Blocked IPs"; [ -s "$BL" ] && sed 's/^/- /' "$BL" || echo "- none"
     echo; echo "## Remediation actions taken (from $LOG)"; grep -E ' (WARN|BAD|OK ) ' "$LOG" | grep -Ei 'quarantin|rotated|locking|removed|disabled|restored|rolled back|stopping' | tail -40 | sed 's/^/- /'
     echo; echo "## Quarantined items"; ls -d "$GDDC_HOME"/quarantine*/* "$GDDC_HOME"/tampered/* 2>/dev/null | sed 's/^/- /'
     echo; echo "## Accounts now able to log in"; getent passwd | awk -F: '$7 !~ /(nologin|false)$/ {print "- "$1" (uid "$3")"}'
     echo; echo "## Listening services"; ss -Htulnp | awk '{print "- "$1" "$5" "$7}'
     echo; echo "## Business impact / lessons (fill in)"; echo "- Downtime: "; echo "- Root cause: "; echo "- Prevention: "; } >"$R"
   ok "report -> $R   (edit the last section, paste into the inject/Gold Team notes)";;
 *) sed -n '2,11p' "$0";;
esac
