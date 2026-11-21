#!/usr/bin/env bash
# 13_remote_check.sh <team-number> [-w]   - run from a KALI JUMPBOX (your own team only!). Checks every scored service from
# the outside, the way the scoring engine sees it (local verify.sh cannot: loopback bypasses the firewall).
#   -w  repeat every 30 s.      Env: EXPECT_STRING="text on web page"  PASV_PORT=40000
# Hosts: web .10  files .20  board .30  dc .40  router .1   (172.16.X.*)
X="${1:?usage: $0 <team-number> [-w]}"; B="172.16.$X"; G=$'\e[32m'; R=$'\e[31m'; Y=$'\e[33m'; N=$'\e[0m'
pass() { printf '  %s[ OK ]%s %s\n' "$G" "$N" "$*"; }; fail() { printf '  %s[FAIL]%s %s\n' "$R" "$N" "$*"; }; note() { printf '  %s[ ?? ]%s %s\n' "$Y" "$N" "$*"; }
tcp() { timeout 3 bash -c "exec 3<>/dev/tcp/$1/$2" 2>/dev/null; }
icmp() { ping -c1 -W2 "$1" >/dev/null 2>&1 && pass "ICMP $1" || fail "ICMP $1"; }
ssh_chk() { local b; b=$(timeout 4 bash -c "exec 3<>/dev/tcp/$1/22; head -c 40 <&3" 2>/dev/null | head -1); [[ "$b" == SSH-* ]] && pass "SSH $1 banner: $b" || fail "SSH $1 (no banner)"; }
http_chk() { local c; c=$(curl -s -m 6 -o /tmp/.gddc-body -w '%{http_code}' "http://$1/${2:-}" 2>/dev/null); local n; n=$(wc -c </tmp/.gddc-body 2>/dev/null)
  [[ "$c" =~ ^[23] ]] && pass "HTTP $1 -> $c ($n bytes)" || fail "HTTP $1 -> ${c:-none}"
  [ -n "${EXPECT_STRING:-}" ] && { grep -qF -- "$EXPECT_STRING" /tmp/.gddc-body && pass "content contains '$EXPECT_STRING'" || fail "content MISSING '$EXPECT_STRING'"; }; rm -f /tmp/.gddc-body; }
round() {
  echo "== $(date +%T) =="
  echo "Router $B.1";    icmp "$B.1"; curl -sk -m 6 -o /dev/null -w '%{http_code}' "https://$B.1/" 2>/dev/null | grep -qE '^(200|30[0-9]|40[0-9])' && pass "pfSense WebUI answers" || { curl -s -m 6 -o /dev/null "http://$B.1/" && pass "pfSense WebUI (http)" || fail "pfSense WebUI"; }
  echo "Web $B.10";      icmp "$B.10"; ssh_chk "$B.10"; http_chk "$B.10"
  echo "Files $B.20";    icmp "$B.20"; ssh_chk "$B.20"
    b=$(timeout 4 bash -c "exec 3<>/dev/tcp/$B.20/21; head -c 80 <&3" 2>/dev/null | head -1); [[ "$b" == 220* ]] && pass "FTP banner: $b" || fail "FTP $B.20"
    if command -v curl >/dev/null; then curl -s -m 6 --list-only "ftp://$B.20/" --user "anonymous:a@b.c" >/dev/null 2>&1 && note "anonymous FTP login WORKS (is that intended?)" ; fi
    if command -v smbclient >/dev/null; then smbclient -L "//$B.20" -N -m SMB2 2>&1 | grep -qE 'Sharename|NT_STATUS_ACCESS_DENIED|NT_STATUS_LOGON_FAILURE' && pass "SMB $B.20 answers" || fail "SMB $B.20"; else tcp "$B.20" 445 && pass "SMB tcp/445 open" || fail "SMB tcp/445"; fi
  echo "Board $B.30";    icmp "$B.30"; ssh_chk "$B.30"; http_chk "$B.30"
  echo "DC $B.40";       icmp "$B.40"; tcp "$B.40" 22 && pass "SSH tcp/22 open" || fail "SSH tcp/22"; tcp "$B.40" 5985 && pass "WinRM tcp/5985 open" || fail "WinRM tcp/5985"
    if command -v ldapsearch >/dev/null; then ldapsearch -x -H "ldap://$B.40" -s base -b '' namingContexts -o nettimeout=4 2>/dev/null | grep -q namingContexts && pass "LDAP rootDSE answers" || fail "LDAP rootDSE"; else tcp "$B.40" 389 && pass "LDAP tcp/389 open" || fail "LDAP tcp/389"; fi
  [ "${2:-}" != "-w" ] && command -v nmap >/dev/null && { echo "Unexpected open ports (nmap top-1000 on web/files/board):"; nmap -Pn -T4 --open -p- --min-rate 2000 "$B.10" "$B.20" "$B.30" 2>/dev/null | grep -E 'Nmap scan report|/tcp' | sed 's/^/   /'; } 
}
if [ "${2:-}" = "-w" ]; then while true; do round; sleep 30; done; else round; fi
