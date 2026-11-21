#!/usr/bin/env bash
# verify.sh <web|files|board> - local sanity check of scored services. (Loopback bypasses the firewall,
# so ALSO confirm from another host/jumpbox:  nmap -Pn -p 21,22,80,139,445 172.16.X.<ip> ; ping 172.16.X.<ip>)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; . "$DIR/lib/common.sh"
ROLE="${1:-web}"
chk() { if listening "$2"; then ok "$1 listening on tcp/$2"; else bad "$1 NOT listening on tcp/$2"; fi; }
chk SSH "$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}' | grep . || echo 22)"
case "$ROLE" in
  web|board) chk HTTP 80; r=$(http_probe http://127.0.0.1/); [ "${r%% *}" -ge 200 ] 2>/dev/null && [ "${r%% *}" -lt 400 ] && ok "HTTP returns $r (code bytes)" || bad "HTTP returned $r";;
  files) chk FTP 21; chk SMB 445
         exec 3<>/dev/tcp/127.0.0.1/21 2>/dev/null && { read -r -t 3 b <&3; ok "FTP banner: $b"; exec 3>&-; }
         have smbclient && smbclient -L localhost -N -m SMB2 2>&1 | grep -q 'Sharename\|NT_STATUS' && ok "smbd answers";;
esac
if have nft && nft list table inet gddc >/dev/null 2>&1; then
  nft list table inet gddc | grep -q 'icmp type' && ok "firewall allows ICMP echo" || bad "firewall may block ICMP!"
elif iptables -S INPUT 2>/dev/null | grep -q 'icmp'; then ok "iptables allows ICMP"; else warn "no gddc firewall detected (or ICMP rule not visible)"; fi
for s in $(case "$ROLE" in files) echo "smbd vsftpd ssh";; *) echo "apache2 nginx ssh";; esac); do svc_exists "$s" && { svc_active "$s" && ok "service $s active" || bad "service $s NOT active"; }; done
