#!/usr/bin/env bash
# 06_firewall.sh <web|files|board> - default-deny INPUT with an allow-list of the scored ports.
#   * ICMP echo is ALWAYS allowed (ICMP is scored).   * Established connections survive, so your SSH session stays up.
#   * Auto-rollback: if you don't press ENTER within ROLLBACK_SECS (default 60) the old rules come back.
#   * Persists across reboot via gddc-firewall.service.
# Env: TEAM_NET=172.16.X.0/24 (auto-detected)   TRUST_TEAM=1 (accept ALL traffic from team subnet; default 1)
#      EXTRA_TCP="3306 8080"   EXTRA_UDP=""   EGRESS=open|strict (strict = outbound only DNS/HTTP(S)/NTP/team subnet)
#      PASV_MIN=40000 PASV_MAX=40100 (files role)   FLUSH_OTHERS=1 (wipe pre-existing iptables/nft rules, incl. attacker NAT)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; . "$DIR/lib/common.sh"; need_root
ROLE="${1:-}"; [ -n "$ROLE" ] || { echo "usage: $0 <web|files|board>"; exit 1; }
TRUST_TEAM="${TRUST_TEAM:-1}"; EGRESS="${EGRESS:-open}"; ROLLBACK_SECS="${ROLLBACK_SECS:-60}"; FLUSH_OTHERS="${FLUSH_OTHERS:-1}"
PASV_MIN="${PASV_MIN:-40000}"; PASV_MAX="${PASV_MAX:-40100}"
TEAM_NET="$(detect_team_net)"; [ -n "$TEAM_NET" ] || { warn "could not detect 172.16.X.0/24 - set TEAM_NET=172.16.X.0/24. Team-subnet trust disabled."; TRUST_TEAM=0; }

SSH_PORT=$(sshd -T 2>/dev/null | awk '/^port /{print $2; exit}'); SSH_PORT="${SSH_PORT:-22}"
case "$ROLE" in
  web)   TCP="$SSH_PORT 80 443"; RANGES="" ;;
  board) TCP="$SSH_PORT 80 443"; RANGES="" ;;
  files) TCP="21 $SSH_PORT 139 445"; RANGES="$PASV_MIN-$PASV_MAX"
         # honour a passive range already configured in vsftpd
         for c in /etc/vsftpd.conf /etc/vsftpd/vsftpd.conf; do [ -f "$c" ] && {
           a=$(awk -F= '/^pasv_min_port/{print $2}' "$c" | tr -d ' '); b=$(awk -F= '/^pasv_max_port/{print $2}' "$c" | tr -d ' ')
           [ -n "$a" ] && [ -n "$b" ] && [ "$a" != 0 ] && RANGES="$a-$b"; }; done ;;
  *) echo "unknown role $ROLE"; exit 1 ;;
esac
TCP="$TCP ${EXTRA_TCP:-}"; UDP="${EXTRA_UDP:-}"
# also open whatever 80/443 listener actually exists on a non-standard port for web roles
hdr "Firewall plan ($ROLE)"
echo "  TCP: $TCP   ranges: ${RANGES:-none}   UDP: ${UDP:-none}   team-trust: $TRUST_TEAM ($TEAM_NET)   egress: $EGRESS"
for p in $TCP; do listening "$p" || warn "nothing is listening on tcp/$p right now (rule added anyway)"; done

FWDIR=/etc/gddc; mkdir -p $FWDIR; backup_file /etc/iptables /etc/nftables.conf
tcp_csv=$(echo "$TCP" | xargs -n1 | sort -un | paste -sd, -); udp_csv=$(echo "$UDP" | xargs -n1 | sort -un | paste -sd, -)
RANGE_CSV=$(echo "$RANGES" | tr ' ' ',')

flush_all() {
  [ "$FLUSH_OTHERS" = 1 ] || return 0
  for b in iptables ip6tables iptables-legacy ip6tables-legacy; do
    have "$b" || continue
    for t in filter nat mangle raw; do "$b" -t "$t" -F 2>/dev/null; "$b" -t "$t" -X 2>/dev/null; done
    "$b" -P INPUT ACCEPT 2>/dev/null; "$b" -P FORWARD ACCEPT 2>/dev/null; "$b" -P OUTPUT ACCEPT 2>/dev/null
  done
}

if have nft; then
  MODE=nft; RULES=$FWDIR/fw.nft
  {
    echo "flush ruleset"
    echo "table inet gddc {"
    echo "  chain input {"
    echo "    type filter hook input priority -10; policy drop;"
    echo "    iif lo accept"
    echo "    ct state established,related accept"
    echo "    ct state invalid drop"
    echo "    ip protocol icmp icmp type { echo-request, destination-unreachable, time-exceeded, parameter-problem } limit rate 100/second burst 200 packets accept"
    echo "    ip6 nexthdr icmpv6 accept"
    [ "$TRUST_TEAM" = 1 ] && echo "    ip saddr $TEAM_NET accept"
    [ -n "$tcp_csv" ] && echo "    tcp dport { $tcp_csv } ct state new limit rate 300/second burst 600 packets accept"
    [ -n "$RANGE_CSV" ] && echo "    tcp dport { $RANGE_CSV } accept"
    [ -n "$udp_csv" ] && echo "    udp dport { $udp_csv } accept"
    echo "    limit rate 5/second log prefix \"gddc-drop \" level info"
    echo "  }"
    echo "  chain forward { type filter hook forward priority -10; policy drop; }"
    if [ "$EGRESS" = strict ]; then
      echo "  chain output {"
      echo "    type filter hook output priority -10; policy drop;"
      echo "    oif lo accept"
      echo "    ct state established,related accept"
      echo "    meta l4proto { icmp, ipv6-icmp } accept"
      echo "    udp dport { 53, 123 } accept"
      echo "    tcp dport { 53, 80, 443 } accept"
      [ -n "$TEAM_NET" ] && echo "    ip daddr $TEAM_NET accept"
      echo "    limit rate 5/second log prefix \"gddc-egress-drop \" level info"
      echo "  }"
    fi
    echo "}"
  } >"$RULES"
  APPLY=(nft -f "$RULES"); CHECK=(nft -c -f "$RULES")
  SAVE_OLD() { nft list ruleset >"$FWDIR/previous.nft" 2>/dev/null; echo "flush ruleset" | cat - "$FWDIR/previous.nft" >"$FWDIR/previous.restore" 2>/dev/null; }
  RESTORE_OLD="nft -f $FWDIR/previous.restore"
elif have iptables-restore; then
  MODE=ipt; RULES=$FWDIR/fw.v4
  {
    echo "*filter"; echo ":INPUT DROP [0:0]"; echo ":FORWARD DROP [0:0]"
    [ "$EGRESS" = strict ] && echo ":OUTPUT DROP [0:0]" || echo ":OUTPUT ACCEPT [0:0]"
    echo "-A INPUT -i lo -j ACCEPT"
    echo "-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
    echo "-A INPUT -m conntrack --ctstate INVALID -j DROP"
    echo "-A INPUT -p icmp --icmp-type echo-request -m limit --limit 100/second --limit-burst 200 -j ACCEPT"
    echo "-A INPUT -p icmp --icmp-type destination-unreachable -j ACCEPT"
    echo "-A INPUT -p icmp --icmp-type time-exceeded -j ACCEPT"
    [ "$TRUST_TEAM" = 1 ] && echo "-A INPUT -s $TEAM_NET -j ACCEPT"
    [ -n "$tcp_csv" ] && echo "-A INPUT -p tcp -m multiport --dports $tcp_csv -m conntrack --ctstate NEW -j ACCEPT"
    for r in $RANGES; do echo "-A INPUT -p tcp --dport ${r/-/:} -j ACCEPT"; done
    [ -n "$udp_csv" ] && echo "-A INPUT -p udp -m multiport --dports $udp_csv -j ACCEPT"
    echo "-A INPUT -m limit --limit 5/second -j LOG --log-prefix \"gddc-drop \""
    if [ "$EGRESS" = strict ]; then
      echo "-A OUTPUT -o lo -j ACCEPT"; echo "-A OUTPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT"
      echo "-A OUTPUT -p icmp -j ACCEPT"; echo "-A OUTPUT -p udp -m multiport --dports 53,123 -j ACCEPT"
      echo "-A OUTPUT -p tcp -m multiport --dports 53,80,443 -j ACCEPT"; [ -n "$TEAM_NET" ] && echo "-A OUTPUT -d $TEAM_NET -j ACCEPT"
    fi
    echo "COMMIT"
  } >"$RULES"
  APPLY=(iptables-restore "$RULES"); CHECK=(iptables-restore --test "$RULES")
  SAVE_OLD() { iptables-save >"$FWDIR/previous.v4" 2>/dev/null; }
  RESTORE_OLD="iptables-restore $FWDIR/previous.v4"
else bad "neither nft nor iptables found - cannot configure a firewall"; exit 1; fi

if ! "${CHECK[@]}" 2>"$FWDIR/check.err"; then bad "generated ruleset is invalid:"; cat "$FWDIR/check.err"; exit 1; fi
[ "$DRY_RUN" = 1 ] && { info "dry-run: ruleset written to $RULES (not applied)"; cat "$RULES"; exit 0; }

SAVE_OLD
# watchdog: runs detached, so it still fires if your SSH session dies
rm -f /run/gddc-fw-confirm
setsid bash -c "sleep $ROLLBACK_SECS; if [ ! -e /run/gddc-fw-confirm ]; then $RESTORE_OLD; logger -t gddc 'firewall rolled back (not confirmed)'; fi" >/dev/null 2>&1 &
flush_all
"${APPLY[@]}" && ok "firewall rules applied ($MODE)" || { bad "apply failed - restoring"; eval "$RESTORE_OLD"; exit 1; }
have ufw && ufw status 2>/dev/null | grep -q 'Status: active' && { warn "disabling ufw (replaced by gddc rules)"; ufw disable >/dev/null 2>&1; }

# persistence
if have systemctl; then
  if [ "$MODE" = nft ]; then LOAD="$(command -v nft) -f $RULES"; else LOAD="$(command -v iptables-restore) $RULES"; fi
  cat >/etc/systemd/system/gddc-firewall.service <<UNIT
[Unit]
Description=GDDC firewall
After=network-pre.target nftables.service netfilter-persistent.service ufw.service
Before=network.target
[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=$LOAD
[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload; systemctl enable gddc-firewall.service >/dev/null 2>&1; ok "persistent across reboot (gddc-firewall.service)"
else warn "no systemd: add '$LOAD' to /etc/rc.local to persist"; fi

echo
warn "Test NOW from ANOTHER terminal/host: new SSH login, ping, and the scored service ports. Scoreboard should stay green."
if [ -t 0 ]; then
  if read -r -t "$ROLLBACK_SECS" -p "Everything still works? Press ENTER within ${ROLLBACK_SECS}s to KEEP the firewall (otherwise it rolls back)... "; then touch /run/gddc-fw-confirm; ok "confirmed - firewall kept"; else echo; bad "no confirmation - rollback will run"; fi
else touch /run/gddc-fw-confirm; info "non-interactive: auto-confirmed. To undo: $RESTORE_OLD"; fi
info "Undo anytime:  $RESTORE_OLD   (and: systemctl disable gddc-firewall)"
