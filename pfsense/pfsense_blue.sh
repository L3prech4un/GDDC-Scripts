#!/bin/sh
# pfsense_blue.sh <audit|passwd|backup|all> - Blue Team Firewall (172.16.X.1, pfSense, FreeBSD sh). Scored: ICMP + WebUI.
# Copy to the router (WebUI: Diagnostics > Command Prompt, or SSH / console option 8), then:  sh pfsense_blue.sh all
#   backup : copy config.xml aside (file-level; do NOT revert VM snapshots)
#   audit  : READ-ONLY - local users, SSH keys, shellcmd/earlyshellcmd persistence, cron, NAT port-forwards, packages, listeners, rc.d
#   passwd : set a NEW admin (WebUI) password non-interactively. Prints it once - share it with your team.
# It never edits firewall rules or interfaces: ICMP + WebUI must stay reachable for scoring.
CF=/cf/conf/config.xml; OUT=/root/gddc; TS=$(date +%Y%m%d-%H%M%S); mkdir -p $OUT; chmod 700 $OUT
hdr() { echo; echo "=== $* ==="; }
flag() { echo "[FLAG] $*"; }
do_backup() { hdr backup; cp -p $CF "$OUT/config-$TS.xml" && echo "saved $OUT/config-$TS.xml"; ls -1t /cf/conf/backup 2>/dev/null | head -3; }
do_audit() {
  hdr "users (config.xml)"; php -r 'require_once("config.inc"); global $config; foreach (($config["system"]["user"] ?? []) as $u) { echo $u["name"]." uid=".$u["uid"]." scope=".$u["scope"]." priv=".(is_array($u["priv"]??null)?implode(",",$u["priv"]):($u["priv"]??""))." keys=".(empty($u["authorizedkeys"])?"no":"YES")."\n"; }' 2>/dev/null || grep -A8 '<user>' $CF | grep -E '<name>|<uid>|<authorizedkeys>'
  grep -q '<authorizedkeys>' $CF && flag "authorized SSH keys stored in config.xml (check users above)"
  hdr "persistence in config"
  for t in shellcmd earlyshellcmd; do grep -n "<$t>" $CF | while read -r l; do flag "$t: $l"; done; done
  grep -n '<cron>' -A12 $CF | grep -E '<command>|<who>' | while read -r l; do flag "cron job: $l"; done
  grep -n '<package>' $CF | head -10 | sed 's/^/  package: /'
  hdr "services exposed"; grep -E '<enablesshd>|<sshdkeyonly>|<ssh>|<protocol>|<port>' $CF | head -8 | sed 's/^/  /'
  grep -q '<enablesshd>' $CF && echo "  SSH is enabled on the router (not scored - disable if unneeded: System > Advanced > Admin Access)"
  hdr "NAT port forwards / outbound oddities"; grep -c '<rule>' $CF | sed 's/^/  total <rule> blocks (filter+nat): /'
  awk '/<nat>/,/<\/nat>/' $CF | grep -E '<target>|<local-port>|<destination>|<interface>' | head -20 | sed 's/^/  /'
  hdr "listeners"; sockstat -4 -6 -l | awk 'NR>1{print $1,$2,$3,$5,$6}' | sort -u | head -30
  hdr "files that don't belong"; ls -la /root/.ssh /root/.tcshrc /root/.profile 2>/dev/null; ls -la /usr/local/etc/rc.d 2>/dev/null; ls -la /etc/rc.local /usr/local/etc/rc.d/*.sh 2>/dev/null
  crontab -l 2>/dev/null | grep -vE '^\s*#' | sed 's/^/  root crontab: /'; grep -vE '^\s*(#|$)' /etc/crontab 2>/dev/null | grep -v 'nobody\|root.*/usr/local/\(sbin\|bin\)/\(php\|pfSense\|fcgicli\)' | sed 's/^/  /' | head -20
  find /tmp /var/tmp /root -xdev -type f \( -perm -u+x -o -name '.*' \) -mtime -3 2>/dev/null | head -20 | while read -r f; do flag "recent executable/hidden: $f"; done
  hdr "admin login attempts (last)"; clog /var/log/auth.log 2>/dev/null | grep -Ei 'Accepted|Failed|webConfigurator authentication' | tail -10 || tail -10 /var/log/auth.log 2>/dev/null
}
do_passwd() {
  hdr "set new admin password"; P=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 18)_Aa1; export GDDC_PW="$P"
  php -r 'require_once("config.inc"); require_once("auth.inc"); global $config; $pw=getenv("GDDC_PW");
    foreach ($config["system"]["user"] as $i => $u) { if ($u["name"]=="admin") { local_user_set_password($config["system"]["user"][$i], $pw); local_user_set($config["system"]["user"][$i]); } }
    write_config("GDDC: rotated admin password"); echo "ok\n";' && { echo "admin new password: $P"; echo "admin $P" >>"$OUT/passwords-$TS.txt"; chmod 600 "$OUT/passwd"* "$OUT/passwords-$TS.txt" 2>/dev/null; } \
  || echo "automatic change failed - use console menu option 3 (Reset webConfigurator password) or: pfSsh.php playback changepassword admin"
  unset GDDC_PW
}
case "${1:-all}" in backup) do_backup;; audit) do_audit;; passwd) do_passwd;; all) do_backup; do_audit; do_passwd;; *) echo "usage: sh $0 <audit|passwd|backup|all>";; esac
echo; echo "Manual pfSense checklist (WebUI): Firewall>Rules (nothing 'any/any' you didn't add), System>User Manager (unknown users/keys), System>Advanced>Admin Access (disable SSH, keep HTTPS), Diagnostics>States (odd outbound), Status>Services (unknown services)."
