#!/usr/bin/env bash
# roles/board.sh - Message Board (172.16.X.30, Canaima GNU/Linux 9.0 = Debian-based): ICMP, SSH, HTTP, HTTP Content.
# Same web hardening as web.sh plus: app-type detection, 'usario' account check, old-distro safety (no blind upgrades).
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; . "$DIR/roles/lib_web.sh"; need_root
hdr "MESSAGE BOARD role"
cat /etc/os-release 2>/dev/null | grep -E '^(PRETTY_NAME|VERSION)=' | sed 's/^/  /'
info "Web roots: $(web_roots | tr '\n' ' ')"
for r in $(web_roots); do
  for app in phpbb phpBB MyBB mybb smf SMF vanilla flarum discourse nodebb wordpress wp-config.php config.php forum board; do
    find "$r" -maxdepth 1 -iname "$app*" 2>/dev/null | grep -q . && info "found '$app' under $r"; done
done
listening 3000 && warn "something on tcp/3000 (Node/Flask app behind a proxy?) - make sure it is not exposed directly"
listening 8080 && warn "something on tcp/8080 - confirm it's expected"
id usario >/dev/null 2>&1 && { info "usario: $(id usario)"; grep -q '^usario:.*:/bin/\(ba\)\?sh' /etc/passwd && warn "usario has a login shell (expected per the packet) - password gets rotated by 03_accounts.sh"; }
# the board's DB is the usual crown jewel: show who can reach it
ss -Htlnp 2>/dev/null | grep -E ':(3306|5432|27017|6379)\b' | sed 's/^/  DB listener: /'
web_scan_all
web_harden_all
warn "Canaima 9 repos may be archived/dead - these scripts never run 'apt upgrade'. Patch only if apt works AND you've confirmed the board still renders afterwards."
ok "Board role done. Next:  sudo $DIR/06_firewall.sh board"
