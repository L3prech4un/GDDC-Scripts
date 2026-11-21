#!/usr/bin/env bash
# roles/web.sh - Web Server (172.16.X.10, Ubuntu 26.04): scored = ICMP, SSH, HTTP, HTTP Content.
# Hardens Apache/nginx/PHP/MySQL, scans web roots for webshells, auto-rolls-back if the site stops answering.
# Env: HTTP_URL=http://127.0.0.1/   EXPECT_STRING="text the scoring check looks for"   QUARANTINE=1   PHP_DISABLE_FUNCS=0
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"; . "$DIR/roles/lib_web.sh"; need_root
hdr "WEB SERVER role"
info "Web roots: $(web_roots | tr '\n' ' ')"
web_scan_all
web_harden_all
ok "Web role done. Next:  sudo $DIR/06_firewall.sh web"
