#!/usr/bin/env bash
# 12_db_rotate.sh - rotate the web app's MySQL/MariaDB password AND patch the app's config file in one step, then verify the site
# (the main script deliberately skips this because changing only one side breaks the site). Rolls back if HTTP degrades.
# Supports WordPress (wp-config.php), phpBB (config.php), SMF (Settings.php), MyBB (inc/config.php).
# Needs: root with MySQL socket access.   Env: HTTP_URL=http://127.0.0.1/  EXPECT_STRING="text"  DRY_RUN=1
# NOTE: this does not change the forum's/CMS's own ADMIN logins - do those in the web UI (or tell me the app and I'll add it).
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; . "$DIR/roles/lib_web.sh"; need_root
cli=$(command -v mariadb || command -v mysql) || { bad "no mysql/mariadb client"; exit 1; }
"$cli" -NBe 'select 1' >/dev/null 2>&1 || { bad "cannot connect as root via socket"; exit 1; }
URL="${HTTP_URL:-http://127.0.0.1/}"; base=$(http_probe "$URL"); info "HTTP baseline: $base"
OUT="$GDDC_HOME/dbpass-$(hostname)-$TS.txt"; : >"$OUT"; chmod 600 "$OUT"
getval() { # file regex -> first captured value (single or double quoted)
  grep -oP "$2" "$1" 2>/dev/null | head -1; }
setdb() { local u=$1 p=$2 h; for h in $("$cli" -NBe "select host from mysql.user where user='$u'"); do
  "$cli" -e "ALTER USER '$u'@'$h' IDENTIFIED BY '$p'" 2>/dev/null || "$cli" -e "SET PASSWORD FOR '$u'@'$h' = PASSWORD('$p')" 2>/dev/null || return 1; done; "$cli" -e "FLUSH PRIVILEGES" 2>/dev/null; }
rotated=0
for r in $(web_roots); do
  while read -r cfg; do
    kind=""; user=""; old=""; sedexp=""
    if grep -q "DB_PASSWORD" "$cfg"; then kind=wordpress
      user=$(getval "$cfg" "DB_USER['\"]\s*,\s*['\"]\K[^'\"]+"); old=$(getval "$cfg" "DB_PASSWORD['\"]\s*,\s*['\"]\K[^'\"]*")
      sedexp="s|(DB_PASSWORD['\"][[:space:]]*,[[:space:]]*['\"])[^'\"]*(['\"])|\1@@P@@\2|"
    elif grep -q '\$dbpasswd' "$cfg"; then kind=phpbb
      user=$(getval "$cfg" "\\\$dbuser\s*=\s*['\"]\K[^'\"]+"); old=$(getval "$cfg" "\\\$dbpasswd\s*=\s*['\"]\K[^'\"]*")
      sedexp="s|(\\\$dbpasswd[[:space:]]*=[[:space:]]*['\"])[^'\"]*(['\"])|\1@@P@@\2|"
    elif grep -q '\$db_passwd' "$cfg"; then kind=smf
      user=$(getval "$cfg" "\\\$db_user\s*=\s*['\"]\K[^'\"]+"); old=$(getval "$cfg" "\\\$db_passwd\s*=\s*['\"]\K[^'\"]*")
      sedexp="s|(\\\$db_passwd[[:space:]]*=[[:space:]]*['\"])[^'\"]*(['\"])|\1@@P@@\2|"
    elif grep -q "\['database'\]\['password'\]" "$cfg"; then kind=mybb
      user=$(getval "$cfg" "\['database'\]\['username'\]\s*=\s*['\"]\K[^'\"]+"); old=$(getval "$cfg" "\['database'\]\['password'\]\s*=\s*['\"]\K[^'\"]*")
      sedexp="s|(\['database'\]\['password'\][[:space:]]*=[[:space:]]*['\"])[^'\"]*(['\"])|\1@@P@@\2|"
    else continue; fi
    [ -n "$user" ] || { warn "$kind config $cfg: could not read DB user - skipping"; continue; }
    "$cli" -NBe "select 1 from mysql.user where user='$user'" | grep -q 1 || { warn "DB user '$user' (from $cfg) not found in mysql.user - skipping"; continue; }
    new=$(gen_pass); info "$kind: $cfg  (db user: $user)"
    [ "$DRY_RUN" = 1 ] && { echo "   [dry-run] would rotate"; continue; }
    backup_file "$cfg"; cp -a "$cfg" "$cfg.gddc.old"
    if setdb "$user" "$new" && sed -i -E "${sedexp//@@P@@/$new}" "$cfg"; then
      sleep 1
      if http_verify "$base" "$URL"; then ok "rotated $user and patched $cfg; site healthy"; printf '%s  %s  %s\n' "$user" "$new" "$cfg" >>"$OUT"; rotated=$((rotated+1)); rm -f "$cfg.gddc.old"
      else bad "site degraded - rolling back $user"; cp -a "$cfg.gddc.old" "$cfg"; rm -f "$cfg.gddc.old"; setdb "$user" "$old" || bad "could not restore old DB password! user=$user old=$old"; fi
    else bad "rotation failed for $user - restoring"; cp -a "$cfg.gddc.old" "$cfg"; rm -f "$cfg.gddc.old"; [ -n "$old" ] && setdb "$user" "$old"; fi
  done < <(find "$r" -maxdepth 4 -type f \( -name wp-config.php -o -name config.php -o -name Settings.php \) 2>/dev/null)
done
[ "$rotated" -gt 0 ] && { ok "New DB credentials saved in $OUT (root-only)"; info "Run 01_backup.sh-style snapshot again: sudo ./09_watchdog.sh snapshot <role>"; } || warn "nothing rotated (unsupported app, or config unreadable). Rotate by hand: ALTER USER ... ; edit the app's config; test the page."
