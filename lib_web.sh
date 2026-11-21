#!/usr/bin/env bash
# lib_web.sh - shared web-server hardening/scan helpers (Apache, nginx, PHP, MySQL/MariaDB).
# Sourced by roles/web.sh, roles/board.sh and 02_audit.sh.
DIR_LW="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
. "$DIR_LW/lib/common.sh"

web_roots() {
  { for r in /var/www /srv/www /usr/share/nginx/html /opt/lampp/htdocs; do [ -d "$r" ] && echo "$r"; done
    grep -rhEi '^\s*DocumentRoot' /etc/apache2 /etc/httpd 2>/dev/null | awk '{print $2}' | tr -d '"'
    grep -rhE '^\s*root\s+' /etc/nginx 2>/dev/null | awk '{print $2}' | tr -d ';'
  } | sort -u | while read -r d; do [ -d "$d" ] && echo "$d"; done
}

_PATFILE=""
_shell_patterns() {
  [ -n "$_PATFILE" ] && [ -f "$_PATFILE" ] && { echo "$_PATFILE"; return; }
  _PATFILE=$(mktemp)
  cat >"$_PATFILE" <<'PAT'
(eval|assert|system|passthru|shell_exec|exec|popen|proc_open|pcntl_exec)[[:space:]]*\([[:space:]]*(base64_decode|gzinflate|gzuncompress|str_rot13|\$_(GET|POST|REQUEST|COOKIE|SERVER)|stripslashes\(\$_)
\$_(GET|POST|REQUEST|COOKIE)\[[^]]*\][[:space:]]*\(
preg_replace[[:space:]]*\([[:space:]]*['"]/.*/[a-z]*e[a-z]*['"]
(FilesMan|c99shell|r57shell|WSO [0-9]|b374k|weevely|ChinaChopper|Fx29Shell|IndoXploit|Mini Shell|p0wny)
array_map[[:space:]]*\([[:space:]]*['"]assert
call_user_func(_array)?[[:space:]]*\([[:space:]]*\$_(GET|POST|REQUEST)
(\$\$[a-zA-Z_]+[[:space:]]*\(|\$\{['"]_(GET|POST))
@?(move_uploaded_file|file_put_contents|fwrite)[[:space:]]*\(.*\$_(GET|POST|REQUEST)
(fsockopen|stream_socket_client)[[:space:]]*\(.*(bash|/bin/sh)
\b(bash|sh)[[:space:]]+-i[[:space:]]+>&[[:space:]]*/dev/tcp
(auto_prepend_file|auto_append_file)
PAT
  echo "$_PATFILE"
}

# web_scan_all [root...] : report-only (QUARANTINE=1 moves pattern-matched files aside)
web_scan_all() {
  local roots=("$@"); [ ${#roots[@]} -eq 0 ] && mapfile -t roots < <(web_roots)
  [ ${#roots[@]} -eq 0 ] && { info "no web roots found"; return; }
  local pf r f n=0; pf=$(_shell_patterns)
  for r in "${roots[@]}"; do
    hdr "Web scan: $r"
    echo "-- files matching webshell patterns:"
    grep -rEnI --include='*.php' --include='*.phtml' --include='*.php[3-8]' --include='*.pht' --include='*.phar' --include='*.inc' --include='*.html' --include='*.htm' --include='.htaccess' --include='*.user.ini' -f "$pf" "$r" 2>/dev/null | cut -c1-200 | while read -r l; do bad "[FLAG] webshell-ish: $l"; done
    echo "-- PHP/exec files in upload-like or static dirs, double extensions, hidden files:"
    find "$r" -type f \( -iname '*.php' -o -iname '*.phtml' -o -iname '*.phar' -o -iname '*.php[3-8]' -o -iname '*.pht' \) \( -ipath '*upload*' -o -ipath '*image*' -o -ipath '*img*' -o -ipath '*cache*' -o -ipath '*tmp*' -o -ipath '*files*' -o -ipath '*avatar*' -o -ipath '*media*' -o -ipath '*static*' \) 2>/dev/null | while read -r f; do bad "[FLAG] script in data dir: $f"; done
    find "$r" -type f \( -iname '*.jpg.php' -o -iname '*.png.php' -o -iname '*.gif.php' -o -iname '*.php.*' -o -iname '*.php;*' \) 2>/dev/null | while read -r f; do bad "[FLAG] double extension: $f"; done
    find "$r" -type f -name '.*' ! -name '.htaccess' ! -name '.htpasswd' ! -name '.gitignore' ! -name '.gitkeep' 2>/dev/null | while read -r f; do bad "[FLAG] hidden file: $f"; done
    echo "-- very long lines (obfuscated payloads):"
    find "$r" -type f \( -name '*.php' -o -name '*.phtml' -o -name '*.js' \) -size -2M 2>/dev/null | while read -r f; do awk 'length>4000{found=1} END{exit !found}' "$f" && bad "[FLAG] minified/obfuscated (line >4000 chars): $f"; done | head -30
    echo "-- .htaccess files with handler/prepend tricks:"
    find "$r" -name '.htaccess' -type f 2>/dev/null | while read -r f; do grep -HnEi 'AddType|AddHandler|SetHandler|php_value|php_flag|auto_prepend|RewriteRule .*https?://|Options .*ExecCGI|ProxyPass' "$f" 2>/dev/null | while read -r l; do bad "[FLAG] .htaccess: $l"; done; done
    echo "-- leftovers an attacker (or admin) shouldn't leave online:"
    find "$r" \( -iname 'phpinfo.php' -o -iname 'info.php' -o -iname 'test.php' -o -iname 'adminer*.php' -o -iname 'phpmyadmin' -o -iname '*.sql' -o -iname '*.bak' -o -iname '*.old' -o -iname '*.orig' -o -iname '*.zip' -o -iname '*.tar.gz' -o -iname '.git' -o -iname '.svn' -o -iname 'install' -o -iname 'setup' -o -iname 'shell*.php' -o -iname 'cmd*.php' \) 2>/dev/null | head -40 | while read -r f; do warn "review: $f"; done
    echo "-- world-writable / www-data-writable code:"
    find "$r" -type f -perm -0002 2>/dev/null | head -20 | while read -r f; do bad "[FLAG] world-writable: $f"; done
    echo "-- config files holding DB credentials (rotate carefully; app breaks if DB pw changes without updating these):"
    grep -rlEI "(DB_PASSWORD|dbpasswd|db_pass|\\\$dbpass|'password'[[:space:]]*=>|define\(.DB_USER)" "$r" --include='*.php' --include='*.ini' --include='*.conf' --include='*.env' --include='*.yml' --include='*.json' 2>/dev/null | head -10 | sed 's/^/   /'
    echo "-- recently modified (last ${RECENT_DAYS:-3}d):"; find "$r" -type f -mtime -"${RECENT_DAYS:-3}" 2>/dev/null | head -20 | sed 's/^/   /'
    if [ "${QUARANTINE:-0}" = 1 ]; then
      local q="$GDDC_HOME/quarantine/$TS"; mkdir -p "$q"
      grep -rElI --include='*.php' --include='*.phtml' --include='*.phar' --include='*.pht' -f "$pf" "$r" 2>/dev/null | grep -v 'auto_prepend' | while read -r f; do
        mkdir -p "$q$(dirname "$f")"; mv "$f" "$q$f" && warn "QUARANTINED $f -> $q$f"; n=$((n+1)); done
    fi
  done
  apache_audit_conf 2>/dev/null
}

apache_audit_conf() {
  [ -d /etc/apache2 ] || [ -d /etc/httpd ] || return 0
  hdr "Apache config review"
  grep -rnEi 'auto_prepend_file|auto_append_file|SetHandler|AddHandler|ProxyPass|php_admin_value|CustomLog\s+"?\||ErrorLog\s+"?\||ScriptAlias|Alias .*(/etc|/root|/home)|LoadModule' /etc/apache2/sites-enabled /etc/apache2/conf-enabled /etc/apache2/apache2.conf /etc/httpd/conf.d 2>/dev/null | grep -v 'mods-enabled' | cut -c1-180 | sed 's/^/   /'
  for f in $(nonpkg /etc/apache2/conf-enabled/* /etc/apache2/mods-enabled/* /etc/apache2/conf-available/*); do [ -f "$f" ] && warn "[FLAG] apache conf/module not from a package: $f"; done
  ls /etc/apache2/mods-enabled 2>/dev/null | tr '\n' ' '; echo
}


# --- Apache -----------------------------------------------------------------
web_harden_apache() {
  have apache2ctl || have apachectl || return 1
  local ctl; ctl=$(command -v apache2ctl || command -v apachectl)
  local conf="/etc/apache2/conf-available/gddc-hardening.conf"
  hdr "Apache hardening"
  if [ -d /etc/apache2/conf-available ]; then
    backup_file /etc/apache2/apache2.conf
    cat >"$conf" <<'CONF'
# GDDC hardening
ServerTokens Prod
ServerSignature Off
TraceEnable Off
FileETag None
Timeout 60
KeepAliveTimeout 5
LimitRequestLine 8190
LimitRequestFieldSize 8190
LimitRequestFields 100
<IfModule mod_headers.c>
  Header always set X-Content-Type-Options "nosniff"
  Header always set X-Frame-Options "SAMEORIGIN"
  Header always unset X-Powered-By
</IfModule>
<DirectoryMatch "/\.(git|svn|hg)">
  Require all denied
</DirectoryMatch>
<FilesMatch "\.(sql|bak|old|orig|swp|inc|ini|log|env)$">
  Require all denied
</FilesMatch>
<Directory /var/www/>
  Options -Indexes
</Directory>
CONF
    run a2enconf gddc-hardening >/dev/null
  fi
  # modules rarely needed that widen attack surface
  local m dis=()
  for m in info userdir dav dav_fs dav_lock status; do
    if [ -e "/etc/apache2/mods-enabled/$m.load" ]; then run a2dismod -f "$m" >/dev/null 2>&1 && dis+=("$m"); fi
  done
  [ ${#dis[@]} -gt 0 ] && ok "disabled Apache modules: ${dis[*]}" && echo "${dis[*]}" >"$BACKUP_DIR/apache_disabled_mods"
  if run "$ctl" configtest 2>&1 | tee -a "$LOG" | grep -q 'Syntax OK'; then ok "apache config OK"; return 0; fi
  bad "apache config test FAILED - rolling back"; web_rollback_apache; return 1
}
web_rollback_apache() {
  a2disconf gddc-hardening >/dev/null 2>&1
  [ -f "$BACKUP_DIR/apache_disabled_mods" ] && for m in $(cat "$BACKUP_DIR/apache_disabled_mods"); do a2enmod "$m" >/dev/null 2>&1; done
  svc_do reload apache2 >/dev/null 2>&1
}

# --- nginx ------------------------------------------------------------------
web_harden_nginx() {
  have nginx || return 1
  hdr "nginx hardening"
  backup_file /etc/nginx/nginx.conf
  mkdir -p /etc/nginx/conf.d
  cat >/etc/nginx/conf.d/gddc-hardening.conf <<'CONF'
server_tokens off;
client_body_timeout 20s;
client_header_timeout 20s;
send_timeout 20s;
CONF
  grep -rnE 'autoindex\s+on|alias\s|proxy_pass|fastcgi_param PHP_VALUE|fastcgi_param\s+SCRIPT_FILENAME\s+\$' /etc/nginx 2>/dev/null | cut -c1-160 | sed 's/^/   review: /'
  if nginx -t 2>&1 | tee -a "$LOG" | grep -q 'successful'; then ok "nginx config OK"; return 0; fi
  bad "nginx config test FAILED - rolling back"; rm -f /etc/nginx/conf.d/gddc-hardening.conf; return 1
}

# --- PHP --------------------------------------------------------------------
web_harden_php() {
  local d any=0 disable="exec,passthru,shell_exec,system,proc_open,popen,pcntl_exec,pcntl_fork,pcntl_signal,dl,show_source,posix_kill,posix_setuid,posix_mkfifo"
  hdr "PHP hardening"
  [ "${PHP_DISABLE_FUNCS:-1}" = 1 ] || disable=""
  for d in /etc/php*/*/conf.d /etc/php*/conf.d /etc/php5/*/conf.d; do
    [ -d "$d" ] || continue; any=1
    {
      echo "; GDDC hardening"
      echo "expose_php=Off"; echo "display_errors=Off"; echo "display_startup_errors=Off"; echo "log_errors=On"
      echo "allow_url_include=Off"; echo "session.cookie_httponly=1"; echo "session.use_strict_mode=1"
      echo "cgi.fix_pathinfo=0"
      [ -n "$disable" ] && echo "disable_functions=$disable"
    } >"$d/99-gddc.ini"
    echo "$d/99-gddc.ini" >>"$BACKUP_DIR/php_ini_added"
    ok "wrote $d/99-gddc.ini"
  done
  [ $any = 0 ] && info "no PHP conf.d found (PHP not installed?)"
  return 0
}
web_rollback_php() { [ -f "$BACKUP_DIR/php_ini_added" ] && while read -r f; do rm -f "$f"; done <"$BACKUP_DIR/php_ini_added"; }

web_reload_all() {
  local s
  for s in apache2 httpd nginx; do svc_exists "$s" && svc_active "$s" && run systemctl reload "$s" 2>/dev/null; done
  for s in $(systemctl list-units --type=service --no-pager --plain --no-legend 'php*-fpm*' 2>/dev/null | awk '{print $1}'); do run systemctl restart "$s"; done
}

# --- MySQL / MariaDB --------------------------------------------------------
web_harden_mysql() {
  local cli; cli=$(command -v mariadb || command -v mysql) || return 1
  { svc_active mysql || svc_active mariadb || svc_active mysqld; } || return 1
  hdr "MySQL/MariaDB hardening"
  if ! "$cli" -NBe 'select 1' >/dev/null 2>&1; then
    warn "cannot connect as root via socket (needs a password). Skipping DB cleanup - do manually:"
    echo "   DELETE FROM mysql.user WHERE User=''; DROP DATABASE IF EXISTS test; FLUSH PRIVILEGES;"; return 0
  fi
  echo "-- DB accounts:"; "$cli" -NBe "select user,host,plugin from mysql.user" 2>/dev/null | sed 's/^/   /'
  "$cli" -NBe "select user,host from mysql.user where user='' or host='%'" 2>/dev/null | while read -r u h; do warn "[FLAG] DB account allows broad access: '$u'@'$h'"; done
  "$cli" -NBe "select name,dl from mysql.func" 2>/dev/null | while read -r n d; do warn "[FLAG] MySQL UDF installed (privesc vector): $n ($d)"; done
  pgrep -af 'skip-grant-tables' >/dev/null && warn "[FLAG] mysqld running with --skip-grant-tables!"
  run "$cli" -e "DELETE FROM mysql.user WHERE User=''; DROP DATABASE IF EXISTS test; DELETE FROM mysql.db WHERE Db LIKE 'test%'; FLUSH PRIVILEGES;" 2>/dev/null && ok "removed anonymous users + test DB"
  # remote root is never needed
  run "$cli" -e "DELETE FROM mysql.user WHERE User='root' AND Host NOT IN ('localhost','127.0.0.1','::1'); FLUSH PRIVILEGES;" 2>/dev/null
  # bind to loopback only if nobody remote is connected right now
  if ss -Htn state established '( sport = :3306 )' 2>/dev/null | awk '{print $4}' | grep -qvE '^(127\.|\[::1\])'; then
    warn "remote clients are connected to MySQL - leaving bind-address alone"
  elif [ -d /etc/mysql/conf.d ]; then
    printf '[mysqld]\nbind-address=127.0.0.1\nlocal-infile=0\nskip-symbolic-links=1\n' >/etc/mysql/conf.d/gddc.cnf
    echo /etc/mysql/conf.d/gddc.cnf >>"$BACKUP_DIR/mysql_added"
    for s in mysql mariadb mysqld; do svc_exists "$s" && svc_active "$s" && run systemctl restart "$s" && break; done
    ok "MySQL bound to 127.0.0.1"
  fi
  info "App DB passwords are NOT rotated automatically (the web app config would break). See config files listed in the web scan."
}

# --- orchestrator -----------------------------------------------------------
# web_harden_all  (baseline HTTP -> harden -> verify -> rollback on failure)
web_harden_all() {
  local url="${HTTP_URL:-http://127.0.0.1/}" base now
  base=$(http_probe "$url"); info "HTTP baseline for $url: $base"
  [ "${base%% *}" = 000 ] && warn "web server not answering on $url (set HTTP_URL=... if it uses another port/vhost)"
  web_harden_apache; web_harden_nginx; web_harden_php; web_harden_mysql
  web_reload_all; sleep 3
  if [ "${base%% *}" != 000 ]; then
    if http_verify "$base" "$url"; then ok "HTTP check still healthy: $(http_probe "$url")"
    else
      bad "HTTP check DEGRADED after hardening ($(http_probe "$url")) - rolling back web changes"
      web_rollback_php; web_rollback_apache; rm -f /etc/nginx/conf.d/gddc-hardening.conf; web_reload_all; sleep 2
      http_verify "$base" "$url" && ok "rolled back; site healthy again" || bad "STILL unhealthy - check logs: journalctl -u apache2 -u nginx; tail /var/log/apache2/error.log"
    fi
  fi
  # file permissions: strip world-write only (ownership untouched so the app keeps working)
  local r; for r in $(web_roots); do find "$r" -perm -0002 ! -type l -exec chmod o-w {} + 2>/dev/null; done; ok "removed world-write bits under web roots"
}
