#!/usr/bin/env bash
# 09_watchdog.sh <snapshot|run|status> <web|files|board> [seconds]
# Keeps scored services alive AND undoes red-team config tampering.
#   snapshot : after hardening (and after ANY legit config change/inject), save a known-good copy of configs + list of running services
#   run      : loop - restarts dead services, restores tampered/new/missing config files from the snapshot (tampered files are
#              kept in $GDDC_HOME/tampered/), reloads services, reloads the firewall if it vanished, alerts if a scored user is locked.
#   status   : show what is being watched
# Pause while you edit configs:  touch /run/gddc-watchdog-pause   (rm it afterwards, then re-snapshot)
# Env: AUTO_RESTORE=1  (0 = alert only)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; . "$DIR/lib/common.sh"; need_root
MODE="${1:-}"; ROLE="${2:-}"; INT="${3:-20}"; AUTO_RESTORE="${AUTO_RESTORE:-1}"
case "$MODE" in snapshot|run|status) ;; *) echo "usage: sudo $0 <snapshot|run|status> <web|files|board> [secs]"; exit 1;; esac
case "$ROLE" in web|files|board) ;; *) echo "role required: web|files|board"; exit 1;; esac
KG="$GDDC_HOME/known-good"; TREE="$KG/tree"; SUMS="$KG/sums"; SVC="$KG/services"; ALERTLOG="$GDDC_HOME/alerts.log"
alert() { echo "${C_R}[WATCHDOG $(date +%T)]${C_0} $*"; echo "$(date '+%F %T') watchdog: $*" >>"$ALERTLOG"; logger -t gddc-watchdog "$*" 2>/dev/null; }
role_paths() { echo /etc/ssh /etc/sudoers /etc/sudoers.d /etc/pam.d /etc/ld.so.preload /etc/hosts /etc/crontab /etc/cron.d /etc/security
  case "$ROLE" in web|board) echo /etc/apache2 /etc/nginx /etc/php /etc/php5 /etc/mysql /etc/httpd;; files) echo /etc/vsftpd.conf /etc/vsftpd /etc/ftpusers /etc/samba /etc/exports;; esac; }
existing_paths() { local p; for p in $(role_paths); do [ -e "$p" ] && echo "$p"; done; }
sums_now() { mapfile -t P < <(existing_paths); find "${P[@]}" -type f ! -name '*.swp' ! -name '*~' -print0 2>/dev/null | xargs -0 sha256sum 2>/dev/null | sort -k2; }
watched_services() { for s in $(case "$ROLE" in files) echo "vsftpd smbd nmbd smb";; *) echo "apache2 nginx httpd mysql mariadb";; esac) "$(ssh_svc)"; do svc_exists "$s" && svc_active "$s" && echo "$s"; done; }
reload_all() { sshd -t 2>/dev/null && run systemctl reload "$(ssh_svc)" 2>/dev/null
  for s in $(cat "$SVC" 2>/dev/null); do [ "$s" = "$(ssh_svc)" ] && continue; run systemctl reload-or-restart "$s" 2>/dev/null; done; }

if [ "$MODE" = snapshot ]; then
  hdr "Snapshot known-good config ($ROLE)"
  rm -rf "$KG"; mkdir -p "$TREE"; chmod 700 "$KG"
  mapfile -t P < <(existing_paths); for p in "${P[@]}"; do cp -a --parents "$p" "$TREE" 2>/dev/null; done
  sums_now >"$SUMS"; watched_services >"$SVC"
  ok "saved $(wc -l <"$SUMS") files; watching services: $(tr '\n' ' ' <"$SVC")"; info "Start the loop:  sudo $0 run $ROLE"; exit 0
fi
[ -s "$SUMS" ] || { bad "no snapshot - run: sudo $0 snapshot $ROLE   (after 05/06/role scripts)"; exit 1; }
if [ "$MODE" = status ]; then info "services: $(tr '\n' ' ' <"$SVC")"; info "files tracked: $(wc -l <"$SUMS")"; ls -la "$GDDC_HOME/tampered" 2>/dev/null | tail -5; exit 0; fi

TAMP="$GDDC_HOME/tampered"; mkdir -p "$TAMP"
info "watchdog running every ${INT}s (role=$ROLE auto_restore=$AUTO_RESTORE) - Ctrl-C to stop"
while true; do
  if [ -e /run/gddc-watchdog-pause ]; then sleep "$INT"; continue; fi
  # ---- config drift
  touched=0; declare -A K=() C=(); cur=$(mktemp); sums_now >"$cur"
  while read -r h f; do K["$f"]=$h; done <"$SUMS"; while read -r h f; do C["$f"]=$h; done <"$cur"; rm -f "$cur"
  for f in "${!K[@]}"; do
    if [ "${C[$f]:-}" != "${K[$f]}" ]; then
      [ -e "$f" ] && alert "CONFIG TAMPERED: $f" || alert "CONFIG DELETED: $f"
      if [ "$AUTO_RESTORE" = 1 ] && [ -e "$TREE$f" ]; then
        [ -e "$f" ] && { mkdir -p "$TAMP/$TS$(dirname "$f")"; cp -a "$f" "$TAMP/$TS$f" 2>/dev/null; chattr -ia "$f" 2>/dev/null; }
        mkdir -p "$(dirname "$f")"; cp -a "$TREE$f" "$f" && { alert "restored $f"; touched=1; }
      fi
    fi; done
  for f in "${!C[@]}"; do
    [ -n "${K[$f]:-}" ] && continue; alert "NEW CONFIG FILE: $f"
    if [ "$AUTO_RESTORE" = 1 ]; then mkdir -p "$TAMP/$TS$(dirname "$f")"; chattr -ia "$f" 2>/dev/null; mv "$f" "$TAMP/$TS$f" 2>/dev/null && { alert "moved $f -> $TAMP/$TS$f"; touched=1; }; fi
  done
  [ "$touched" = 1 ] && { reload_all; sleep 2; }
  # ---- services
  for s in $(cat "$SVC"); do
    svc_active "$s" && continue
    alert "service $s is DOWN - restarting"; svc_do restart "$s"; sleep 2
    svc_active "$s" && alert "$s recovered" || alert "$s FAILED to restart: journalctl -u $s -n 30 --no-pager"
  done
  # ---- firewall
  if [ -f /etc/gddc/fw.nft ] && have nft && ! nft list table inet gddc >/dev/null 2>&1; then alert "firewall table gone - reloading"; nft -f /etc/gddc/fw.nft; [ -f "$GDDC_HOME/blocklist.txt" ] && "$DIR/10_ir.sh" reapply >/dev/null 2>&1; fi
  # ---- scored users still usable?
  for u in "${SCORED_USERS[@]}"; do id "$u" >/dev/null 2>&1 || continue
    [ "$(passwd -S "$u" 2>/dev/null | awk '{print $2}')" = L ] && alert "scored user $u is LOCKED - unlock only if you didn't do it: passwd -u $u"
    case "$(getent passwd "$u" | cut -d: -f7)" in */nologin|*/false) alert "scored user $u shell is nologin/false";; esac; done
  sleep "$INT"
done
