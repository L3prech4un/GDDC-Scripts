#!/usr/bin/env bash
# GDDC hardening - shared helpers. Source this file; do not run it directly.
[ -n "${GDDC_COMMON_LOADED:-}" ] && return 0
GDDC_COMMON_LOADED=1

GDDC_HOME="${GDDC_HOME:-/root/gddc}"
TS="${TS:-$(date +%Y%m%d-%H%M%S)}"
BACKUP_DIR="$GDDC_HOME/backups/$TS"
LOG="$GDDC_HOME/gddc.log"
DRY_RUN="${DRY_RUN:-0}"
mkdir -p "$GDDC_HOME" "$BACKUP_DIR" 2>/dev/null && chmod 700 "$GDDC_HOME" 2>/dev/null

# Accounts the scoring engine logs in as. NEVER touched by these scripts
# (no password change, shell change, group removal, locking, etc.) unless you
# explicitly name them in ROTATE_EXTRA.
SCORED_USERS=(amarino mdesocio lsmith acapece johnlinux linuswindows alvin simon theodore abauer)

if [ -t 1 ]; then C_R=$'\e[31m'; C_G=$'\e[32m'; C_Y=$'\e[33m'; C_B=$'\e[36m'; C_0=$'\e[0m'; else C_R=; C_G=; C_Y=; C_B=; C_0=; fi
_log() { printf '%s %s\n' "$(date '+%F %T')" "$*" >>"$LOG" 2>/dev/null; }
info() { echo "${C_B}[*]${C_0} $*"; _log "INFO $*"; }
ok()   { echo "${C_G}[+]${C_0} $*"; _log "OK   $*"; }
warn() { echo "${C_Y}[!]${C_0} $*"; _log "WARN $*"; }
bad()  { echo "${C_R}[-]${C_0} $*"; _log "BAD  $*"; }
hdr()  { echo; echo "${C_B}=== $* ===${C_0}"; _log "=== $*"; }

need_root() { [ "$(id -u)" -eq 0 ] || { echo "Run as root:  sudo -i  (then re-run)"; exit 1; }; }
have() { command -v "$1" >/dev/null 2>&1; }

# run CMD...  -> logs, honours DRY_RUN=1
run() { _log "RUN  $*"; if [ "$DRY_RUN" = 1 ]; then echo "   [dry-run] $*"; return 0; fi; "$@"; }

# backup_file PATH...  -> copies to $BACKUP_DIR preserving the full path
backup_file() { local f; for f in "$@"; do [ -e "$f" ] || continue; mkdir -p "$BACKUP_DIR$(dirname "$f")"; cp -a "$f" "$BACKUP_DIR$f" 2>/dev/null; done; }
restore_file() { local f=$1; [ -e "$BACKUP_DIR$f" ] && cp -a "$BACKUP_DIR$f" "$f"; }

is_scored() { local u; for u in "${SCORED_USERS[@]}"; do [ "$u" = "$1" ] && return 0; done; return 1; }

svc_exists() { if have systemctl; then systemctl list-unit-files "$1.service" 2>/dev/null | grep -q "^$1.service"; else [ -x "/etc/init.d/$1" ]; fi; }
svc_active() { if have systemctl; then systemctl is-active --quiet "$1" 2>/dev/null; else service "$1" status >/dev/null 2>&1; fi; }
svc_do()     { local act=$1 s=$2; if have systemctl; then run systemctl "$act" "$s"; else run service "$s" "$act"; fi; }
ssh_svc()    { local s; for s in ssh sshd; do svc_exists "$s" && { echo "$s"; return; }; done; echo ssh; }

# is something listening on TCP port $1 ?
listening() { ss -Htln 2>/dev/null | awk '{print $4}' | grep -qE "[:.]$1\$"; }

# Team subnet detection: 172.16.X.0/24 from our own IP (override with TEAM_NET=...)
detect_team_net() {
  [ -n "${TEAM_NET:-}" ] && { echo "$TEAM_NET"; return; }
  local ip
  ip=$(ip -4 -o addr show 2>/dev/null | awk '{print $4}' | grep -E '^172\.16\.[0-9]+\.' | head -1)
  [ -n "$ip" ] && echo "${ip%/*}" | awk -F. '{printf "%s.%s.%s.0/24\n",$1,$2,$3}'
}

gen_pass() { local p; p=$(LC_ALL=C tr -dc 'A-Za-z0-9' </dev/urandom | head -c 18); echo "${p}_Aa1"; }

# http_probe URL -> "CODE BYTES"
http_probe() {
  local url=$1 tmp code size; tmp=$(mktemp)
  if have curl; then code=$(curl -s -o "$tmp" -m 8 -w '%{http_code}' "$url" 2>/dev/null) || code=000
  elif have wget; then code=$(wget -q -T 8 -O "$tmp" --server-response "$url" 2>&1 | awk '/HTTP\//{c=$2} END{print c+0}')
  else rm -f "$tmp"; echo "000 0"; return; fi
  size=$(wc -c <"$tmp" 2>/dev/null || echo 0)
  if [ -n "${EXPECT_STRING:-}" ] && ! grep -qF -- "$EXPECT_STRING" "$tmp" 2>/dev/null; then code="${code}-nostring"; fi
  rm -f "$tmp"; echo "$code $size"
}
# http_verify "BASELINE" URL -> 0 if still healthy (same code class, body >= 50% of baseline)
http_verify() {
  local base=$1 url=$2 now bc bs nc ns
  now=$(http_probe "$url"); bc=${base%% *}; bs=${base##* }; nc=${now%% *}; ns=${now##* }
  case "$nc" in *nostring) return 1;; 2*|3*) ;; *) return 1;; esac
  [ "${bc:0:1}" = "${nc:0:1}" ] || return 1
  [ "$bs" -eq 0 ] || [ "$ns" -ge $((bs / 2)) ]
}

# set_kv FILE KEY VALUE [SEP]  - set "key=value" in a simple conf file (replace or append)
set_kv() {
  local f=$1 k=$2 v=$3 sep=${4:-=}
  if grep -qiE "^[[:space:]]*#?[[:space:]]*${k}[[:space:]]*=" "$f" 2>/dev/null; then
    sed -i -E "s|^[[:space:]]*#?[[:space:]]*${k}[[:space:]]*=.*|${k}${sep}${v}|I" "$f"
  else echo "${k}${sep}${v}" >>"$f"; fi
}

# nonpkg PATH... -> print paths that no installed package owns
nonpkg() {  # resolves /lib -> /usr/lib (merged-usr) before asking dpkg
  have dpkg || return 0; local f c
  for f in "$@"; do [ -e "$f" ] || continue
    c="$(realpath -m "$(dirname "$f")")/$(basename "$f")"
    dpkg -S "$c" >/dev/null 2>&1 || dpkg -S "$f" >/dev/null 2>&1 || echo "$f"; done; }
