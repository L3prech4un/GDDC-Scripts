#!/usr/bin/env bash
# 03_accounts.sh - credential rotation + account/privilege cleanup.
# SCORED USERS ARE NEVER MODIFIED (password, shell, groups, lock) - the scoring engine logs in as them.
#
# Env (all optional):
#   NEWPASS=...            use this password for every rotated account (default: unique random per account)
#   ROTATE_EXTRA="u1 u2"   extra accounts to rotate (the ONLY way to include a scored user - coordinate w/ White Team!)
#   ROTATE_OTHERS=1        also rotate every other non-scored login user with UID>=1000 or named 'usario' (default 1)
#   CLEAR_AUTHKEYS=0       1 = back up and empty every authorized_keys file (do this after the audit shows keys you don't recognise)
#   LOCK_UNKNOWN=0         1 = lock (not delete) non-scored UID>=1000 users instead of rotating them
#   STRIP_SCORED_SUDO=1    remove scored users from sudo/wheel/admin groups (they only need to log in)
#   KICK_SESSIONS=0        1 = kill every other logged-in session (use right after rotating passwords)
#   DRY_RUN=1              print what would happen
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; . "$DIR/lib/common.sh"; need_root
ROTATE_OTHERS="${ROTATE_OTHERS:-1}"; CLEAR_AUTHKEYS="${CLEAR_AUTHKEYS:-0}"; LOCK_UNKNOWN="${LOCK_UNKNOWN:-0}"
STRIP_SCORED_SUDO="${STRIP_SCORED_SUDO:-1}"; KICK_SESSIONS="${KICK_SESSIONS:-0}"
NOLOGIN=$(command -v nologin || echo /usr/sbin/nologin)
PWFILE="$GDDC_HOME/passwords-$(hostname)-$TS.txt"; : >"$PWFILE"; chmod 600 "$PWFILE"

hdr "1. Extra UID-0 accounts (only root should be UID 0)"
awk -F: '$3==0 && $1!="root"{print $1}' /etc/passwd | while read -r u; do
  bad "UID-0 backdoor account: $u -> locking, nologin, expiring"
  run usermod -L -s "$NOLOGIN" -e 1 "$u"; run chage -E 0 "$u" 2>/dev/null
done

hdr "2. Empty-password accounts"
awk -F: '$2==""{print $1}' /etc/shadow | while read -r u; do
  if is_scored "$u"; then warn "scored user '$u' has an EMPTY password - leaving it; ask White Team"; else bad "locking empty-password account $u"; run passwd -l "$u" >/dev/null; fi
done

hdr "3. Password rotation"
rotate() { # user
  local u=$1 p="${NEWPASS:-$(gen_pass)}"
  id "$u" >/dev/null 2>&1 || return
  if [ "$DRY_RUN" = 1 ]; then echo "   [dry-run] would rotate $u"; return; fi
  echo "$u:$p" | chpasswd && { printf '%-14s %s\n' "$u" "$p" >>"$PWFILE"; ok "rotated $u"; _log "rotated $u"; } || bad "failed to rotate $u"
}
rotate root
if [ "$ROTATE_OTHERS" = 1 ]; then
  getent passwd | awk -F: '($3>=1000 && $3<60000) || $1=="usario"{print $1":"$7}' | while IFS=: read -r u sh; do
    is_scored "$u" && continue; [ "$u" = root ] && continue
    case "$sh" in */nologin|*/false) continue;; esac
    if [ "$LOCK_UNKNOWN" = 1 ] && [ "$u" != usario ]; then warn "locking non-scored user $u"; run usermod -L "$u"; else rotate "$u"; fi
  done
fi
for u in ${ROTATE_EXTRA:-}; do is_scored "$u" && warn "ROTATE_EXTRA includes SCORED user $u - scoring may fail until White Team updates the engine"; rotate "$u"; done
if [ -s "$PWFILE" ]; then
  echo; ok "New passwords (also saved to $PWFILE, root-only). Share them with your team NOW:"; sed 's/^/     /' "$PWFILE"
else rm -f "$PWFILE"; fi

hdr "4. sudo / privileged group hygiene"
if [ "$STRIP_SCORED_SUDO" = 1 ]; then
  for u in "${SCORED_USERS[@]}"; do id "$u" >/dev/null 2>&1 || continue
    for g in sudo wheel admin adm docker lxd; do getent group "$g" 2>/dev/null | cut -d: -f4 | tr ',' '\n' | grep -qx "$u" && { warn "removing scored user $u from group $g"; run gpasswd -d "$u" "$g" >/dev/null; }; done
  done
fi
# NOPASSWD rules -> require password (validated with visudo; reverted if invalid)
for f in /etc/sudoers /etc/sudoers.d/*; do
  [ -f "$f" ] || continue; grep -q NOPASSWD "$f" 2>/dev/null || continue
  backup_file "$f"; cp -a "$f" "$f.gddc.new"; sed -i 's/NOPASSWD:[[:space:]]*//g' "$f.gddc.new"
  if [ "$DRY_RUN" != 1 ] && visudo -cf "$f.gddc.new" >/dev/null 2>&1; then mv "$f.gddc.new" "$f"; chmod 440 "$f"; ok "removed NOPASSWD from $f"; else rm -f "$f.gddc.new"; warn "left $f alone"; fi
done
# sudoers.d files granting access to people who shouldn't have it - report
grep -rhE '^[^#%[:space:]][^[:space:]]*[[:space:]]+ALL' /etc/sudoers /etc/sudoers.d 2>/dev/null | grep -v '^root' | while read -r l; do warn "sudo grant to review: $l"; done

hdr "5. System accounts with login shells -> nologin"
getent passwd | awk -F: '$3<1000 && $1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $7 ~ /(bash|zsh|ksh|fish|\/sh|dash)$/ {print $1}' | while read -r u; do
  is_scored "$u" && continue; warn "$u had a login shell -> $NOLOGIN"; run usermod -s "$NOLOGIN" "$u"; done

hdr "6. SSH authorized_keys"
find / -xdev \( -name authorized_keys -o -name authorized_keys2 \) -type f 2>/dev/null | while read -r f; do
  [ -s "$f" ] || continue
  if [ "$CLEAR_AUTHKEYS" = 1 ]; then backup_file "$f"; warn "emptying $f ($(wc -l <"$f") keys) - backup in $BACKUP_DIR"; run truncate -s 0 "$f"
  else warn "KEYS PRESENT in $f - review (re-run with CLEAR_AUTHKEYS=1 to wipe)"; fi
done

hdr "7. Legacy trust files / preload"
for f in /etc/hosts.equiv /root/.rhosts /home/*/.rhosts; do [ -e "$f" ] && { backup_file "$f"; warn "removing $f"; run rm -f "$f"; }; done
if [ -s /etc/ld.so.preload ]; then backup_file /etc/ld.so.preload; bad "emptying /etc/ld.so.preload: $(cat /etc/ld.so.preload)"; run truncate -s 0 /etc/ld.so.preload; fi
if have lsattr; then
  lsattr -R /etc /root /home /var/www /usr/local /opt /var/spool/cron 2>/dev/null | awk 'NF==2 && length($1)>=5 && (substr($1,5,1)=="i" || substr($1,6,1)=="a") {print $2}' | while read -r f; do
    warn "removing immutable/append-only flag: $f"; run chattr -ia "$f" 2>/dev/null; done
fi

if [ "$KICK_SESSIONS" = 1 ]; then
  hdr "8. Killing other login sessions"
  me=$(tty 2>/dev/null | sed 's|/dev/||')
  who | awk '{print $2}' | sort -u | while read -r t; do [ "$t" = "$me" ] && continue; warn "killing session on $t"; run pkill -KILL -t "$t"; done
fi
ok "Accounts step done.  Log: $LOG"
