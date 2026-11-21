#!/usr/bin/env bash
# 08_extra_hardening.sh - gaps left by 05_base_hardening.sh: PAM/su/sudo hygiene, module blacklist, /dev/shm,
# persistent logging, optional attacker-tool lockdown. Scored services and scored accounts are never touched.
# Env: TMP_NOEXEC=0 (1 = mount /tmp noexec; can break apt)  COMPILERS=0 (1 = gcc/make root-only)
#      TOOLS=0 (1 = nc/ncat/socat/telnet root-only)   SU_WHEEL=1 (only group 'sudo' may su)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; . "$DIR/lib/common.sh"; need_root
TMP_NOEXEC="${TMP_NOEXEC:-0}"; COMPILERS="${COMPILERS:-0}"; TOOLS="${TOOLS:-0}"; SU_WHEEL="${SU_WHEEL:-1}"

hdr "PAM: remove nullok (blank passwords) - only if nobody has one"
if awk -F: '$2==""{f=1} END{exit !f}' /etc/shadow; then warn "an account has an EMPTY password - not removing nullok (run 03_accounts.sh first)"
else for f in /etc/pam.d/common-auth /etc/pam.d/common-password; do [ -f "$f" ] && grep -q nullok "$f" && { backup_file "$f"; run sed -i 's/[[:space:]]nullok_secure//; s/[[:space:]]nullok//' "$f"; ok "nullok removed from $f"; }; done; fi

hdr "su restricted to group sudo"
if [ "$SU_WHEEL" = 1 ] && getent group sudo >/dev/null && [ -f /etc/pam.d/su ] && ! grep -qE '^\s*auth\s+required\s+pam_wheel.so' /etc/pam.d/su; then
  backup_file /etc/pam.d/su; run sed -i '0,/^auth/{s/^auth/auth       required   pam_wheel.so use_uid group=sudo\nauth/}' /etc/pam.d/su; ok "su now requires membership of group sudo (restore: $BACKUP_DIR/etc/pam.d/su)"
fi

hdr "sudo hygiene (/etc/sudoers.d/99-gddc, validated with visudo)"
T=$(mktemp); printf 'Defaults use_pty\nDefaults logfile="/var/log/sudo.log"\nDefaults !visiblepw\nDefaults timestamp_timeout=5\nDefaults passwd_tries=3\n' >"$T"
if visudo -cf "$T" >/dev/null 2>&1; then [ "$DRY_RUN" = 1 ] || { install -m 440 -o root -g root "$T" /etc/sudoers.d/99-gddc; }; ok "sudo defaults installed"; else warn "sudo defaults rejected by visudo (old sudo?) - skipped"; fi; rm -f "$T"

hdr "Rarely-needed kernel modules/protocols blacklisted"
for m in dccp sctp rds tipc ax25 netrom x25 rose cramfs freevxfs jffs2 hfs hfsplus; do echo "blacklist $m"; done >/etc/modprobe.d/gddc-blacklist.conf; ok "wrote /etc/modprobe.d/gddc-blacklist.conf"

hdr "Mount options"
run mount -o remount,noexec,nosuid,nodev /dev/shm 2>/dev/null && ok "/dev/shm noexec,nosuid,nodev (not persistent across reboot)"
if [ "$TMP_NOEXEC" = 1 ]; then
  findmnt -n /tmp >/dev/null 2>&1 || run mount --bind /tmp /tmp
  run mount -o remount,noexec,nosuid,nodev /tmp && ok "/tmp noexec (undo: mount -o remount,exec /tmp)"
fi

hdr "Persistent logging"
mkdir -p /var/log/journal /etc/systemd/journald.conf.d; printf '[Journal]\nStorage=persistent\nSystemMaxUse=500M\n' >/etc/systemd/journald.conf.d/gddc.conf
run systemctl restart systemd-journald 2>/dev/null; ok "journald persistent"
touch /var/log/sudo.log; chmod 600 /var/log/sudo.log

hdr "Misc"
run systemctl mask ctrl-alt-del.target >/dev/null 2>&1 && ok "ctrl-alt-del masked"
have aa-status && { aa-status --enabled 2>/dev/null && ok "AppArmor enabled" || warn "AppArmor not enabled"; }
for f in /etc/hosts.allow /etc/hosts.deny; do [ -s "$f" ] && grep -vE '^\s*(#|$)' "$f" | sed "s|^|   $f: |"; done
if [ "$COMPILERS" = 1 ]; then for b in gcc cc g++ c++ make as ld; do p=$(command -v "$b" 2>/dev/null) && p=$(readlink -f "$p") && run chmod 750 "$p" && ok "root-only: $p"; done; fi
if [ "$TOOLS" = 1 ]; then for b in nc ncat netcat nc.traditional nc.openbsd socat telnet; do p=$(command -v "$b" 2>/dev/null) && p=$(readlink -f "$p") && run chmod 750 "$p" && ok "root-only: $p"; done; fi
ok "Extra hardening done."
