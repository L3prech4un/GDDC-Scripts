#!/usr/bin/env bash
# 04_ssh.sh - harden sshd WITHOUT breaking scoring (password auth stays ON; scored users log in with passwords).
# Directives are PREPENDED to sshd_config: sshd uses the first value it sees, so these beat anything
# later in the file or in sshd_config.d/ drop-ins (a common place to hide a backdoor setting).
# Env: ROOT_SSH=keep|no|prohibit-password   (default keep - Cloudflare/Proxmox access may use root; switch after testing)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; . "$DIR/lib/common.sh"; need_root
CONF=/etc/ssh/sshd_config; ROOT_SSH="${ROOT_SSH:-keep}"
[ -f "$CONF" ] || { bad "no $CONF"; exit 1; }
hdr "sshd hardening"
backup_file "$CONF" /etc/ssh/sshd_config.d
# remove any previous block of ours
sed -i '/^# BEGIN GDDC/,/^# END GDDC/d' "$CONF"
BLOCK=$(mktemp)
{
  echo "# BEGIN GDDC (first-match-wins, keep at top)"
  echo "PermitEmptyPasswords no"
  echo "PermitUserEnvironment no"
  echo "HostbasedAuthentication no"
  echo "IgnoreRhosts yes"
  echo "X11Forwarding no"
  echo "AllowAgentForwarding no"
  echo "AllowTcpForwarding no"
  echo "GatewayPorts no"
  echo "PermitTunnel no"
  echo "MaxAuthTries 4"
  echo "LoginGraceTime 30"
  echo "MaxStartups 30:50:100"
  echo "ClientAliveInterval 120"
  echo "ClientAliveCountMax 3"
  echo "LogLevel VERBOSE"
  echo "UseDNS no"
  echo "Banner none"
  echo "ForceCommand none"
  echo "AuthorizedKeysCommand none"
  echo "AuthorizedKeysFile .ssh/authorized_keys"
  echo "PasswordAuthentication yes"
  [ "$ROOT_SSH" != keep ] && echo "PermitRootLogin $ROOT_SSH"
  echo "# END GDDC"
} >"$BLOCK"
cat "$BLOCK" "$CONF" >"$CONF.gddc.new"; rm -f "$BLOCK"
SSHD=$(command -v sshd || echo /usr/sbin/sshd)
mkdir -p /run/sshd 2>/dev/null
if "$SSHD" -t -f "$CONF.gddc.new" 2>/tmp/gddc-sshd.err; then
  [ "$DRY_RUN" = 1 ] && { info "dry-run: config valid, not installing"; rm -f "$CONF.gddc.new"; exit 0; }
  mv "$CONF.gddc.new" "$CONF"; chmod 600 "$CONF"; ok "sshd_config updated"
else
  bad "new sshd_config failed validation (kept the old one):"; cat /tmp/gddc-sshd.err; rm -f "$CONF.gddc.new"; exit 1
fi
# Match blocks / drop-ins that could re-enable things: show them
grep -nEi '^\s*Match' "$CONF" /etc/ssh/sshd_config.d/* 2>/dev/null | while read -r l; do warn "Match block present - review: $l"; done
S=$(ssh_svc); run systemctl reload "$S" 2>/dev/null || run service "$S" reload
sleep 1
if have ssh-keyscan && ssh-keyscan -T 5 -p "$("$SSHD" -T 2>/dev/null | awk '/^port /{print $2; exit}')" 127.0.0.1 2>/dev/null | grep -q ssh; then
  ok "sshd is answering after reload"
else
  bad "sshd not answering - restoring previous config"; restore_file "$CONF"; run systemctl restart "$S"
fi
warn "KEEP YOUR CURRENT SSH SESSION OPEN and test a NEW login (as a scored user, if you can) before closing it."
