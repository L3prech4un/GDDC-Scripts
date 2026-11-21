#!/usr/bin/env bash
# 05_base_hardening.sh - kernel/network sysctls, cron lockdown, file perms, unneeded services, auditd.
# Nothing here touches scored services. Env: INSTALL_TOOLS=1 (try apt install auditd; default 1, 60s timeout)
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"; . "$DIR/lib/common.sh"; need_root
INSTALL_TOOLS="${INSTALL_TOOLS:-1}"

hdr "sysctl"
cat >/etc/sysctl.d/99-gddc.conf <<'CONF'
net.ipv4.ip_forward = 0
net.ipv4.conf.all.rp_filter = 2
net.ipv4.conf.default.rp_filter = 2
net.ipv4.conf.all.accept_source_route = 0
net.ipv4.conf.default.accept_source_route = 0
net.ipv4.conf.all.accept_redirects = 0
net.ipv4.conf.default.accept_redirects = 0
net.ipv4.conf.all.secure_redirects = 0
net.ipv4.conf.all.send_redirects = 0
net.ipv4.conf.default.send_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv6.conf.default.accept_redirects = 0
net.ipv4.icmp_echo_ignore_broadcasts = 1
net.ipv4.icmp_ignore_bogus_error_responses = 1
net.ipv4.tcp_syncookies = 1
net.ipv4.conf.all.log_martians = 1
kernel.randomize_va_space = 2
kernel.kptr_restrict = 2
kernel.dmesg_restrict = 1
kernel.sysrq = 0
kernel.unprivileged_bpf_disabled = 1
net.core.bpf_jit_harden = 2
fs.protected_hardlinks = 1
fs.protected_symlinks = 1
fs.protected_regular = 2
fs.protected_fifos = 2
fs.suid_dumpable = 0
CONF
run sysctl --system >/dev/null 2>&1; ok "sysctl applied (ICMP echo replies are NOT disabled - scoring needs them)"
echo '* hard core 0' >/etc/security/limits.d/99-gddc-nocore.conf

hdr "File permissions"
chmod 644 /etc/passwd /etc/group; chmod 640 /etc/shadow /etc/gshadow 2>/dev/null; chown root:shadow /etc/shadow /etc/gshadow 2>/dev/null || chown root:root /etc/shadow
chmod 600 /etc/ssh/ssh_host_*_key 2>/dev/null; chmod go-w /etc/crontab /etc/cron.d /etc/cron.d/* 2>/dev/null
chmod 700 /root; ok "passwd/shadow/ssh keys/cron perms fixed"

hdr "cron / at restricted to root"
for f in cron.allow at.allow; do echo root >"/etc/$f"; chmod 600 "/etc/$f"; done
rm -f /etc/cron.deny /etc/at.deny; ok "only root can create user crontabs/at jobs (system cron in /etc/cron.d still runs)"

hdr "Unneeded services (only touched if running and NOT listening on a scored port)"
for s in avahi-daemon cups cups-browsed bluetooth rpcbind nfs-server nfs-kernel-server telnet.socket telnetd inetd xinetd rsh.socket rexec.socket snmpd tftpd-hpa isc-dhcp-server ModemManager; do
  svc_exists "${s%.socket}" 2>/dev/null || systemctl list-unit-files "$s" >/dev/null 2>&1 || continue
  if systemctl is-active --quiet "$s" 2>/dev/null; then warn "stopping+disabling $s"; run systemctl disable --now "$s" >/dev/null 2>&1; fi
done

hdr "auditd (records edits to accounts/ssh/cron/systemd for incident reports)"
if ! have auditctl && [ "$INSTALL_TOOLS" = 1 ] && have apt-get; then info "trying apt install auditd (60s timeout; fine if it fails - no internet)"; DEBIAN_FRONTEND=noninteractive timeout 60 apt-get install -y -qq auditd >/dev/null 2>&1; fi
if have auditctl; then
  cat >/etc/audit/rules.d/99-gddc.rules <<'RULES'
-w /etc/passwd -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/sudoers -p wa -k sudo
-w /etc/sudoers.d/ -p wa -k sudo
-w /etc/ssh/sshd_config -p wa -k ssh
-w /etc/ssh/sshd_config.d/ -p wa -k ssh
-w /root/.ssh/ -p wa -k ssh
-w /etc/crontab -p wa -k cron
-w /etc/cron.d/ -p wa -k cron
-w /var/spool/cron/ -p wa -k cron
-w /etc/systemd/system/ -p wa -k systemd
-w /etc/ld.so.preload -p wa -k preload
-w /etc/pam.d/ -p wa -k pam
-w /tmp/ -p x -k tmpexec
-w /dev/shm/ -p x -k tmpexec
RULES
  run augenrules --load >/dev/null 2>&1 || run auditctl -R /etc/audit/rules.d/99-gddc.rules >/dev/null 2>&1
  run systemctl enable --now auditd >/dev/null 2>&1; ok "auditd rules loaded   (query: ausearch -k identity -ts recent ; ausearch -k cron)"
else info "auditd unavailable - skipping (use monitor.sh instead)"; fi
ok "Base hardening done."
