# GDDC extra blue-team scripts (gap-fillers)

Your existing playbook covers **Linux** only (backup, audit, accounts, ssh, base, firewall, web/files/board roles, monitor, verify).
These add everything else. Same style: DRY_RUN / rollback / scored users never touched.

## 0. Fix first: `roles/files.sh` has a syntax error
`bash -n files.sh` fails at line 41 (stray `}` in `harden_vsftpd`). `linux/files.sh.FIXED` is the corrected file
-> `cp linux/files.sh.FIXED roles/files.sh`. (Without this the File Server role will not run at all.)

## Layout
Linux: drop `linux/07..13` next to your `01_*.sh` (they source `lib/common.sh`; 12 also uses `roles/lib_web.sh`). `chmod +x`.
Windows: copy `windows\` to `C:\gddc-scripts\` on the DC. Elevated PowerShell; if blocked: `Set-ExecutionPolicy -Scope Process Bypass`.
pfSense: `pfsense/pfsense_blue.sh` -> router shell.

## What each adds
| Script | Fills the gap |
|---|---|
| linux/07_persistence_clean.sh | 02_audit only *reports*; this quarantines cron/unit/hook/shell-rc/SUID/temp-dir implants + kills processes (asks y/N, backups) |
| linux/08_extra_hardening.sh | nullok, su->group sudo, sudo defaults/log, module blacklist, /dev/shm noexec, persistent journal; opt-in: TMP_NOEXEC, COMPILERS, TOOLS |
| linux/09_watchdog.sh | **restores red-team config tampering** + restarts dead scored services + reloads firewall (snapshot -> run) |
| linux/10_ir.sh | sessions, kick, reverse-shell finder, attackers (top IPs), block/unblock, who-changed, **incident report** for injects / Gold Team |
| linux/11_integrity.sh | rootkit-ish checks: hidden PIDs/ports, tampered ps/ss, LD_PRELOAD, kernel modules, full dpkg verify, REPAIR=1 |
| linux/12_db_rotate.sh | rotates the web app DB password *and* its config together (WordPress/phpBB/SMF/MyBB), auto-rollback |
| linux/13_remote_check.sh | run from a Kali jumpbox: checks every scored service from outside (loopback verify can't) |
| windows/01-08 + run_all | **entire Windows DC** (scored: ICMP, SSH, LDAP, WinRM): backup/baseline, AD+persistence audit, password rotation + AD cleanup, hardening, persistence removal, firewall w/ rollback, monitor, verify |
| pfsense/pfsense_blue.sh | router: backup, audit (shellcmd/cron/keys/NAT), non-interactive admin password change |

## Suggested order
Linux boxes (existing): `sudo ./run_all.sh <role>` -> `sudo ./09_watchdog.sh snapshot <role>` -> in spare terminals
`sudo ./monitor.sh` and `sudo ./09_watchdog.sh run <role>`. Then `08_extra_hardening.sh`, `07_persistence_clean.sh` (after reading the audit),
`11_integrity.sh`, and on the web/board box `12_db_rotate.sh`. Re-snapshot the watchdog after any intended config change (or `touch /run/gddc-watchdog-pause`).
DC: `.\run_all.ps1` (or step by step) -> `.\07_monitor.ps1 -AutoHeal`. Router: `sh pfsense_blue.sh all`.
From a jumpbox, every few minutes: `./13_remote_check.sh <team#> -w`.

## Deliberate safety choices (scoring)
* Scored users are never rotated/locked/removed from groups - on Windows WinRM needs their admin/remote-mgmt rights.
* LDAP signing is **not** forced (a plain simple-bind scoring check would go red) - `-LdapSigning` is opt-in; AD ports stay open to the team subnet.
* No account-lockout policy (red could lock the scored users by guessing). No fail2ban for the same reason.
* RDP is kept (Cloudflare access) but NLA-only and team-subnet-only in the firewall.
* Not covered: Windows DC GPO redesign, and app-level admin passwords (forum/CMS logins) - do those by hand.

## Caveats
* Windows/pfSense scripts could not be executed here (no PowerShell/pfSense in my sandbox) - Linux scripts were syntax-checked with `bash -n`.
  Run `-DryRun` first (windows) and keep a second session open. pfSense `passwd` falls back to console option 3 if the PHP call fails.
* Competition rules: #10 bans *autonomous AI agents* and #6 bans outside assistance; I'd confirm with White Team that using a chat assistant to prepare scripts is OK before relying on them.
