# run_all.ps1 - the Windows DC playbook in a safe order.   (elevated PowerShell)   .\run_all.ps1 [-Yes] [-LdapSigning]
param([switch]$Yes, [switch]$LdapSigning)
$env:GDDC_TS = Get-Date -Format 'yyyyMMdd-HHmmss'; Set-Location $PSScriptRoot
function Pause2($m) { if (-not $Yes) { Read-Host "$m [ENTER to continue, Ctrl-C to stop]" | Out-Null } }
.\01_backup.ps1;                    Pause2 'Backup + baseline done.'
.\02_audit.ps1 | Select-Object -Last 25; Pause2 'Audit done (full report in C:\gddc). Read the [FLAG]s.'
.\03_accounts.ps1;                  Pause2 'Share the new passwords with the team, then continue.'
.\04_harden.ps1 -LdapSigning:$LdapSigning; Pause2 'Open a SECOND SSH/RDP session to test, then continue.'
.\05_persistence_clean.ps1 -Auto:$Yes
.\06_firewall.ps1
.\08_verify.ps1
Write-Host "`nFinished. Start the watcher in another window:  .\07_monitor.ps1 -AutoHeal" -ForegroundColor Green
