# 06_firewall.ps1 - Windows Firewall on the DC with AUTO-ROLLBACK (like 06_firewall.sh on Linux).
#   .\06_firewall.ps1 [-Strict] [-TeamNet 172.16.X.0/24] [-ExtraTcp 8080,9000] [-RollbackSeconds 60] [-DryRun]
# Always allowed from ANYWHERE (scored): ICMP echo, SSH 22, LDAP 389/636, WinRM 5985/5986.
# From the team subnet only: RDP 3389 + Active Directory/DNS/SMB/RPC (so domain members + jumpboxes keep working).
# Default mode : firewall ON for all profiles, default inbound = Block, GDDC allow rules added, and dangerous
#                remote-management rule GROUPS (remote service/task/registry/WMI/DCOM/...) disabled.
# -Strict      : additionally DISABLE every other enabled inbound allow rule (export kept) - tightest, but verify AD still works.
# A scheduled task re-imports the OLD policy after -RollbackSeconds unless you type KEEP.
param([switch]$Strict, [string]$TeamNet, [int[]]$ExtraTcp = @(), [int]$RollbackSeconds = 60, [switch]$DryRun)
. "$PSScriptRoot\common.ps1"; Require-Admin
if (-not $TeamNet) { $TeamNet = Get-TeamNet }; if (-not $TeamNet) { Warn 'could not detect 172.16.X.0/24 - pass -TeamNet; AD/RDP rules will allow ANY source until you do' }
$src = if ($TeamNet) { $TeamNet } else { 'Any' }
$prev = "$GddcHome\fw-previous-$TS.wfw"; $disabledList = "$GddcHome\fw-disabled-$TS.txt"
Hdr "Firewall plan (team net: $src, strict: $Strict)"
if ($DryRun) { Info 'dry-run: nothing applied'; return }
Set-Service mpssvc -StartupType Automatic -ErrorAction SilentlyContinue; Start-Service mpssvc -ErrorAction SilentlyContinue
netsh advfirewall export $prev | Out-Null; Ok "current policy exported to $prev"

# ---- rollback watchdog (survives a dead SSH/RDP session)
$tn = 'GDDC-FW-Rollback'; Unregister-ScheduledTask -TaskName $tn -Confirm:$false -ErrorAction SilentlyContinue
$act = New-ScheduledTaskAction -Execute 'netsh.exe' -Argument "advfirewall import `"$prev`""
Register-ScheduledTask -TaskName $tn -Action $act -Trigger (New-ScheduledTaskTrigger -Once -At (Get-Date).AddSeconds($RollbackSeconds)) -User 'SYSTEM' -RunLevel Highest -Force | Out-Null
Info "rollback armed for ${RollbackSeconds}s"

# ---- policy
Get-NetFirewallRule -Group 'GDDC' -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue
Set-NetFirewallProfile -Profile Domain,Private,Public -Enabled True -DefaultInboundAction Block -DefaultOutboundAction Allow -NotifyOnListen False -LogBlocked True -LogMaxSizeKilobytes 16384
function Allow($name, $proto, $ports, $remote = 'Any') { $p = @{ DisplayName="GDDC $name"; Group='GDDC'; Direction='Inbound'; Action='Allow'; Protocol=$proto; Profile='Any'; RemoteAddress=$remote }; if ($ports) { $p.LocalPort = $ports }; New-NetFirewallRule @p | Out-Null }
New-NetFirewallRule -DisplayName 'GDDC ICMPv4 echo' -Group GDDC -Direction Inbound -Action Allow -Protocol ICMPv4 -IcmpType 8 -Profile Any | Out-Null
New-NetFirewallRule -DisplayName 'GDDC ICMPv6 echo' -Group GDDC -Direction Inbound -Action Allow -Protocol ICMPv6 -IcmpType 128 -Profile Any | Out-Null
Allow 'SSH' TCP 22; Allow 'LDAP tcp' TCP @(389,636); Allow 'LDAP udp' UDP 389; Allow 'WinRM' TCP @(5985,5986)
foreach ($x in $ExtraTcp) { Allow "extra $x" TCP $x }
Allow 'RDP (team)' TCP 3389 $src
Allow 'AD/DNS/Kerberos/SMB (team) tcp' TCP @(53,88,135,139,445,464,3268,3269,9389,'49152-65535') $src
Allow 'AD/DNS/Kerberos (team) udp' UDP @(53,88,123,137,138,464) $src
Ok 'GDDC allow rules created; default inbound = BLOCK on all profiles'

$risky = 'Remote Service Management','Remote Scheduled Tasks Management','Remote Event Log Management','Remote Volume Management','Windows Management Instrumentation (WMI)','COM+ Network Access','COM+ Remote Administration','Network Discovery','Performance Logs and Alerts','Windows Remote Management (Compatibility)','Routing and Remote Access','Distributed Transaction Coordinator','Remote Shutdown','Wireless Portable Devices','mDNS','Cast to Device functionality','Delivery Optimization'
foreach ($g in $risky) { Get-NetFirewallRule -DisplayGroup $g -Direction Inbound -Enabled True -ErrorAction SilentlyContinue | ForEach-Object { Add-Content $disabledList $_.Name; Disable-NetFirewallRule -Name $_.Name; Warn "disabled rule: $($_.DisplayName)" } }
if ($Strict) {
    Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | Where-Object { $_.Group -ne 'GDDC' -and $_.DisplayName -notmatch 'Windows Remote Management|OpenSSH|SSH' } | ForEach-Object { Add-Content $disabledList $_.Name; Disable-NetFirewallRule -Name $_.Name }
    Warn "STRICT: every other inbound allow rule disabled (list: $disabledList). If AD/DNS/replication misbehave: Get-Content $disabledList | % { Enable-NetFirewallRule -Name `$_ }" }

Write-Host ''; Warn 'TEST NOW from a jumpbox: ping, ssh, ldapsearch, evil-winrm/Enter-PSSession - and watch the scoreboard.'
$t0 = Get-Date; $a = Read-Host "Everything still green? Type KEEP within ${RollbackSeconds}s to keep this firewall (otherwise it rolls back)"
if ($a -eq 'KEEP' -and ((Get-Date) - $t0).TotalSeconds -lt $RollbackSeconds) { Unregister-ScheduledTask -TaskName $tn -Confirm:$false; Ok 'confirmed - firewall kept, rollback cancelled' }
else { Bad 'not confirmed in time - previous policy is (being) restored' }
Info "Undo any time:  netsh advfirewall import `"$prev`""
