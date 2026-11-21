# 04_harden.ps1 - OS/AD hardening that does NOT touch the scored services (ICMP, SSH, LDAP, WinRM).
#   .\04_harden.ps1 [-LdapSigning] [-KeepSpooler] [-KeepSshKeys] [-RemoveDefenderExclusions] [-DryRun]
#   -LdapSigning   REQUIRE LDAP signing (off by default: the scoring engine may use a plain simple bind and would go red)
param([switch]$LdapSigning, [switch]$KeepSpooler, [switch]$KeepSshKeys, [switch]$RemoveDefenderExclusions, [switch]$DryRun)
. "$PSScriptRoot\common.ps1"; Require-Admin; $DC = Is-DC
function R($path,$name,$val,$type='DWord') { if ($DryRun) { Write-Host "   [dry-run] $path\$name = $val" } else { if (Set-Reg $path $name $val $type) { Write-Log 'SET ' "$path\$name=$val" } } }

Hdr 'Credential / protocol hardening'
$lsa = 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
R "$lsa" LmCompatibilityLevel 5; R "$lsa" NoLMHash 1; R "$lsa" RestrictAnonymous 1; R "$lsa" RestrictAnonymousSAM 1; R "$lsa" EveryoneIncludesAnonymous 0
R 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' UseLogonCredential 0
R 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' FullSecureChannelProtection 1
R 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' RequireSignOrSeal 1
R 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' AlwaysInstallElevated 0
R 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' EnableMulticast 0       # LLMNR off
R 'HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient' EnableMDNS 0
R 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer' NoDriveTypeAutoRun 255
R 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' UserAuthentication 1   # RDP stays ON (Cloudflare uses it) but needs NLA
R 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' AutoAdminLogon '0' 'String'
if (-not $DryRun) { Remove-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon' -Name DefaultPassword -ErrorAction SilentlyContinue }
if ($LdapSigning) { R 'HKLM:\SYSTEM\CurrentControlSet\Services\NTDS\Parameters' LDAPServerIntegrity 2; Warn 'LDAP signing REQUIRED - watch the scoreboard LDAP check; undo: set LDAPServerIntegrity=1' }
else { Info 'LDAP signing left as-is (use -LdapSigning only if the LDAP check stays green)' }
try { if (-not $DryRun) { Set-SmbServerConfiguration -EnableSMB1Protocol $false -RequireSecuritySignature $true -EnableSecuritySignature $true -Force -Confirm:$false; Ok 'SMB1 off, SMB signing required' } } catch { Warn "SMB config: $_" }
if (-not $DryRun) { try { Disable-WindowsOptionalFeature -Online -FeatureName MicrosoftWindowsPowerShellV2Root -NoRestart -ErrorAction Stop | Out-Null; Ok 'PowerShell v2 removed' } catch { Info 'PowerShell v2 feature not removable here' } }
Get-CimInstance Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true' | ForEach-Object { if (-not $DryRun) { $null = Invoke-CimMethod -InputObject $_ -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions=2} } }; Ok 'NetBIOS over TCP disabled'

Hdr 'Services not needed on a DC (scored services untouched)'
$kill = @('RemoteRegistry','SSDPSRV','upnphost','WebClient','Fax','TlntSvr','SNMP','FTPSVC','W3SVC','SharedAccess','XblAuthManager','XblGameSave','lltdsvc','icssvc','MapsBroker','RasMan','RemoteAccess','WinHttpAutoProxySvc')
if (-not $KeepSpooler) { $kill += 'Spooler' }
foreach ($s in $kill) { $svc = Get-Service $s -ErrorAction SilentlyContinue; if ($svc -and $svc.StartType -ne 'Disabled') { Warn "disabling $s"; if (-not $DryRun) { Stop-Service $s -Force -ErrorAction SilentlyContinue; Set-Service $s -StartupType Disabled } } }

Hdr 'Logging (for incident reports / Gold Team)'
if (-not $DryRun) {
    foreach ($c in 'Logon','Logoff','Account Lockout','Special Logon','User Account Management','Security Group Management','Computer Account Management','Directory Service Changes','Directory Service Access','Process Creation','Security State Change','Security System Extension','Audit Policy Change','Authentication Policy Change','Sensitive Privilege Use','Kerberos Service Ticket Operations','Kerberos Authentication Service','Credential Validation','Other Object Access Events','File Share') { auditpol /set /subcategory:"$c" /success:enable /failure:enable 2>$null | Out-Null }
    wevtutil sl Security /ms:536870912; wevtutil sl 'Windows PowerShell' /ms:67108864; wevtutil sl System /ms:67108864; Ok 'advanced audit policy on, Security log = 512 MB'
}
R 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit' ProcessCreationIncludeCmdLine_Enabled 1
R 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging' EnableScriptBlockLogging 1
R 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ModuleLogging' EnableModuleLogging 1

Hdr 'Defender'
try { if (-not $DryRun) { Set-MpPreference -DisableRealtimeMonitoring $false -DisableBehaviorMonitoring $false -DisableIOAVProtection $false -DisableScriptScanning $false -MAPSReporting 0 -SubmitSamplesConsent 2 -ErrorAction Stop; Ok 'Defender real-time/behaviour/script scanning ON' }
    $pf = Get-MpPreference; $ex = @($pf.ExclusionPath) + @($pf.ExclusionProcess) + @($pf.ExclusionExtension) | Where-Object { $_ }
    foreach ($e in $ex) { Warn "Defender exclusion present: $e"; if ($RemoveDefenderExclusions -and -not $DryRun) { Remove-MpPreference -ExclusionPath $e -ExclusionProcess $e -ExclusionExtension $e -ErrorAction SilentlyContinue } }
    if ($ex -and -not $RemoveDefenderExclusions) { Info 're-run with -RemoveDefenderExclusions to clear them' } } catch { Warn "Defender: $_ (third-party AV or Defender removed?)" }

Hdr 'OpenSSH server (scored): harden without breaking password logins'
$cfg = Get-SshdConfigPath
if (Test-Path $cfg) {
    $bk = "$GddcHome\sshd_config.$TS.bak"; Copy-Item $cfg $bk -Force
    $old = Get-Content $cfg -Raw; $old = [regex]::Replace($old,'(?ms)^# BEGIN GDDC.*?^# END GDDC\r?\n?','')
    $blk = "# BEGIN GDDC (first match wins - keep at top)`nPermitEmptyPasswords no`nPermitUserEnvironment no`nHostbasedAuthentication no`nIgnoreRhosts yes`nAllowAgentForwarding no`nAllowTcpForwarding no`nGatewayPorts no`nPermitTunnel no`nMaxAuthTries 4`nLoginGraceTime 30`nLogLevel VERBOSE`nPasswordAuthentication yes`n# END GDDC`n"
    $new = "$cfg.new"; [IO.File]::WriteAllText($new, $blk + $old, (New-Object Text.UTF8Encoding($false)))
    $t = & "$env:SystemRoot\System32\OpenSSH\sshd.exe" -t -f $new 2>&1
    if ($LASTEXITCODE -eq 0 -and -not $DryRun) {
        Move-Item $new $cfg -Force; Restart-Service sshd -ErrorAction SilentlyContinue; Start-Sleep 2
        if ((Get-Service sshd).Status -eq 'Running' -and (Get-NetTCPConnection -LocalPort 22 -State Listen -ErrorAction SilentlyContinue)) { Ok 'sshd hardened and listening on 22' }
        else { Bad 'sshd not healthy - restoring old config'; Copy-Item $bk $cfg -Force; Restart-Service sshd }
    } else { Remove-Item $new -Force -ErrorAction SilentlyContinue; if ($LASTEXITCODE -ne 0) { Bad "sshd -t rejected the new config (kept old): $t" } }
    Select-String -Path $cfg -Pattern '^\s*Match' | ForEach-Object { Warn "Match block in sshd_config - review: $($_.Line)" }
    $ak = 'C:\ProgramData\ssh\administrators_authorized_keys'
    if ((Test-Path $ak) -and (Get-Item $ak).Length -gt 0) { if ($KeepSshKeys) { Warn "KEYS in $ak (kept) - review" } else { Copy-Item $ak "$GddcHome\administrators_authorized_keys.$TS.bak"; if (-not $DryRun) { Clear-Content $ak }; Warn "emptied $ak (backup in $GddcHome)" } }
    Get-ChildItem 'C:\Users\*\.ssh\authorized_keys' -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 0 } | ForEach-Object { Warn "KEYS present: $($_.FullName) - review/clear if unknown" }
} else { Warn 'no sshd_config - OpenSSH server not installed? (SSH is scored: Add-WindowsCapability -Online -Name OpenSSH.Server~~~~0.0.1.0)' }
Set-Service sshd -StartupType Automatic -ErrorAction SilentlyContinue; Start-Service sshd -ErrorAction SilentlyContinue

Hdr 'WinRM (scored): make sure it is listening'
Set-Service WinRM -StartupType Automatic -ErrorAction SilentlyContinue; Start-Service WinRM -ErrorAction SilentlyContinue
if (-not (Get-NetTCPConnection -LocalPort 5985 -State Listen -ErrorAction SilentlyContinue)) { Warn 'WinRM not listening - enabling'; if (-not $DryRun) { Enable-PSRemoting -SkipNetworkProfileCheck -Force | Out-Null } } else { Ok 'WinRM listening on 5985' }
if ($DC) { Hdr 'DC services (scored: LDAP)'; foreach ($s in 'NTDS','DNS','Netlogon','KDC') { $v = Get-Service $s -ErrorAction SilentlyContinue; if ($v) { "{0,-10} {1}" -f $s,$v.Status; if ($v.Status -ne 'Running') { Warn "$s is $($v.Status)" } } } }
Ok 'Hardening done. Now run .\05_persistence_clean.ps1 then .\06_firewall.ps1'
