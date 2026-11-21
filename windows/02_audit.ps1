# 02_audit.ps1 - READ-ONLY hunt for persistence / misconfig on the Windows DC. Changes nothing. Look for [FLAG] lines.
#   .\02_audit.ps1 [-RecentDays 3]      Report: C:\gddc\audit-<host>-<ts>.txt
param([int]$RecentDays = 3)
. "$PSScriptRoot\common.ps1"; Require-Admin
Start-Transcript -Path "$GddcHome\audit-$env:COMPUTERNAME-$TS.txt" -Append | Out-Null
$since = (Get-Date).AddDays(-$RecentDays); $DC = Is-DC; $AD = $DC -and (Import-AD)

Hdr 'System'; Get-ComputerInfo -Property CsName,OsName,OsVersion,CsDomain -ErrorAction SilentlyContinue | Format-List; Get-Date; quser 2>$null

Hdr 'Local users / local Administrators'
Get-LocalUser | ForEach-Object { "{0,-20} enabled={1} pwdRequired={2} lastSet={3}" -f $_.Name,$_.Enabled,$_.PasswordRequired,$_.PasswordLastSet
    if ($_.Enabled -and -not $_.PasswordRequired) { Flag "local user without password requirement: $($_.Name)" } }
if (-not $DC) { Get-LocalGroupMember Administrators | ForEach-Object { if ($_.Name -notmatch '\\Administrator$|Domain Admins|Enterprise Admins') { Flag "local Administrators member: $($_.Name)" } } }

if ($AD) {
    Hdr 'Privileged AD groups (default = only Administrator)'
    $defaults = @{ 'Domain Admins'=@('Administrator'); 'Enterprise Admins'=@('Administrator'); 'Schema Admins'=@('Administrator'); 'Administrators'=@('Administrator','Domain Admins','Enterprise Admins');
                   'Group Policy Creator Owners'=@('Administrator'); 'Account Operators'=@(); 'Backup Operators'=@(); 'Server Operators'=@(); 'Print Operators'=@(); 'DnsAdmins'=@(); 'Remote Management Users'=@(); 'Remote Desktop Users'=@() }
    foreach ($g in $defaults.Keys) { $m = @(Get-ADGroupMember $g -ErrorAction SilentlyContinue)
        foreach ($x in $m) { if ($defaults[$g] -notcontains $x.SamAccountName) { $sc = if (Is-Scored $x.SamAccountName) { ' (scored user - leave alone)' } else { '' }; Flag "$g member: $($x.SamAccountName)$sc" } } }
    Hdr 'AD user attack surface'
    Get-ADUser -Filter * -Properties whenCreated,PasswordNotRequired,DoesNotRequirePreAuth,TrustedForDelegation,TrustedToAuthForDelegation,ServicePrincipalName,AdminCount,AllowReversiblePasswordEncryption,SIDHistory,Enabled,PasswordNeverExpires,UseDESKeyOnly | ForEach-Object {
        $n = $_.SamAccountName
        if ($_.whenCreated -gt $since -and -not (Is-Scored $n)) { Flag "user created in last $RecentDays d: $n ($($_.whenCreated))" }
        if ($_.Enabled -and $_.DoesNotRequirePreAuth) { Flag "AS-REP roastable (no Kerberos pre-auth): $n" }
        if ($_.ServicePrincipalName.Count -gt 0 -and $n -ne 'krbtgt') { Flag "user has SPN (kerberoastable): $n -> $($_.ServicePrincipalName -join ',')" }
        if ($_.TrustedForDelegation -or $_.TrustedToAuthForDelegation) { Flag "user trusted for delegation: $n" }
        if ($_.Enabled -and $_.PasswordNotRequired) { Flag "PASSWD_NOTREQD set: $n" }
        if ($_.AllowReversiblePasswordEncryption) { Flag "reversible password encryption: $n" }
        if ($_.UseDESKeyOnly) { Flag "DES-only Kerberos: $n" }
        if ($_.SIDHistory.Count -gt 0) { Flag "SIDHistory present: $n" } }
    Get-ADComputer -Filter {TrustedForDelegation -eq $true} | Where-Object { $_.DistinguishedName -notmatch 'OU=Domain Controllers' } | ForEach-Object { Flag "computer with unconstrained delegation: $($_.Name)" }
    Hdr 'DCSync / dangerous ACEs on the domain root and AdminSDHolder'
    $dn = (Get-ADDomain).DistinguishedName; $guids = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ad-9c07-11d1-f79f-00c04fc2dcd2','89e95b76-444d-4c62-991a-0facbeda640c'
    $okIds = 'NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS|\\Domain Controllers|BUILTIN\\Administrators|\\Enterprise Read-only Domain Controllers|NT AUTHORITY\\SYSTEM|\\Domain Admins|\\Enterprise Admins|CREATOR OWNER|\\Cloneable|Key Admins|Enterprise Key Admins'
    foreach ($obj in $dn,"CN=AdminSDHolder,CN=System,$dn") { (Get-Acl "AD:$obj").Access | Where-Object { $_.AccessControlType -eq 'Allow' -and "$($_.IdentityReference)" -notmatch $okIds -and
        ( ($guids -contains "$($_.ObjectType)") -or ($_.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner') ) } | ForEach-Object { Flag "risky ACE on $obj : $($_.IdentityReference) $($_.ActiveDirectoryRights) $($_.ObjectType)" } }
    Hdr 'Domain settings'
    $maq = (Get-ADObject -Identity $dn -Properties 'ms-DS-MachineAccountQuota').'ms-DS-MachineAccountQuota'; if ($maq -gt 0) { Flag "MachineAccountQuota=$maq (any user can add computers; set 0)" }
    $dsh = (Get-ADObject "CN=Directory Service,CN=Windows NT,CN=Services,CN=Configuration,$dn" -Properties dsHeuristics).dsHeuristics; if ($dsh) { Flag "dsHeuristics is set: '$dsh' (7th char '2' = anonymous LDAP access)" }
    Get-ADTrust -Filter * -ErrorAction SilentlyContinue | ForEach-Object { Flag "domain trust: $($_.Name)" }
    Hdr 'GPOs'
    Get-GPO -All | ForEach-Object { "{0,-40} modified {1}" -f $_.DisplayName,$_.ModificationTime; if ($_.ModificationTime -gt $since) { Flag "GPO modified recently: $($_.DisplayName)" } }
    $sys = "$env:SystemRoot\SYSVOL\domain"; if (Test-Path $sys) {
        Get-ChildItem $sys -Recurse -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -match '\.(ps1|bat|cmd|vbs|js|exe|dll)$|^(ScheduledTasks|Services|Groups|Files|Registry|Printers)\.xml$' } | ForEach-Object { Flag "SYSVOL item to review: $($_.FullName)" }
        Select-String -Path "$sys\*\*.xml","$sys\Policies\*\*\*\*\*.xml" -Pattern 'cpassword' -ErrorAction SilentlyContinue | ForEach-Object { Flag "GPP cpassword: $($_.Path)" } }
    if ((Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue).DsrmAdminLogonBehavior -ge 1) { Flag 'DsrmAdminLogonBehavior set (DSRM admin can log on while AD is up)' }
}

Hdr 'Persistence: Run keys / Winlogon / IFEO / AppInit / LSA'
foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run') {
    if (Test-Path $k) { (Get-ItemProperty $k).PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { Flag "autorun: $k  $($_.Name) = $($_.Value)" } } }
$wl = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'
if ($wl.Shell -ne 'explorer.exe') { Flag "Winlogon Shell = $($wl.Shell)" }; if ($wl.Userinit -notmatch '^C:\\Windows\\system32\\userinit\.exe,?$') { Flag "Winlogon Userinit = $($wl.Userinit)" }
if ($wl.Taskman) { Flag "Winlogon Taskman = $($wl.Taskman)" }; if ($wl.AutoAdminLogon -eq '1') { Flag "AutoAdminLogon on (DefaultPassword stored in registry: $([bool]$wl.DefaultPassword))" }
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue | ForEach-Object { $p = Get-ItemProperty $_.PSPath; if ($p.Debugger) { Flag "IFEO debugger hijack: $($_.PSChildName) -> $($p.Debugger)" } }
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\SilentProcessExit' -ErrorAction SilentlyContinue | ForEach-Object { Flag "SilentProcessExit entry: $($_.PSChildName)" }
$ai = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'; if ($ai.AppInit_DLLs) { Flag "AppInit_DLLs = $($ai.AppInit_DLLs)" }
$lsa = Get-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa'
foreach ($n in 'Authentication Packages','Notification Packages','Security Packages') { $v = @($lsa.$n) | Where-Object { $_ -and $_ -notmatch '^(msv1_0|kerberos|wdigest|tspkg|pku2u|cloudAP|scecli|rassfm|"")$' }; if ($v) { Flag "LSA $n unusual: $($v -join ',')" } }
if ($lsa.RunAsPPL -ne 1) { Warn 'LSA protection (RunAsPPL) off' }

Hdr 'Scheduled tasks outside \Microsoft\'
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object {
    $a = ($_.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | '; Flag "task $($_.TaskPath)$($_.TaskName) [$($_.State)] runs as $($_.Principal.UserId): $a" }
Hdr 'Services with suspicious paths / created recently'
Get-CimInstance Win32_Service | ForEach-Object { $p = $_.PathName
    if ($p -match '(?i)\\(temp|users|programdata|appdata|downloads)\\|powershell|cmd(\.exe)?\s+/c|mshta|rundll32|regsvr32|wscript|cscript|-enc|FromBase64') { Flag "service $($_.Name) [$($_.State)] path: $p" }
    elseif ($p -match '^[A-Za-z]:\\[^"]*\s[^"]*\.exe' -and $p -notmatch '^"') { Warn "unquoted service path: $($_.Name): $p" } }
Get-WinEvent -FilterHashtable @{LogName='System';Id=7045;StartTime=$since} -ErrorAction SilentlyContinue | ForEach-Object { Flag "service installed $($_.TimeCreated): $($_.Properties[0].Value) -> $($_.Properties[1].Value)" }
Hdr 'WMI event subscriptions'
foreach ($c in '__EventFilter','CommandLineEventConsumer','ActiveScriptEventConsumer','__FilterToConsumerBinding') { Get-CimInstance -Namespace root\subscription -ClassName $c -ErrorAction SilentlyContinue | ForEach-Object { Flag "WMI $c : $($_ | Out-String -Width 200)" } }
Hdr 'Startup folders / PowerShell profiles / accessibility binaries'
foreach ($d in "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",'C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup') { Get-ChildItem $d -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object { Flag "startup item: $($_.FullName)" } }
foreach ($p in "$PSHOME\profile.ps1","$PSHOME\Microsoft.PowerShell_profile.ps1",'C:\Users\*\Documents\WindowsPowerShell\*profile.ps1','C:\Users\*\Documents\PowerShell\*profile.ps1') { Get-ChildItem $p -ErrorAction SilentlyContinue | ForEach-Object { Flag "PowerShell profile: $($_.FullName)" } }
$cmdHash = (Get-FileHash "$env:SystemRoot\System32\cmd.exe").Hash; $psHash = (Get-FileHash "$env:SystemRoot\System32\WindowsPowerShell\v1.0\powershell.exe").Hash
foreach ($f in 'sethc','utilman','osk','narrator','magnify','displayswitch','atbroker') { $p = "$env:SystemRoot\System32\$f.exe"; if (Test-Path $p) { $h = (Get-FileHash $p).Hash; $s = (Get-AuthenticodeSignature $p).Status
    if ($h -eq $cmdHash -or $h -eq $psHash -or $s -ne 'Valid') { Flag "accessibility binary replaced/unsigned: $p (sig=$s)" } } }
Hdr 'Network'
$expected = 22,53,88,123,135,139,389,445,464,593,636,3268,3269,3389,5985,5986,9389,47001,49664,49665,49666,49667,5357,5040
Get-NetTCPConnection -State Listen | Where-Object { $_.LocalAddress -notin '127.0.0.1','::1' } | Sort-Object LocalPort -Unique | ForEach-Object {
    $pr = Get-CimInstance Win32_Process -Filter "ProcessId=$($_.OwningProcess)" -ErrorAction SilentlyContinue; $line = "tcp/{0} {1} pid={2} {3}" -f $_.LocalPort,$_.LocalAddress,$_.OwningProcess,$pr.ExecutablePath
    if ($_.LocalPort -lt 49152 -and $expected -notcontains $_.LocalPort) { Flag "unexpected listener: $line" } else { $line } }
Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notmatch '^(172\.16\.|127\.|::1|0\.)' } | ForEach-Object { Flag "external connection: $($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort) pid=$($_.OwningProcess) $((Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path)" }
Get-SmbShare | Where-Object { $_.Name -notmatch '^(ADMIN\$|C\$|IPC\$|NETLOGON|SYSVOL|[A-Z]\$)$' } | ForEach-Object { Flag "non-default SMB share: $($_.Name) -> $($_.Path)" }
Get-Content "$env:SystemRoot\System32\drivers\etc\hosts" | Where-Object { $_ -notmatch '^\s*(#|$)' } | ForEach-Object { Flag "hosts entry: $_" }
Get-NetFirewallProfile | ForEach-Object { if (-not $_.Enabled) { Flag "firewall profile $($_.Name) DISABLED" } }
Hdr 'Defender'
try { $m = Get-MpComputerStatus; "RealTime=$($m.RealTimeProtectionEnabled) AV=$($m.AntivirusEnabled) SigAge=$($m.AntivirusSignatureAge)d"; if (-not $m.RealTimeProtectionEnabled) { Flag 'Defender real-time protection OFF' }
    $pf = Get-MpPreference; @($pf.ExclusionPath) + @($pf.ExclusionProcess) + @($pf.ExclusionExtension) | Where-Object { $_ } | ForEach-Object { Flag "Defender exclusion: $_" } } catch { Warn "Defender not queryable: $_" }
Hdr 'Weak settings'
function Chk($path,$name,$bad,$msg) { $v = (Get-ItemProperty $path -ErrorAction SilentlyContinue).$name; if (& $bad $v) { Flag "$msg (current: $v)" } }
Chk 'HKLM:\SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest' UseLogonCredential { param($v) $v -eq 1 } 'WDigest stores cleartext creds'
Chk 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' LmCompatibilityLevel { param($v) $v -ne $null -and $v -lt 3 } 'LM/NTLMv1 allowed'
Chk 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' RestrictAnonymous { param($v) -not $v } 'anonymous enumeration not restricted'
Chk 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\Installer' AlwaysInstallElevated { param($v) $v -eq 1 } 'AlwaysInstallElevated (HKLM)'
Chk 'HKCU:\SOFTWARE\Policies\Microsoft\Windows\Installer' AlwaysInstallElevated { param($v) $v -eq 1 } 'AlwaysInstallElevated (HKCU)'
Chk 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters' FullSecureChannelProtection { param($v) $v -ne 1 } 'Zerologon enforcement not set'
Chk 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp' UserAuthentication { param($v) $v -eq 0 } 'RDP NLA off'
try { if ((Get-SmbServerConfiguration).EnableSMB1Protocol) { Flag 'SMBv1 enabled' }; if (-not (Get-SmbServerConfiguration).RequireSecuritySignature) { Warn 'SMB signing not required' } } catch {}
if ((Get-Service Spooler -ErrorAction SilentlyContinue).Status -eq 'Running' -and $DC) { Flag 'Print Spooler running on a DC (PrintNightmare/coercion)' }
Hdr 'OpenSSH server'
$sc = Get-SshdConfigPath; Get-Service sshd -ErrorAction SilentlyContinue | Format-Table Name,Status,StartType -AutoSize
if (Test-Path $sc) { Select-String -Path $sc -Pattern '^\s*(Match|ForceCommand|AuthorizedKeys|PermitEmptyPasswords|PermitRootLogin|PasswordAuthentication|Subsystem|AllowUsers|DenyUsers|AllowGroups)' | ForEach-Object { "  $($_.Line)" } }
foreach ($f in 'C:\ProgramData\ssh\administrators_authorized_keys','C:\Users\*\.ssh\authorized_keys') { Get-ChildItem $f -ErrorAction SilentlyContinue | Where-Object { $_.Length -gt 0 } | ForEach-Object { Flag "authorized_keys present: $($_.FullName)"; Get-Content $_.FullName | ForEach-Object { '     ' + $_.Substring(0,[Math]::Min(70,$_.Length)) } } }
Hdr 'Recent file drops / log clearing / account events'
foreach ($d in "$env:SystemRoot\Temp",'C:\Users\*\AppData\Local\Temp','C:\Users\Public','C:\ProgramData',"$env:SystemRoot\Tasks","$env:SystemRoot\System32\Tasks") {
    Get-ChildItem $d -Recurse -Force -File -ErrorAction SilentlyContinue | Where-Object { $_.CreationTime -gt $since -and $_.Extension -match '\.(exe|dll|ps1|bat|cmd|vbs|js|hta|scr|lnk|sys)$' } | Select-Object -First 15 | ForEach-Object { Flag "recent executable/script: $($_.FullName) ($($_.CreationTime))" } }
Get-WinEvent -FilterHashtable @{LogName='Security';Id=1102;StartTime=$since} -ErrorAction SilentlyContinue | ForEach-Object { Flag "SECURITY LOG CLEARED $($_.TimeCreated)" }
foreach ($id in 4720,4722,4728,4732,4756,4724,4698) { $e = Get-WinEvent -FilterHashtable @{LogName='Security';Id=$id;StartTime=$since} -ErrorAction SilentlyContinue; if ($e) { "event $id x$($e.Count) (4720 user created, 4728/4732/4756 group add, 4724 pw reset, 4698 task created)" } }
Hdr 'SUMMARY'; "Total [FLAG] items: $Script:Flags   Report: $GddcHome\audit-$env:COMPUTERNAME-$TS.txt"
"Review every flag. Delete implants only after confirming no scored service needs them (SSH/LDAP/WinRM/DNS/NTDS)."
Stop-Transcript | Out-Null
