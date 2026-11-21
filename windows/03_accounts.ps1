# 03_accounts.ps1 - credential rotation + AD/account cleanup on the Windows DC.
# SCORED USERS ARE NEVER MODIFIED (password, groups, enabled state) - scoring logs in as them (WinRM needs them to keep their group rights).
#   .\03_accounts.ps1 [-NewPass X] [-RotateKrbtgt] [-RemoveUnknownAdmins] [-DisableRecentUsers] [-FixAcls] [-KickSessions] [-DryRun]
#   -RotateKrbtgt         reset krbtgt twice (kills golden tickets; brief auth hiccups for logged-in sessions)
#   -RemoveUnknownAdmins  remove non-default, non-scored members from privileged groups
#   -DisableRecentUsers   disable (not delete) non-scored AD users created in the last 3 days (see audit for names)
#   -FixAcls              strip non-default DCSync / GenericAll / WriteDacl ACEs from the domain root + AdminSDHolder
param([string]$NewPass, [switch]$RotateKrbtgt, [switch]$RemoveUnknownAdmins, [switch]$DisableRecentUsers, [switch]$FixAcls, [switch]$KickSessions, [switch]$DryRun)
. "$PSScriptRoot\common.ps1"; Require-Admin
$DC = Is-DC; $AD = $DC -and (Import-AD)
$PW = Join-Path $GddcHome "passwords-$env:COMPUTERNAME-$TS.txt"; New-Item -ItemType File -Force -Path $PW | Out-Null; Protect-File $PW
function Run($desc, [scriptblock]$sb) { if ($DryRun) { Write-Host "   [dry-run] $desc" } else { try { & $sb; Ok $desc } catch { Bad "$desc FAILED: $_" } } }
function Rotate($sam) {
    $p = if ($NewPass) { $NewPass } else { New-GddcPassword }; $sec = ConvertTo-SecureString $p -AsPlainText -Force
    if ($DryRun) { Write-Host "   [dry-run] would rotate $sam"; return }
    try { if ($AD) { Set-ADAccountPassword -Identity $sam -Reset -NewPassword $sec -ErrorAction Stop; Unlock-ADAccount $sam -ErrorAction SilentlyContinue } else { Set-LocalUser -Name $sam -Password $sec -ErrorAction Stop }
          Add-Content $PW ("{0,-20} {1}" -f $sam,$p); Ok "rotated $sam" } catch { Bad "rotate $sam failed: $_" }
}

Hdr '1. Administrator + other accounts'
Rotate 'Administrator'
if ($AD) {
    Get-ADUser -Filter 'Enabled -eq $true' | Where-Object { $_.SamAccountName -notin 'Administrator','krbtgt','Guest','DefaultAccount' -and -not (Is-Scored $_.SamAccountName) -and $_.SamAccountName -notmatch '\$$' } | ForEach-Object { Rotate $_.SamAccountName }
} else { Get-LocalUser | Where-Object { $_.Enabled -and $_.Name -notin 'Administrator' -and -not (Is-Scored $_.Name) } | ForEach-Object { Rotate $_.Name } }
foreach ($g in 'Guest','DefaultAccount','WDAGUtilityAccount') { if ($AD) { Run "disable AD $g" { Disable-ADAccount $g } } else { Run "disable local $g" { Disable-LocalUser $g } } }

if ($AD) {
    Hdr '2. Privileged group hygiene'
    $defaults = @{ 'Domain Admins'=@('Administrator'); 'Enterprise Admins'=@('Administrator'); 'Schema Admins'=@('Administrator'); 'Administrators'=@('Administrator','Domain Admins','Enterprise Admins'); 'Group Policy Creator Owners'=@('Administrator');
                   'Account Operators'=@(); 'Backup Operators'=@(); 'Server Operators'=@(); 'Print Operators'=@(); 'DnsAdmins'=@() }
    foreach ($g in $defaults.Keys) { foreach ($m in @(Get-ADGroupMember $g -ErrorAction SilentlyContinue)) {
        if ($defaults[$g] -contains $m.SamAccountName) { continue }
        if (Is-Scored $m.SamAccountName) { Warn "$($m.SamAccountName) (scored) is in $g - left alone (WinRM may need it)"; continue }
        if ($RemoveUnknownAdmins) { Run "remove $($m.SamAccountName) from $g" { Remove-ADGroupMember $g -Members $m -Confirm:$false } } else { Warn "unknown member of ${g}: $($m.SamAccountName)  (re-run with -RemoveUnknownAdmins)" } } }

    Hdr '3. Dangerous account flags'
    Get-ADUser -Filter * -Properties DoesNotRequirePreAuth,PasswordNotRequired,AllowReversiblePasswordEncryption,TrustedForDelegation,TrustedToAuthForDelegation,ServicePrincipalName,UseDESKeyOnly,SIDHistory,whenCreated | Where-Object { -not (Is-Scored $_.SamAccountName) } | ForEach-Object {
        $u = $_; $n = $u.SamAccountName
        if ($u.DoesNotRequirePreAuth)  { Run "require Kerberos pre-auth: $n" { Set-ADAccountControl $n -DoesNotRequirePreAuth $false } }
        if ($u.PasswordNotRequired)    { Run "password required: $n" { Set-ADAccountControl $n -PasswordNotRequired $false } }
        if ($u.AllowReversiblePasswordEncryption) { Run "no reversible encryption: $n" { Set-ADAccountControl $n -AllowReversiblePasswordEncryption $false } }
        if ($u.TrustedForDelegation -or $u.TrustedToAuthForDelegation) { Run "no delegation: $n" { Set-ADAccountControl $n -TrustedForDelegation $false -TrustedToAuthForDelegation $false } }
        if ($u.UseDESKeyOnly)          { Run "no DES-only: $n" { Set-ADAccountControl $n -UseDESKeyOnly $false } }
        if ($n -ne 'krbtgt' -and $u.ServicePrincipalName.Count -gt 0) { Run "clear SPNs on $n ($($u.ServicePrincipalName -join ','))" { Set-ADUser $n -ServicePrincipalNames @{Remove=$u.ServicePrincipalName} } }
        if ($u.SIDHistory.Count -gt 0) { Run "clear SIDHistory on $n" { Set-ADUser $n -Remove @{SIDHistory=$u.SIDHistory.Value} } }
        if ($DisableRecentUsers -and $u.whenCreated -gt (Get-Date).AddDays(-3) -and $n -notin 'Administrator','krbtgt') { Run "DISABLE recently created user $n" { Disable-ADAccount $n } } }
    Run 'MachineAccountQuota = 0' { Set-ADDomain (Get-ADDomain) -Replace @{'ms-DS-MachineAccountQuota'=0} }

    if ($FixAcls) { Hdr '4. Strip risky ACEs'
        $dn = (Get-ADDomain).DistinguishedName; $guids = '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2','1131f6ad-9c07-11d1-f79f-00c04fc2dcd2','89e95b76-444d-4c62-991a-0facbeda640c'
        $okIds = 'NT AUTHORITY\\ENTERPRISE DOMAIN CONTROLLERS|\\Domain Controllers|BUILTIN\\Administrators|\\Enterprise Read-only Domain Controllers|NT AUTHORITY\\SYSTEM|\\Domain Admins|\\Enterprise Admins|CREATOR OWNER|\\Cloneable|Key Admins|Enterprise Key Admins'
        foreach ($obj in $dn,"CN=AdminSDHolder,CN=System,$dn") { $acl = Get-Acl "AD:$obj"; $changed = $false
            foreach ($ace in @($acl.Access)) { if ($ace.AccessControlType -eq 'Allow' -and "$($ace.IdentityReference)" -notmatch $okIds -and (($guids -contains "$($ace.ObjectType)") -or ($ace.ActiveDirectoryRights -match 'GenericAll|WriteDacl|WriteOwner')) -and -not $ace.IsInherited) {
                Warn "removing ACE on $obj : $($ace.IdentityReference) $($ace.ActiveDirectoryRights)"; if (-not $DryRun) { $acl.RemoveAccessRuleSpecific($ace) | Out-Null; $changed = $true } } }
            if ($changed) { Set-Acl "AD:$obj" $acl; Ok "ACL updated on $obj" } } }

    Hdr '5. DSRM password + logon behaviour'
    $d = if ($NewPass) { $NewPass } else { New-GddcPassword }
    if (-not $DryRun) { $o = & ntdsutil "set dsrm password" "reset password on server null" $d q q 2>&1; if ($LASTEXITCODE -eq 0) { Add-Content $PW ("{0,-20} {1}" -f 'DSRM',$d); Ok 'DSRM password reset' } else { Warn "ntdsutil: $($o -join ' ')" } }
    Remove-ItemProperty 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name DsrmAdminLogonBehavior -ErrorAction SilentlyContinue

    if ($RotateKrbtgt) { Hdr '6. krbtgt (twice)'
        1..2 | ForEach-Object { Run "reset krbtgt pass #$_" { Set-ADAccountPassword krbtgt -Reset -NewPassword (ConvertTo-SecureString (New-GddcPassword) -AsPlainText -Force) } } }
}
if ($KickSessions) { Hdr 'Logging off other sessions'
    $me = $env:USERNAME; quser 2>$null | Select-Object -Skip 1 | ForEach-Object { $t = ($_ -replace '^\s*>?','') -split '\s+'; $u = $t[0]; $id = ($t | Where-Object { $_ -match '^\d+$' } | Select-Object -First 1)
        if ($u -ne $me -and $id) { Warn "logging off $u (session $id)"; Run "logoff $id" { logoff $id } } } }
if ((Get-Item $PW).Length -gt 0) { Write-Host ''; Ok "New passwords (also in $PW, admin-only). SHARE WITH YOUR TEAM NOW:"; Get-Content $PW | ForEach-Object { "     $_" } } else { Remove-Item $PW -Force }
Ok 'Accounts step done.'
