# 01_backup.ps1 - file-level backup + baseline BEFORE changing anything (NOT a VM snapshot - those are penalised).
#   .\01_backup.ps1        (elevated PowerShell)
. "$PSScriptRoot\common.ps1"; Require-Admin
$B = Join-Path $GddcHome "backup-$env:COMPUTERNAME-$TS"; New-Item -ItemType Directory -Force -Path $B, "$GddcHome\baseline" | Out-Null
Hdr 'Exporting configuration'
netsh advfirewall export "$B\firewall.wfw" | Out-Null;           Ok 'firewall policy'
secedit /export /cfg "$B\secpol.inf" /quiet;                      Ok 'local security policy'
foreach ($k in 'HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon','HKLM\SYSTEM\CurrentControlSet\Control\Lsa','HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options') {
    reg export $k "$B\reg_$(($k -replace '[\\ ]','_')).reg" /y | Out-Null }; Ok 'registry hives of interest'
Get-ScheduledTask | ForEach-Object { try { Export-ScheduledTask -TaskName $_.TaskName -TaskPath $_.TaskPath | Out-File "$B\task_$($_.TaskName -replace '[^\w]','_').xml" } catch {} }; Ok 'scheduled tasks'
Get-CimInstance Win32_Service | Select-Object Name,DisplayName,State,StartMode,PathName,StartName | Export-Csv "$B\services.csv" -NoTypeInformation
foreach ($f in 'C:\ProgramData\ssh\sshd_config','C:\ProgramData\ssh\administrators_authorized_keys','C:\Windows\System32\drivers\etc\hosts') { if (Test-Path $f) { Copy-Item $f "$B\$(Split-Path $f -Leaf)" -Force } }; Ok 'sshd_config / authorized keys / hosts'
if (Is-DC -and (Import-AD)) {
    Hdr 'Active Directory'
    try { Backup-GPO -All -Path (New-Item -ItemType Directory -Force "$B\gpo").FullName | Out-Null; Ok 'GPOs backed up' } catch { Warn "GPO backup: $_" }
    Get-ADUser -Filter * -Properties * | Select-Object SamAccountName,Enabled,whenCreated,PasswordLastSet,AdminCount,MemberOf,ServicePrincipalName | Export-Csv "$B\ad_users.csv" -NoTypeInformation
    Get-ADGroup -Filter * | ForEach-Object { $g = $_; Get-ADGroupMember $g -ErrorAction SilentlyContinue | ForEach-Object { [pscustomobject]@{Group=$g.Name;Member=$_.SamAccountName} } } | Export-Csv "$B\ad_groups.csv" -NoTypeInformation
    try { Get-DnsServerZone | ForEach-Object { Export-DnsServerZone -Name $_.ZoneName -FileName "gddc-$($_.ZoneName).dns" -ErrorAction SilentlyContinue }; Ok 'DNS zones exported to %SystemRoot%\System32\dns' } catch {}
    Ok 'AD users/groups exported'
}
Hdr 'Baseline for 07_monitor.ps1'
$bl = "$GddcHome\baseline"
Get-LocalUser | Select-Object Name,Enabled | ConvertTo-Json | Set-Content "$bl\localusers.json"
$priv = 'Administrators','Remote Management Users','Remote Desktop Users'
if (Is-DC -and (Import-AD)) { $priv += 'Domain Admins','Enterprise Admins','Schema Admins','Account Operators','Backup Operators','Server Operators','Print Operators','DnsAdmins','Group Policy Creator Owners'
    Get-ADUser -Filter * | Select-Object -Expand SamAccountName | ConvertTo-Json | Set-Content "$bl\adusers.json" }
$gm = @{}; foreach ($g in $priv) { try { $gm[$g] = @(if (Is-DC) { Get-ADGroupMember $g -ErrorAction Stop | Select-Object -Expand SamAccountName } else { Get-LocalGroupMember $g -ErrorAction Stop | Select-Object -Expand Name }) } catch { } }
$gm | ConvertTo-Json | Set-Content "$bl\groups.json"
Get-ScheduledTask | Select-Object -Expand TaskName | ConvertTo-Json | Set-Content "$bl\tasks.json"
Get-CimInstance Win32_Service | Select-Object -Expand Name | ConvertTo-Json | Set-Content "$bl\services.json"
Get-NetTCPConnection -State Listen | Select-Object -Expand LocalPort -Unique | ConvertTo-Json | Set-Content "$bl\listeners.json"
Ok "Baseline saved in $bl ; backups in $B"
