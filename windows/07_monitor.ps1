# 07_monitor.ps1 - blue-team watcher for the Windows DC (counterpart to monitor.sh). Run in a spare elevated window.
#   .\07_monitor.ps1 [-Interval 30] [-AutoHeal] [-Enforce]
#   -AutoHeal : restart dead scored services (sshd, WinRM, NTDS, DNS, Netlogon, KDC) and re-enable firewall profiles
#   -Enforce  : remove NEW members of Domain/Enterprise/Schema Admins + Administrators, and DISABLE brand-new non-scored AD users
# Needs the baseline from 01_backup.ps1. Alerts -> console + C:\gddc\alerts.log
param([int]$Interval = 30, [switch]$AutoHeal, [switch]$Enforce)
. "$PSScriptRoot\common.ps1"; Require-Admin
$bl = "$GddcHome\baseline"; if (-not (Test-Path "$bl\groups.json")) { Warn 'no baseline - running 01_backup.ps1'; & "$PSScriptRoot\01_backup.ps1" | Out-Null }
$AL = "$GddcHome\alerts.log"; $DC = Is-DC; $AD = $DC -and (Import-AD)
function Alert($m) { Write-Host ("[ALERT {0}] {1}" -f (Get-Date -Format T), $m) -ForegroundColor Red; Add-Content $AL ("{0} {1}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $m) }
$seen = @{}; function Once($k) { if ($seen.ContainsKey($k)) { return $false }; $seen[$k] = 1; return $true }
$gb = Get-Content "$bl\groups.json" -Raw | ConvertFrom-Json; $tb = @(Get-Content "$bl\tasks.json" -Raw | ConvertFrom-Json); $sb = @(Get-Content "$bl\services.json" -Raw | ConvertFrom-Json); $lb = @(Get-Content "$bl\listeners.json" -Raw | ConvertFrom-Json)
$ub = if (Test-Path "$bl\adusers.json") { @(Get-Content "$bl\adusers.json" -Raw | ConvertFrom-Json) } else { @() }
$last = Get-Date; $scoredSvc = 'sshd','WinRM','mpssvc' + $(if ($DC) { 'NTDS','DNS','Netlogon','KDC' })
$evt = @{ 4720='USER CREATED'; 4722='user enabled'; 4724='password reset by admin'; 4728='member added to global group'; 4732='member added to local group'; 4756='member added to universal group'; 4698='scheduled task created'; 4697='service installed (security)'; 4719='audit policy changed'; 1102='SECURITY LOG CLEARED'; 4738='user changed' }
Info "watching every ${Interval}s (AutoHeal=$AutoHeal Enforce=$Enforce) - alerts also in $AL   (Ctrl-C to stop)"
while ($true) {
    $now = Get-Date
    foreach ($id in 4720,4722,4724,4728,4732,4756,4698,4697,4719,1102) { $lg = 'Security'
        Get-WinEvent -FilterHashtable @{LogName=$lg;Id=$id;StartTime=$last} -ErrorAction SilentlyContinue | ForEach-Object { $m = ($_.Message -split "`n" | Select-Object -First 12) -join ' ' -replace '\s+',' '; Alert "event $id $($evt[$id]): $($m.Substring(0,[Math]::Min(230,$m.Length)))" } }
    Get-WinEvent -FilterHashtable @{LogName='System';Id=7045;StartTime=$last} -ErrorAction SilentlyContinue | ForEach-Object { Alert "NEW SERVICE $($_.Properties[0].Value) -> $($_.Properties[1].Value)" }
    $f = @(Get-WinEvent -FilterHashtable @{LogName='Security';Id=4625;StartTime=$last} -ErrorAction SilentlyContinue); if ($f.Count -ge 20) { $ips = $f | ForEach-Object { $_.Properties[19].Value } | Group-Object | Sort-Object Count -Desc | Select-Object -First 3; Alert "$($f.Count) failed logons in ${Interval}s; top sources: $(($ips | ForEach-Object { "$($_.Name)x$($_.Count)" }) -join ', ')" }
    $last = $now
    # privileged groups
    foreach ($g in $gb.PSObject.Properties.Name) { $cur = @(try { if ($DC) { Get-ADGroupMember $g -ErrorAction Stop | Select-Object -Expand SamAccountName } else { Get-LocalGroupMember $g -ErrorAction Stop | Select-Object -Expand Name } } catch { $null })
        foreach ($m in $cur) { if ($m -and @($gb.$g) -notcontains $m -and (Once "g:$g:$m")) { Alert "NEW member of '$g': $m"
            if ($Enforce -and $DC -and $g -in 'Domain Admins','Enterprise Admins','Schema Admins','Administrators' -and -not (Is-Scored $m)) { try { Remove-ADGroupMember $g -Members $m -Confirm:$false; Alert "  enforced: removed $m from $g" } catch { Alert "  enforce failed: $_" } } } } }
    if ($AD) { Get-ADUser -Filter * | Select-Object -Expand SamAccountName | Where-Object { $ub -notcontains $_ -and (Once "u:$_") } | ForEach-Object { Alert "NEW AD USER: $_"; if ($Enforce -and -not (Is-Scored $_)) { try { Disable-ADAccount $_; Alert "  enforced: disabled $_" } catch {} } } }
    Get-LocalUser | Where-Object { $_.Enabled -and (Once "lu:$($_.Name)") -and $_.Name -notin (Get-Content "$bl\localusers.json" -Raw | ConvertFrom-Json | Select-Object -Expand Name) } | ForEach-Object { Alert "NEW LOCAL USER: $($_.Name)" }
    Get-ScheduledTask | Where-Object { $tb -notcontains $_.TaskName -and (Once "t:$($_.TaskName)") } | ForEach-Object { Alert "NEW TASK: $($_.TaskPath)$($_.TaskName) -> $(($_.Actions | ForEach-Object { $_.Execute + ' ' + $_.Arguments }) -join ' | ')" }
    Get-CimInstance Win32_Service | Where-Object { $sb -notcontains $_.Name -and (Once "s:$($_.Name)") } | ForEach-Object { Alert "NEW SERVICE: $($_.Name) $($_.PathName)" }
    Get-NetTCPConnection -State Listen | Where-Object { $_.LocalPort -lt 49152 -and $lb -notcontains $_.LocalPort -and (Once "l:$($_.LocalPort)") } | ForEach-Object { Alert "NEW LISTENER tcp/$($_.LocalPort) pid=$($_.OwningProcess) $((Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path)" }
    Get-NetTCPConnection -State Established | Where-Object { $_.RemoteAddress -notmatch '^(172\.16\.|127\.|::1|0\.)' -and (Once "x:$($_.RemoteAddress):$($_.RemotePort)") } | ForEach-Object { Alert "EXTERNAL connection $($_.LocalPort) -> $($_.RemoteAddress):$($_.RemotePort) $((Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).Path)" }
    foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce') { (Get-ItemProperty $k -ErrorAction SilentlyContinue).PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' -and (Once "r:$($_.Name)") } | ForEach-Object { Alert "AUTORUN present: $($_.Name) = $($_.Value)" } }
    Get-NetFirewallProfile | Where-Object { -not $_.Enabled } | ForEach-Object { Alert "FIREWALL profile $($_.Name) DISABLED"; if ($AutoHeal) { Set-NetFirewallProfile -Name $_.Name -Enabled True; Alert '  healed: re-enabled' } }
    try { if (-not (Get-MpComputerStatus).RealTimeProtectionEnabled -and (Once "av:$([math]::Floor($now.Minute/10))")) { Alert 'Defender real-time protection is OFF' } } catch {}
    foreach ($s in $scoredSvc) { $v = Get-Service $s -ErrorAction SilentlyContinue; if ($v -and $v.Status -ne 'Running') { Alert "SCORED SERVICE DOWN: $s ($($v.Status))"; if ($AutoHeal) { Start-Service $s -ErrorAction SilentlyContinue; Start-Sleep 2; Alert "  restart $s -> $((Get-Service $s).Status)" } } }
    foreach ($p in 22,5985) { if (-not (Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue) -and (Once "np:$p:$([math]::Floor($now.Minute/5))")) { Alert "tcp/$p is NOT listening (scored)" } }
    Start-Sleep $Interval
}
