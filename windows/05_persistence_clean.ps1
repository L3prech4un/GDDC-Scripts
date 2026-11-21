# 05_persistence_clean.ps1 - REMEDIATION counterpart to 02_audit.ps1. Exports then removes persistence. Asks y/N per item unless -Auto.
#   .\05_persistence_clean.ps1 [-Auto] [-DryRun]       Everything is exported to C:\gddc\quarantine\<ts> first.
param([switch]$Auto, [switch]$DryRun)
. "$PSScriptRoot\common.ps1"; Require-Admin
$Q = "$GddcHome\quarantine\$TS"; New-Item -ItemType Directory -Force -Path $Q | Out-Null
function Do($desc, [scriptblock]$sb) { if ($DryRun) { Write-Host "   [dry-run] $desc"; return }; try { & $sb; Ok $desc } catch { Bad "$desc FAILED: $_" } }

Hdr 'Run / RunOnce entries'
foreach ($k in 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run','HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce','HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run') {
    if (-not (Test-Path $k)) { continue }
    (Get-ItemProperty $k).PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' } | ForEach-Object { $n = $_.Name; Warn "$k  $n = $($_.Value)"
        if (Confirm-Action 'remove this autorun?' -Auto:$Auto) { Add-Content "$Q\autoruns.txt" "$k|$n|$($_.Value)"; Do "removed autorun $n" { Remove-ItemProperty -Path $k -Name $n -Force } } } }

Hdr 'Scheduled tasks outside \Microsoft\'
Get-ScheduledTask | Where-Object { $_.TaskPath -notlike '\Microsoft\*' } | ForEach-Object { $t = $_
    Warn "task $($t.TaskPath)$($t.TaskName) -> $(($t.Actions | ForEach-Object { "$($_.Execute) $($_.Arguments)" }) -join ' | ')"
    if (Confirm-Action 'export + delete this task?' -Auto:$Auto) { Export-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath | Out-File "$Q\task_$($t.TaskName -replace '[^\w]','_').xml"; Do "deleted task $($t.TaskName)" { Unregister-ScheduledTask -TaskName $t.TaskName -TaskPath $t.TaskPath -Confirm:$false } } }

Hdr 'Services with suspicious ImagePath'
$protect = 'sshd','ssh-agent','WinRM','NTDS','DNS','Netlogon','KDC','gddc*'
Get-CimInstance Win32_Service | Where-Object { $_.PathName -match '(?i)\\(temp|users|programdata|appdata|downloads)\\|powershell|cmd(\.exe)?\s+/c|mshta|rundll32|regsvr32|wscript|cscript|-enc|FromBase64' } | ForEach-Object { $s = $_
    if ($protect | Where-Object { $s.Name -like $_ }) { return }
    Warn "service $($s.Name) [$($s.State)] $($s.PathName)"
    if (Confirm-Action 'stop + disable (config kept in quarantine)?' -Auto:$Auto) { Add-Content "$Q\services.txt" "$($s.Name)|$($s.PathName)|$($s.StartName)"; Do "disabled service $($s.Name)" { Stop-Service $s.Name -Force -ErrorAction SilentlyContinue; Set-Service $s.Name -StartupType Disabled } } }

Hdr 'WMI event subscriptions'
foreach ($c in '__FilterToConsumerBinding','CommandLineEventConsumer','ActiveScriptEventConsumer','__EventFilter') {
    Get-CimInstance -Namespace root\subscription -ClassName $c -ErrorAction SilentlyContinue | ForEach-Object { $o = $_; Warn "WMI $c : $($o.Name)"; if (Confirm-Action 'remove?' -Auto:$Auto) { $o | Out-String | Add-Content "$Q\wmi.txt"; Do "removed WMI $c $($o.Name)" { Remove-CimInstance -InputObject $o } } } }

Hdr 'Winlogon / IFEO / AppInit'
$wl = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon'; $p = Get-ItemProperty $wl
if ($p.Shell -ne 'explorer.exe') { Warn "Shell=$($p.Shell)"; if (Confirm-Action 'reset Shell?' -Auto:$Auto) { Do 'Shell reset' { Set-ItemProperty $wl Shell 'explorer.exe' } } }
if ($p.Userinit -notmatch '^C:\\Windows\\system32\\userinit\.exe,?$') { Warn "Userinit=$($p.Userinit)"; if (Confirm-Action 'reset Userinit?' -Auto:$Auto) { Do 'Userinit reset' { Set-ItemProperty $wl Userinit 'C:\Windows\system32\userinit.exe,' } } }
if ($p.Taskman) { Warn "Taskman=$($p.Taskman)"; if (Confirm-Action 'remove Taskman?' -Auto:$Auto) { Do 'Taskman removed' { Remove-ItemProperty $wl Taskman } } }
Get-ChildItem 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options' -ErrorAction SilentlyContinue | ForEach-Object { $ip = Get-ItemProperty $_.PSPath; if ($ip.Debugger) { Warn "IFEO $($_.PSChildName) Debugger=$($ip.Debugger)"; if (Confirm-Action 'remove Debugger?' -Auto:$Auto) { Do "IFEO $($_.PSChildName) cleared" { Remove-ItemProperty $_.PSPath Debugger } } } }
$aw = 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows'; if ((Get-ItemProperty $aw).AppInit_DLLs) { Warn 'AppInit_DLLs set'; if (Confirm-Action 'clear?' -Auto:$Auto) { Do 'AppInit_DLLs cleared' { Set-ItemProperty $aw AppInit_DLLs ''; Set-ItemProperty $aw LoadAppInit_DLLs 0 } } }

Hdr 'Accessibility-binary backdoors (sethc/utilman/osk/...)'
$cmdHash = (Get-FileHash "$env:SystemRoot\System32\cmd.exe").Hash
foreach ($f in 'sethc','utilman','osk','narrator','magnify','displayswitch','atbroker') { $path = "$env:SystemRoot\System32\$f.exe"; if (-not (Test-Path $path)) { continue }
    if ((Get-FileHash $path).Hash -eq $cmdHash -or (Get-AuthenticodeSignature $path).Status -ne 'Valid') { Warn "$path is NOT the genuine binary"
        if (Confirm-Action 'repair with sfc /scanfile (restores the original)?' -Auto:$Auto) { Do "repairing $f" { takeown /f $path | Out-Null; icacls $path /grant 'Administrators:F' | Out-Null; Copy-Item $path "$Q\$f.exe.bad" -Force; sfc /scanfile=$path | Out-Null } } } }

Hdr 'Startup folders / PowerShell profiles / hosts'
foreach ($d in "$env:ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp",'C:\Users\*\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup') { Get-ChildItem $d -Force -ErrorAction SilentlyContinue | Where-Object { $_.Name -ne 'desktop.ini' } | ForEach-Object { Warn "startup item $($_.FullName)"; if (Confirm-Action 'quarantine?' -Auto:$Auto) { if (-not $DryRun) { Quarantine $_.FullName $Q } } } }
foreach ($pp in "$PSHOME\profile.ps1","$PSHOME\Microsoft.PowerShell_profile.ps1",'C:\Users\*\Documents\WindowsPowerShell\*profile.ps1','C:\Users\*\Documents\PowerShell\*profile.ps1') { Get-ChildItem $pp -ErrorAction SilentlyContinue | ForEach-Object { Warn "PS profile $($_.FullName)"; if (Confirm-Action 'quarantine?' -Auto:$Auto) { if (-not $DryRun) { Quarantine $_.FullName $Q } } } }
$h = "$env:SystemRoot\System32\drivers\etc\hosts"; $bad = Get-Content $h | Where-Object { $_ -notmatch '^\s*(#|$)' }
if ($bad) { Warn "hosts entries: $($bad -join '; ')"; if (Confirm-Action 'reset hosts file (backup kept)?' -Auto:$Auto) { Copy-Item $h "$Q\hosts.bak"; Do 'hosts reset' { Set-Content $h '# GDDC reset hosts file' } } }

Hdr 'Suspicious processes'
Get-CimInstance Win32_Process | Where-Object { $_.ExecutablePath -match '(?i)\\(temp|appdata|downloads|public|programdata)\\' -or $_.CommandLine -match '(?i)-enc |-encodedcommand|FromBase64String|IEX\s*\(|DownloadString|nc(at)?\.exe .*-e|mimikatz|chisel|ligolo' } | Where-Object { $_.ProcessId -ne $PID } | ForEach-Object {
    Warn "pid $($_.ProcessId) $($_.Name): $($_.CommandLine)"; if (Confirm-Action 'kill?' -Auto:$Auto) { Do "killed $($_.ProcessId)" { Stop-Process -Id $_.ProcessId -Force } } }
Ok "Done. Quarantine/exports: $Q. Re-run .\02_audit.ps1 to confirm, and check the scoreboard."
