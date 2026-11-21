# common.ps1 - shared helpers. Dot-source it:  . "$PSScriptRoot\common.ps1"
# Windows Server 2022 DC (172.16.X.40). Scored: ICMP, SSH (OpenSSH), LDAP, WinRM.  Run in an ELEVATED PowerShell.
$ErrorActionPreference = 'Continue'
$GddcHome = 'C:\gddc'
$TS = if ($env:GDDC_TS) { $env:GDDC_TS } else { Get-Date -Format 'yyyyMMdd-HHmmss' }
New-Item -ItemType Directory -Force -Path $GddcHome | Out-Null
$GddcLog = Join-Path $GddcHome 'gddc.log'
# Accounts the scoring engine logs in as. NEVER modified (password, groups, disable) by these scripts.
$ScoredUsers = @('amarino','mdesocio','lsmith','acapece','johnlinux','linuswindows','alvin','simon','theodore','abauer')
$Script:Flags = 0

function Write-Log($lvl, $msg) { Add-Content -Path $GddcLog -Value ("{0} {1} {2}" -f (Get-Date -Format 'yyyy-MM-dd HH:mm:ss'), $lvl, $msg) -ErrorAction SilentlyContinue }
function Info($m) { Write-Host "[*] $m" -ForegroundColor Cyan;   Write-Log 'INFO' $m }
function Ok($m)   { Write-Host "[+] $m" -ForegroundColor Green;  Write-Log 'OK  ' $m }
function Warn($m) { Write-Host "[!] $m" -ForegroundColor Yellow; Write-Log 'WARN' $m }
function Bad($m)  { Write-Host "[-] $m" -ForegroundColor Red;    Write-Log 'BAD ' $m }
function Flag($m) { $Script:Flags++; Write-Host "[FLAG] $m" -ForegroundColor Red; Write-Log 'FLAG' $m }
function Hdr($m)  { Write-Host "`n=== $m ===" -ForegroundColor Cyan; Write-Log '====' $m }

function Require-Admin {
    $p = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    if (-not $p.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { Write-Host 'Run from an elevated (Administrator) PowerShell.' -ForegroundColor Red; exit 1 }
}
function Is-Scored($name) { $n = ($name -split '\\')[-1]; return ($ScoredUsers -contains $n.ToLower()) }
function Is-DC { return ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) }
function Import-AD { if (-not (Get-Module ActiveDirectory)) { Import-Module ActiveDirectory -ErrorAction SilentlyContinue }; return [bool](Get-Module ActiveDirectory) }
function New-GddcPassword {
    $chars = (48..57) + (65..90) + (97..122) | ForEach-Object { [char]$_ }
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create(); $b = New-Object byte[] 18; $rng.GetBytes($b)
    return (($b | ForEach-Object { $chars[$_ % $chars.Count] }) -join '') + '_Aa1'
}
function Set-Reg($path, $name, $value, $type = 'DWord') {
    try { if (-not (Test-Path $path)) { New-Item -Path $path -Force | Out-Null }; New-ItemProperty -Path $path -Name $name -Value $value -PropertyType $type -Force | Out-Null; return $true }
    catch { Warn "registry write failed: $path\$name ($_)"; return $false }
}
function Protect-File($path) { icacls $path /inheritance:r /grant:r 'Administrators:F' 'SYSTEM:F' | Out-Null }
function Confirm-Action($prompt, [switch]$Auto) { if ($Auto) { return $true }; $a = Read-Host "     $prompt [y/N]"; return ($a -match '^[yY]') }
function Quarantine($path, $QDir) {
    if (-not (Test-Path $path)) { return }
    $dest = Join-Path $QDir (($path -replace '[:\\\/]', '_')); New-Item -ItemType Directory -Force -Path $QDir | Out-Null
    try { Move-Item -LiteralPath $path -Destination $dest -Force -ErrorAction Stop; Ok "quarantined $path -> $dest" } catch { Warn "could not move $path ($_)" }
}
function Get-TeamNet {
    $ip = Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue | Where-Object { $_.IPAddress -like '172.16.*' } | Select-Object -First 1
    if ($ip) { $o = $ip.IPAddress.Split('.'); return "$($o[0]).$($o[1]).$($o[2]).0/24" }; return $null
}
function Get-SshdConfigPath { 'C:\ProgramData\ssh\sshd_config' }
