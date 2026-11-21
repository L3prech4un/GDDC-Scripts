# 08_verify.ps1 - local sanity check of the DC's scored services. (Loopback bypasses the firewall: ALSO test from a jumpbox with 13_remote_check.sh.)
. "$PSScriptRoot\common.ps1"; Require-Admin
function T($n,$p) { if (Get-NetTCPConnection -LocalPort $p -State Listen -ErrorAction SilentlyContinue) { Ok "$n listening on tcp/$p" } else { Bad "$n NOT listening on tcp/$p" } }
T 'SSH' 22; T 'LDAP' 389; T 'WinRM' 5985
foreach ($s in 'sshd','WinRM','NTDS','DNS','Netlogon','KDC') { $v = Get-Service $s -ErrorAction SilentlyContinue; if ($v) { if ($v.Status -eq 'Running') { Ok "service $s running" } else { Bad "service $s $($v.Status)" } } }
$icmp = Get-NetFirewallRule -Enabled True -Direction Inbound -Action Allow -ErrorAction SilentlyContinue | Where-Object { $_.DisplayName -match 'ICMPv4|Echo Request' -or ($_ | Get-NetFirewallPortFilter).IcmpType -eq 8 }
if ($icmp) { Ok 'firewall allows ICMP echo' } else { Bad 'no enabled inbound rule allows ICMP echo!' }
try { $c = New-Object DirectoryServices.DirectoryEntry('LDAP://RootDSE'); Ok "LDAP RootDSE: $($c.defaultNamingContext)" } catch { Bad "LDAP RootDSE query failed: $_" }
try { Test-WSMan localhost -ErrorAction Stop | Out-Null; Ok 'WinRM answers (Test-WSMan)' } catch { Bad "WinRM: $_" }
$ssh = Get-NetTCPConnection -LocalPort 22 -State Listen -ErrorAction SilentlyContinue; if ($ssh) { try { $s = New-Object Net.Sockets.TcpClient('127.0.0.1',22); $r = New-Object IO.StreamReader($s.GetStream()); Ok "SSH banner: $($r.ReadLine())"; $s.Close() } catch {} }
foreach ($u in $ScoredUsers) { try { if (Import-AD) { $a = Get-ADUser $u -Properties Enabled,LockedOut -ErrorAction Stop; if (-not $a.Enabled -or $a.LockedOut) { Bad "scored user $u disabled/locked" } } else { $a = Get-LocalUser $u -ErrorAction Stop; if (-not $a.Enabled) { Bad "scored user $u disabled" } } } catch {} }
