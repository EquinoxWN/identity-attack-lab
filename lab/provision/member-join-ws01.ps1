# Generated from lab/lab.toml by `python -m identity_attack_lab render`. Do not edit.
# Join WS01 to corp.idlab.test.
# Lab only: runs inside the isolated VMs that the Vagrantfile creates.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) {
    Write-Host 'Already joined; nothing to do'
    exit 0
}
$lab = Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -eq '192.168.56.20'
if ($null -eq $lab) { throw 'host-only address not found' }
Get-NetIPInterface -AddressFamily IPv4 |
    Where-Object { $_.InterfaceIndex -ne $lab.InterfaceIndex -and $_.InterfaceAlias -notlike 'Loopback*' } |
    ForEach-Object { Set-DnsClient -InterfaceIndex $_.InterfaceIndex -RegisterThisConnectionsAddress $false }
Set-DnsClientServerAddress -InterfaceIndex $lab.InterfaceIndex -ServerAddresses '192.168.56.10'
# Wait (at most 10 minutes, monotonic clock) until the domain resolves.
$clock = [Diagnostics.Stopwatch]::StartNew()
while (-not (Resolve-DnsName -Name 'corp.idlab.test' -Type A -QuickTimeout -ErrorAction SilentlyContinue)) {
    if ($clock.Elapsed.TotalMinutes -gt 10) { throw 'cannot resolve corp.idlab.test' }
    Start-Sleep -Seconds 15
}
$secure = ConvertTo-SecureString 'EXAMPLE-NOT-A-SECRET-Admin1!' -AsPlainText -Force
$cred = New-Object Management.Automation.PSCredential('IDLAB\Administrator', $secure)
Add-Computer -DomainName 'corp.idlab.test' -Credential $cred -Force
Write-Host 'Joined; the next provisioner reboots the VM'
