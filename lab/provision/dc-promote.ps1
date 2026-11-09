# Generated from lab/lab.toml by `python -m identity_attack_lab render`. Do not edit.
# Promote DC01 to the first domain controller of corp.idlab.test.
# Lab only: runs inside the isolated VMs that the Vagrantfile creates.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) {
    Write-Host 'Already a domain controller; nothing to do'
    exit 0
}
$lab = Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -eq '192.168.56.10'
if ($null -eq $lab) { throw 'host-only address not found' }
Get-NetIPInterface -AddressFamily IPv4 |
    Where-Object { $_.InterfaceIndex -ne $lab.InterfaceIndex -and $_.InterfaceAlias -notlike 'Loopback*' } |
    ForEach-Object { Set-DnsClient -InterfaceIndex $_.InterfaceIndex -RegisterThisConnectionsAddress $false }
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools | Out-Null
$dsrm = ConvertTo-SecureString 'EXAMPLE-NOT-A-SECRET-Admin1!' -AsPlainText -Force
Install-ADDSForest -DomainName 'corp.idlab.test' -DomainNetbiosName 'IDLAB' `
    -SafeModeAdministratorPassword $dsrm -InstallDns -NoRebootOnCompletion -Force | Out-Null
Write-Host 'Forest created; the next provisioner reboots the VM'
