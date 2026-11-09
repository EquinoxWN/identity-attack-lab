# Generated from lab/lab.toml by `python -m identity_attack_lab render`. Do not edit.
# Local misconfigurations on WS01.
# Lab only: runs inside the isolated VMs that the Vagrantfile creates.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

# Misconfiguration: domain principals in the local Administrators group
if (-not (Get-LocalGroupMember -Group Administrators | Where-Object Name -eq 'IDLAB\IT Admins')) {
    Add-LocalGroupMember -Group Administrators -Member 'IDLAB\IT Admins'
}

# Misconfiguration: a privileged account keeps a logon session on this host
$action = New-ScheduledTaskAction -Execute 'powershell.exe' `
    -Argument '-NoProfile -WindowStyle Hidden -Command Start-Sleep -Seconds 2000000'
$trigger = New-ScheduledTaskTrigger -AtStartup
Register-ScheduledTask -TaskName 'idlab-session-da_admin' -Action $action -Trigger $trigger `
    -User 'IDLAB\da_admin' -Password 'EXAMPLE-NOT-A-SECRET-DomainAdmin1!' -Force | Out-Null
Start-ScheduledTask -TaskName 'idlab-session-da_admin'

Write-Host 'WS01 seeded'
