# Run once by Autounattend.xml at first logon of the Packer build VM (lab only).
# Opens WinRM over HTTP with basic auth so Packer and Vagrant can provision the VM. The VM is only
# reachable through VirtualBox NAT port forwards that Vagrant binds to 127.0.0.1.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private
Enable-PSRemoting -Force -SkipNetworkProfileCheck | Out-Null
Set-Item -Path WSMan:\localhost\Service\AllowUnencrypted -Value $true
Set-Item -Path WSMan:\localhost\Service\Auth\Basic -Value $true
Set-Item -Path WSMan:\localhost\MaxTimeoutms -Value 1800000
Set-Service -Name WinRM -StartupType Automatic
Restart-Service -Name WinRM
Write-Host 'WinRM ready'
