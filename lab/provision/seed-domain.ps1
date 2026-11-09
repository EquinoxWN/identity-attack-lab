# Generated from lab/lab.toml by `python -m identity_attack_lab render`. Do not edit.
# Create the corp.idlab.test objects and their deliberate misconfigurations.
# Lab only: runs inside the isolated VMs that the Vagrantfile creates.
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest

Import-Module ActiveDirectory
# Wait (at most 10 minutes, monotonic clock) for AD Web Services after the reboot.
$clock = [Diagnostics.Stopwatch]::StartNew()
while ($true) {
    try { Get-ADDomain | Out-Null; break }
    catch {
        if ($clock.Elapsed.TotalMinutes -gt 10) { throw "AD not ready after 10 minutes: $_" }
        Start-Sleep -Seconds 15
    }
}

function Get-Dn([string]$Kind, [string]$Name) {
    $found = switch ($Kind) {
        'User' { Get-ADUser -Identity $Name }
        'Group' { Get-ADGroup -Identity $Name }
        'Computer' { Get-ADComputer -Identity $Name }
        'Domain' { Get-ADDomain }
    }
    return $found.DistinguishedName
}
function Set-LabGroup([string]$Name) {
    if (-not (Get-ADGroup -Filter "Name -eq '$Name'")) {
        New-ADGroup -Name $Name -SamAccountName $Name -GroupScope Global -GroupCategory Security
    }
}
function Set-LabUser([string]$Name, [string]$Password, [string]$Description) {
    $secure = ConvertTo-SecureString $Password -AsPlainText -Force
    if (-not (Get-ADUser -Filter "SamAccountName -eq '$Name'")) {
        New-ADUser -Name $Name -SamAccountName $Name -AccountPassword $secure `
            -Enabled $true -PasswordNeverExpires $true
    } else {
        Set-ADAccountPassword -Identity $Name -NewPassword $secure -Reset
    }
    if ($Description) { Set-ADUser -Identity $Name -Description $Description }
}
function Add-LabMember([string]$Group, [string]$Member) {
    $current = @(Get-ADGroupMember -Identity $Group | ForEach-Object SamAccountName)
    if ($current -notcontains $Member) { Add-ADGroupMember -Identity $Group -Members $Member }
}
function Add-LabSpn([string]$User, [string]$Spn) {
    $spns = @((Get-ADUser -Identity $User -Properties ServicePrincipalName).ServicePrincipalName)
    if ($spns -notcontains $Spn) { Set-ADUser -Identity $User -ServicePrincipalNames @{Add = $Spn} }
}
function Grant-LabRight([string]$TargetDn, [string]$Grant) {
    & dsacls.exe $TargetDn /G $Grant | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "dsacls failed ($LASTEXITCODE) for $Grant on $TargetDn" }
}
function Set-LabOwner([string]$TargetDn, [string]$Owner) {
    $acl = Get-Acl -Path "AD:$TargetDn"
    $acl.SetOwner([Security.Principal.NTAccount]$Owner)
    Set-Acl -Path "AD:$TargetDn" -AclObject $acl
}

Set-ADAccountPassword -Identity Administrator -Reset `
    -NewPassword (ConvertTo-SecureString 'EXAMPLE-NOT-A-SECRET-Admin1!' -AsPlainText -Force)

# Groups
Set-LabGroup 'Helpdesk'
Set-LabGroup 'IT Admins'

# Users
Set-LabUser 'alice' 'EXAMPLE-NOT-A-SECRET-Alice1!' 'Foothold: an ordinary employee account assumed to be phished'
Set-LabUser 'bob' 'EXAMPLE-NOT-A-SECRET-Bob1!' 'Control: an ordinary employee with no path to Tier Zero'
Set-LabUser 'carol' 'EXAMPLE-NOT-A-SECRET-Carol1!' 'Helpdesk operator with Kerberos pre-authentication disabled'
Set-LabUser 'it_ian' 'EXAMPLE-NOT-A-SECRET-Ian1!' 'Workstation administrator'
Set-LabUser 'svc_sql' 'EXAMPLE-NOT-A-SECRET-Sql1!' 'SQL service account with an SPN and admin rights it does not need'
Set-LabUser 'svc_backup' 'EXAMPLE-NOT-A-SECRET-Backup1!' 'Backup service account granted directory replication rights'
Set-LabUser 'da_admin' 'EXAMPLE-NOT-A-SECRET-DomainAdmin1!' 'Domain administrator who also logs on to a workstation'

# Memberships
Add-LabMember 'Helpdesk' 'carol'
Add-LabMember 'IT Admins' 'it_ian'
Add-LabMember 'IT Admins' 'svc_sql'
Add-LabMember 'Domain Admins' 'da_admin'

# Misconfiguration: service principal names (Kerberoastable accounts)
Add-LabSpn 'svc_sql' 'MSSQLSvc/ws01.corp.idlab.test:1433'

# Misconfiguration: Kerberos pre-authentication disabled (AS-REP roastable)
Set-ADAccountControl -Identity 'carol' -DoesNotRequirePreAuth $true

# Misconfiguration: access-control entries
Grant-LabRight (Get-Dn 'User' 'it_ian') 'IDLAB\Helpdesk:CA;Reset Password'
Grant-LabRight (Get-Dn 'User' 'svc_backup') 'IDLAB\alice:GA'
Grant-LabRight (Get-Dn 'Domain' 'domain') 'IDLAB\svc_backup:CA;Replicating Directory Changes'
Grant-LabRight (Get-Dn 'Domain' 'domain') 'IDLAB\svc_backup:CA;Replicating Directory Changes All'

Write-Host 'Domain seeded'
