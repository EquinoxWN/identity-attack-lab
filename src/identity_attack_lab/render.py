"""Render the Vagrantfile, provisioning scripts and BloodHound model from the lab spec.

Every generated file starts with a do-not-edit header. Output is deterministic (no timestamps),
so `render --check` can prove the committed files still match `lab/lab.toml`. Values are placed
inside single-quoted Ruby and PowerShell strings; the spec validator already rejects quotes,
backticks, `$` and newlines in every free-text value, so no value can break out of its string.
"""

from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

from .bloodhound import model_collection
from .spec import DOMAIN_TARGET, Host, LabSpec

# The Packer-built box's local `vagrant` account; must match packer/windows-server-2022.pkr.hcl.
BOX_NAME = "idlab/windows-server-2022"
BOX_USER = "vagrant"
BOX_PASSWORD = "EXAMPLE-NOT-A-SECRET-Vagrant1!"  # noqa: S105 - visibly fake lab value
HEADER = "Generated from lab/lab.toml by `python -m identity_attack_lab render`. Do not edit."
# Forwarded ports Vagrant would otherwise create for Windows guests; each is pinned to loopback.
FORWARDED = (("winrm", 5985, 55985), ("winrm-ssl", 5986, 56985), ("rdp", 3389, 53389))
# dsacls grant strings for each ACL right (DCSync and Owns are handled separately).
DSACLS = {
    "GenericAll": ["GA"],
    "GenericWrite": ["GW"],
    "WriteDacl": ["WD"],
    "WriteOwner": ["WO"],
    "ForceChangePassword": ["CA;Reset Password"],
    "AddMember": ["WP;member"],
    "AllExtendedRights": ["CA"],
    "DCSync": ["CA;Replicating Directory Changes", "CA;Replicating Directory Changes All"],
}


def _ps_prelude(purpose: str) -> list[str]:
    """Common PowerShell header: fail fast, strict mode."""
    return [
        f"# {HEADER}",
        f"# {purpose}",
        "# Lab only: runs inside the isolated VMs that the Vagrantfile creates.",
        "$ErrorActionPreference = 'Stop'",
        "Set-StrictMode -Version Latest",
        "",
    ]


def _isolate_dns(ip: str) -> list[str]:
    """Stop the NAT adapter registering itself in lab DNS (only the host-only IP is used)."""
    return [
        f"$lab = Get-NetIPAddress -AddressFamily IPv4 | Where-Object IPAddress -eq '{ip}'",
        "if ($null -eq $lab) { throw 'host-only address not found' }",
        "Get-NetIPInterface -AddressFamily IPv4 |",
        "    Where-Object { $_.InterfaceIndex -ne $lab.InterfaceIndex -and "
        "$_.InterfaceAlias -notlike 'Loopback*' } |",
        "    ForEach-Object { Set-DnsClient -InterfaceIndex $_.InterfaceIndex "
        "-RegisterThisConnectionsAddress $false }",
    ]


def render_dc_promote(spec: LabSpec) -> str:
    """dc-promote.ps1: install AD DS and create the forest (idempotent)."""
    d = spec.domain
    lines = _ps_prelude(f"Promote {spec.dc.name} to the first domain controller of {d.fqdn}.")
    lines += [
        "if ((Get-CimInstance Win32_ComputerSystem).DomainRole -ge 4) {",
        "    Write-Host 'Already a domain controller; nothing to do'",
        "    exit 0",
        "}",
        *_isolate_dns(spec.dc.ip),
        "Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools | Out-Null",
        f"$dsrm = ConvertTo-SecureString '{d.admin_password}' -AsPlainText -Force",
        f"Install-ADDSForest -DomainName '{d.fqdn}' -DomainNetbiosName '{d.netbios}' `",
        "    -SafeModeAdministratorPassword $dsrm -InstallDns -NoRebootOnCompletion -Force | Out-Null",
        "Write-Host 'Forest created; the next provisioner reboots the VM'",
    ]
    return "\n".join(lines) + "\n"


def _principal_kind(spec: LabSpec, name: str) -> str:
    """'User', 'Group' or 'Computer' for a spec principal."""
    if name in spec.all_groups():
        return "Group"
    if name in spec.all_users():
        return "User"
    return "Computer"


def render_seed_domain(spec: LabSpec) -> str:
    """seed-domain.ps1: groups, users, memberships and the deliberate misconfigurations."""
    d = spec.domain
    lines = _ps_prelude(f"Create the {d.fqdn} objects and their deliberate misconfigurations.")
    lines += [
        "Import-Module ActiveDirectory",
        "# Wait (at most 10 minutes, monotonic clock) for AD Web Services after the reboot.",
        "$clock = [Diagnostics.Stopwatch]::StartNew()",
        "while ($true) {",
        "    try { Get-ADDomain | Out-Null; break }",
        "    catch {",
        '        if ($clock.Elapsed.TotalMinutes -gt 10) { throw "AD not ready after 10 minutes: $_" }',
        "        Start-Sleep -Seconds 15",
        "    }",
        "}",
        "",
        "function Get-Dn([string]$Kind, [string]$Name) {",
        "    $found = switch ($Kind) {",
        "        'User' { Get-ADUser -Identity $Name }",
        "        'Group' { Get-ADGroup -Identity $Name }",
        "        'Computer' { Get-ADComputer -Identity $Name }",
        "        'Domain' { Get-ADDomain }",
        "    }",
        "    return $found.DistinguishedName",
        "}",
        "function Set-LabGroup([string]$Name) {",
        "    if (-not (Get-ADGroup -Filter \"Name -eq '$Name'\")) {",
        "        New-ADGroup -Name $Name -SamAccountName $Name -GroupScope Global -GroupCategory Security",
        "    }",
        "}",
        "function Set-LabUser([string]$Name, [string]$Password, [string]$Description) {",
        "    $secure = ConvertTo-SecureString $Password -AsPlainText -Force",
        "    if (-not (Get-ADUser -Filter \"SamAccountName -eq '$Name'\")) {",
        "        New-ADUser -Name $Name -SamAccountName $Name -AccountPassword $secure `",
        "            -Enabled $true -PasswordNeverExpires $true",
        "    } else {",
        "        Set-ADAccountPassword -Identity $Name -NewPassword $secure -Reset",
        "    }",
        "    if ($Description) { Set-ADUser -Identity $Name -Description $Description }",
        "}",
        "function Add-LabMember([string]$Group, [string]$Member) {",
        "    $current = @(Get-ADGroupMember -Identity $Group | ForEach-Object SamAccountName)",
        "    if ($current -notcontains $Member) { Add-ADGroupMember -Identity $Group -Members $Member }",
        "}",
        "function Add-LabSpn([string]$User, [string]$Spn) {",
        "    $spns = @((Get-ADUser -Identity $User -Properties ServicePrincipalName).ServicePrincipalName)",
        "    if ($spns -notcontains $Spn) { Set-ADUser -Identity $User -ServicePrincipalNames @{Add = $Spn} }",
        "}",
        "function Grant-LabRight([string]$TargetDn, [string]$Grant) {",
        "    & dsacls.exe $TargetDn /G $Grant | Out-Null",
        '    if ($LASTEXITCODE -ne 0) { throw "dsacls failed ($LASTEXITCODE) for $Grant on $TargetDn" }',
        "}",
        "function Set-LabOwner([string]$TargetDn, [string]$Owner) {",
        '    $acl = Get-Acl -Path "AD:$TargetDn"',
        "    $acl.SetOwner([Security.Principal.NTAccount]$Owner)",
        '    Set-Acl -Path "AD:$TargetDn" -AclObject $acl',
        "}",
        "",
        "Set-ADAccountPassword -Identity Administrator -Reset `",
        f"    -NewPassword (ConvertTo-SecureString '{d.admin_password}' -AsPlainText -Force)",
        "",
        "# Groups",
    ]
    lines += [f"Set-LabGroup '{g}'" for g in spec.groups]
    lines += ["", "# Users"]
    for u in spec.users:
        lines.append(f"Set-LabUser '{u.name}' '{u.password}' '{u.description}'")
    lines += ["", "# Memberships"]
    for u in spec.users:
        lines += [f"Add-LabMember '{g}' '{u.name}'" for g in u.groups if g != "Domain Users"]
    lines += ["", "# Misconfiguration: service principal names (Kerberoastable accounts)"]
    for u in spec.users:
        lines += [f"Add-LabSpn '{u.name}' '{spn}'" for spn in u.spns]
    lines += ["", "# Misconfiguration: Kerberos pre-authentication disabled (AS-REP roastable)"]
    for u in spec.users:
        if u.dont_require_preauth:
            lines.append(f"Set-ADAccountControl -Identity '{u.name}' -DoesNotRequirePreAuth $true")
    lines += ["", "# Misconfiguration: access-control entries"]
    for acl in spec.acls:
        kind = "Domain" if acl.target == DOMAIN_TARGET else _principal_kind(spec, acl.target)
        dn = f"(Get-Dn '{kind}' '{acl.target}')"
        who = f"{d.netbios}\\{acl.principal}"
        if acl.right == "Owns":
            lines.append(f"Set-LabOwner {dn} '{who}'")
        else:
            lines += [f"Grant-LabRight {dn} '{who}:{g}'" for g in DSACLS[acl.right]]
    lines += ["", "Write-Host 'Domain seeded'"]
    return "\n".join(lines) + "\n"


def render_member_join(spec: LabSpec, host: Host) -> str:
    """member-join.ps1: point DNS at the DC and join the domain (idempotent)."""
    d = spec.domain
    lines = _ps_prelude(f"Join {host.name} to {d.fqdn}.")
    lines += [
        "if ((Get-CimInstance Win32_ComputerSystem).PartOfDomain) {",
        "    Write-Host 'Already joined; nothing to do'",
        "    exit 0",
        "}",
        *_isolate_dns(host.ip),
        f"Set-DnsClientServerAddress -InterfaceIndex $lab.InterfaceIndex -ServerAddresses '{spec.dc.ip}'",
        "# Wait (at most 10 minutes, monotonic clock) until the domain resolves.",
        "$clock = [Diagnostics.Stopwatch]::StartNew()",
        f"while (-not (Resolve-DnsName -Name '{d.fqdn}' -Type A -QuickTimeout "
        "-ErrorAction SilentlyContinue)) {",
        f"    if ($clock.Elapsed.TotalMinutes -gt 10) {{ throw 'cannot resolve {d.fqdn}' }}",
        "    Start-Sleep -Seconds 15",
        "}",
        f"$secure = ConvertTo-SecureString '{d.admin_password}' -AsPlainText -Force",
        f"$cred = New-Object Management.Automation.PSCredential('{d.netbios}\\Administrator', $secure)",
        f"Add-Computer -DomainName '{d.fqdn}' -Credential $cred -Force",
        "Write-Host 'Joined; the next provisioner reboots the VM'",
    ]
    return "\n".join(lines) + "\n"


def render_member_seed(spec: LabSpec, host: Host) -> str:
    """member-<host>.ps1: local administrators and standing sessions for this host."""
    d = spec.domain
    lines = _ps_prelude(f"Local misconfigurations on {host.name}.")
    lines += ["# Misconfiguration: domain principals in the local Administrators group"]
    for la in spec.local_admins:
        if la.host != host.name:
            continue
        who = f"{d.netbios}\\{la.principal}"
        lines += [
            f"if (-not (Get-LocalGroupMember -Group Administrators | Where-Object Name -eq '{who}')) {{",
            f"    Add-LocalGroupMember -Group Administrators -Member '{who}'",
            "}",
        ]
    lines += ["", "# Misconfiguration: a privileged account keeps a logon session on this host"]
    for s in spec.sessions:
        if s.host != host.name:
            continue
        user = next(u for u in spec.users if u.name == s.user)
        task = f"idlab-session-{user.name}"
        lines += [
            "$action = New-ScheduledTaskAction -Execute 'powershell.exe' `",
            "    -Argument '-NoProfile -WindowStyle Hidden -Command Start-Sleep -Seconds 2000000'",
            "$trigger = New-ScheduledTaskTrigger -AtStartup",
            f"Register-ScheduledTask -TaskName '{task}' -Action $action -Trigger $trigger `",
            f"    -User '{d.netbios}\\{user.name}' -Password '{user.password}' -Force | Out-Null",
            f"Start-ScheduledTask -TaskName '{task}'",
        ]
    lines += ["", f"Write-Host '{host.name} seeded'"]
    return "\n".join(lines) + "\n"


def _q(value: str) -> str:
    """Single-quoted Ruby string (values are pre-validated to contain no quotes)."""
    return f"'{value}'"


def render_vagrantfile(spec: LabSpec) -> str:
    """Vagrantfile: one VM per host, host-only network, loopback-only forwarded ports."""
    out = [
        f"# {HEADER}",
        f"# Lab only: every VM sits on the host-only network {spec.cidr}; the forwarded WinRM and",
        "# RDP ports are bound to 127.0.0.1, so nothing is reachable from outside this machine.",
        "Vagrant.require_version '>= 2.4.0'",
        "",
        "Vagrant.configure('2') do |config|",
        f"  config.vm.box = {_q(BOX_NAME)}",
        "  config.vm.box_check_update = false",
        "  config.vm.guest = :windows",
        "  config.vm.communicator = 'winrm'",
        "  config.vm.boot_timeout = 900",
        f"  config.winrm.username = {_q(BOX_USER)}",
        f"  config.winrm.password = {_q(BOX_PASSWORD)}",
        "  config.winrm.transport = :plaintext",
        "  config.winrm.basic_auth_only = true",
        "  config.winrm.timeout = 1800",
        "  config.winrm.retry_limit = 30",
        "  config.winrm.retry_delay = 10",
        "  config.vm.synced_folder '.', '/vagrant', disabled: true",
        "",
        "  config.vm.provider 'virtualbox' do |vb|",
        "    vb.gui = false",
        "    vb.linked_clone = true",
        "    vb.customize ['modifyvm', :id, '--clipboard-mode', 'disabled',",
        "                  '--drag-and-drop', 'disabled', '--vrde', 'off']",
        "  end",
    ]
    hosts = sorted(spec.hosts, key=lambda h: h.role != "dc")  # the DC must come up first
    for i, h in enumerate(hosts):
        vm = h.name.lower()
        out += [
            "",
            f"  config.vm.define {_q(vm)} do |h|",
            f"    h.vm.hostname = {_q(h.name)}",
            f"    h.vm.network 'private_network', ip: {_q(h.ip)}",
        ]
        for port_id, guest, host_port in FORWARDED:
            out.append(
                f"    h.vm.network 'forwarded_port', id: {_q(port_id)}, guest: {guest}, "
                f"host: {host_port + i}, host_ip: '127.0.0.1', auto_correct: true"
            )
        out += [
            "    h.vm.provider 'virtualbox' do |vb|",
            f"      vb.name = {_q('idlab-' + vm)}",
            f"      vb.memory = {h.memory_mb}",
            f"      vb.cpus = {h.cpus}",
            "    end",
        ]
        if h.role == "dc":
            steps = [("promote", "provision/dc-promote.ps1"), ("seed", "provision/seed-domain.ps1")]
        else:
            steps = [
                ("join", "provision/member-join-" + vm + ".ps1"),
                ("seed", f"provision/member-{vm}.ps1"),
            ]
        out += [
            f"    h.vm.provision {_q(steps[0][0])}, type: 'shell', path: {_q(steps[0][1])}",
            f"    h.vm.provision 'reboot-after-{steps[0][0]}', type: 'shell', "
            "inline: 'Write-Host rebooting', reboot: true",
            f"    h.vm.provision {_q(steps[1][0])}, type: 'shell', path: {_q(steps[1][1])}",
            "  end",
        ]
    out.append("end")
    return "\n".join(out) + "\n"


def _check_printable(rel: str, text: str) -> None:
    """Defence in depth: generated Ruby/PowerShell must be printable ASCII plus newlines."""
    # split("\n"), not splitlines(): U+2028, \x0b, \x85 and friends must be reported, not split on.
    for no, line in enumerate(text.split("\n"), 1):
        bad = next((c for c in line if not " " <= c <= "~"), None)
        if bad is not None:
            raise ValueError(f"{rel}:{no}: character U+{ord(bad):04X} is not printable ASCII")


def render_all(spec: LabSpec) -> dict[str, str]:
    """Every generated file, keyed by path relative to the repository root."""
    files = {
        "lab/Vagrantfile": render_vagrantfile(spec),
        "lab/provision/dc-promote.ps1": render_dc_promote(spec),
        "lab/provision/seed-domain.ps1": render_seed_domain(spec),
    }
    for h in spec.hosts:
        if h.role == "member":
            vm = h.name.lower()
            files[f"lab/provision/member-join-{vm}.ps1"] = render_member_join(spec, h)
            files[f"lab/provision/member-{vm}.ps1"] = render_member_seed(spec, h)
    for rel, text in files.items():
        _check_printable(rel, text)
    for name, doc in model_collection(spec).items():
        files[f"bloodhound/model/{name}"] = json.dumps(doc, indent=2) + "\n"
    return files


def _normalized(text: str) -> str:
    """Ignore CRLF/LF differences (a Windows checkout may convert line endings)."""
    return text.replace("\r\n", "\n")


def drift(root: Path, files: dict[str, str]) -> list[str]:
    """Generated paths whose file on disk is missing or differs from the rendering."""
    out = []
    for rel, text in sorted(files.items()):
        path = root / rel
        if not path.is_file() or _normalized(path.read_text(encoding="utf-8")) != text:
            out.append(rel)
    return out


def atomic_write(path: Path, text: str) -> bool:
    """Write via a temp file and rename; skip (return False) when content is unchanged."""
    if path.is_file() and _normalized(path.read_text(encoding="utf-8")) == text:
        return False
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=f".{path.name}.", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        Path(tmp).unlink(missing_ok=True)
        raise
    return True


def write_all(root: Path, files: dict[str, str]) -> list[str]:
    """Write every file atomically; return the paths that changed."""
    return [rel for rel, text in sorted(files.items()) if atomic_write(root / rel, text)]
