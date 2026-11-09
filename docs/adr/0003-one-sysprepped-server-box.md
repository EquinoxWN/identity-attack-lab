# ADR 0003: One sysprepped Windows Server 2022 box for every VM

- **Status:** Accepted

## Context

The lab needs a domain controller and a workstation-like member. Building a Windows 11 box as well
would double the Packer work and the evaluation ISOs a user must download, and Windows 11 needs
TPM and Secure Boot settings in VirtualBox. Cloning one image for both VMs, however, gives them the
same machine SID; because the domain SID is derived from the first DC's machine SID, the member
then refuses to join ("the SID of the domain you attempted to join was identical to the SID of this
machine").

## Decision

Build a single Windows Server 2022 Standard Evaluation box and end the Packer build with
`sysprep /generalize /oobe` and an answer file (`packer/answer/sysprep-unattend.xml`), so each
Vagrant VM gets a new machine SID at first boot. WS01 is a member server playing the workstation.

## Consequences

- Positive: one ISO, one Packer template, about half the build time and disk; the member join works.
- Negative: WS01 is a server OS, so workstation-only telemetry (M2) may differ from Windows 11;
  first boot of each VM runs OOBE, which adds a few minutes. A Windows 11 box can be added later as
  a second Packer source if M2 needs it.
