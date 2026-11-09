# RFC 0001: identity-attack-lab design

- **Status:** Accepted for M1
- **Author:** EquinoxWN
- **Created:** 2026-11-09

## Problem

People who want to learn to detect Active Directory attacks need a domain that contains the
classic misconfigurations (Kerberoastable service accounts, accounts without Kerberos
pre-authentication, abusable ACLs, admin sessions on workstations), and they need to know which
attack paths that domain actually contains. Home labs are usually built by hand: nobody can say
afterwards which misconfiguration produced which path, the VMs are often bridged onto the home
network, and passwords from tutorials end up looking real.

Users: students and blue/purple-team engineers who run the lab on their own machine; reviewers who
want to read the lab's design without building it.

## Goals (M1)

- One file (`lab/lab.toml`) describes the domain, hosts, users, groups, misconfigurations and the
  attack paths they are meant to create.
- Packer builds a Windows Server 2022 Vagrant box; Vagrant builds a DC and a member server from
  generated, idempotent PowerShell; nothing is reachable from outside the host.
- The designed domain is exported in the SharpHound CE JSON format, so BloodHound CE (or the
  built-in analyzer) shows the paths to Domain Admin before any VM exists.
- The same analyzer reads a real collection from the lab and reports any difference from the design.

## Non-goals

- Running or documenting attack techniques (M2, signal level only), log capture (M2), Sigma rules
  and hardening (M3).
- Anything reachable from the internet or another machine; cloud labs; real credentials.
- Re-implementing BloodHound's UI or all its edge types.

## Critical-to-quality measures (Define)

| CTQ | Target | How it is measured |
|---|---|---|
| Isolation | 0 violations: host-only IPs, port forwards on 127.0.0.1, no bridged NIC, ISO checksum required | `isolation` command, CI |
| Secrets | every password literal contains `EXAMPLE-NOT-A-SECRET` | spec validator + `isolation` |
| Single source of truth | 0 drifted generated files | `render --check`, CI |
| Path fidelity | 3/3 designed paths found, 0 unexpected | `verify` on the model (and on a real collection, manual) |
| Test strength | every hand mutation of core functions killed | `docs/quality/2026-11-01.md` |

## Design

```
lab/lab.toml --spec.py (validate)--> LabSpec
   LabSpec --render.py--> lab/Vagrantfile, lab/provision/*.ps1
   LabSpec --bloodhound.py--> bloodhound/model/{users,groups,computers,domains}.json
packer/windows-server-2022.pkr.hcl --> idlab/windows-server-2022 box (sysprepped)
collection dir or zip --bloodhound.load_collection--> Graph --paths.analyze--> findings
findings vs LabSpec.expected_paths --cli.compare--> verify (exit 0/1)
```

- **Spec validation** rejects unknown keys, non-`.test` domains, addresses outside
  192.168.56.0/21, passwords without the fake marker, rights that do not fit their target (DCSync
  only on the domain, ForceChangePassword only on users) and any quote, backtick or `$` in values
  that are later embedded in Ruby or PowerShell strings.
- **Rendering** is deterministic and atomic (temp file + rename, unchanged files untouched).
- **Graph analysis**: edges point in the direction control flows; breadth-first search from each
  entry point (owned users, Kerberoastable users, AS-REP roastable users) to the first Tier Zero
  node (Domain Admins, Enterprise/Schema Admins, Administrators, Domain Controllers, RID 500, DCs,
  the domain object). Ties are broken by edge kind, then target name, so output is stable.
- **Collection loading** accepts a directory or a zip, never extracts to disk, caps file size,
  total size, entry count and compression ratio.

## Alternatives considered

| Option | Why not (yet) |
|---|---|
| Use GOAD (Game of Active Directory) as is | Large (5 VMs, ~24 GB RAM), Ansible-based; its paths are documented in prose, not checked by a test. A small spec-driven lab fits a laptop and its paths are asserted. |
| Run BloodHound CE (Neo4j + Postgres) in CI and query it | Needs Docker, an API login and a bootstrap password scraped from logs; slow and brittle. The offline analyzer answers the same question in under a second; BloodHound CE stays the interactive viewer. See ADR 0002. |
| Ansible instead of generated PowerShell | Needs a control node and WinRM tuning on Windows hosts; generated scripts run with Vagrant's built-in shell provisioner and are readable. |
| Write the Vagrantfile by hand | The Vagrantfile, scripts and model would drift from each other; one spec with a drift check prevents it. |

## Measurement plan (Measure, Analyze)

`make bench` (render-check, isolation, verify, paths) records the numbers in `docs/results/m1.md`.
A full `packer build` and `vagrant up` followed by a SharpHound / bloodhound-ce-python collection
and `verify <zip>` is the manual end-to-end check; its result is recorded when it is run.

## Control

CI runs lint, mypy, tests, `render --check`, `isolation`, `verify`, `pip-audit`, and in a second
job `packer validate`, `ruby -c`, `vagrant validate` and a PowerShell parse of every script.

## Milestones

- **M1:** this design; the Packer + Vagrant lab with deliberate misconfigurations; BloodHound data
  and path analysis to Domain Admin.
- **M2:** each technique reproduced in the lab only, documented at signal level; Windows and Sysmon
  events captured as samples.
- **M3:** Sigma detections in detection-as-code tested on those samples; each misconfiguration
  fixed and re-tested.

## Risks and open questions

- The model collection follows the SharpHound CE v6 field names but has not been ingested into a
  live BloodHound CE yet; field drift in newer collectors would show up as `verify` failures.
- The full VM build has not been run on this machine (needs VirtualBox, a Windows ISO, about 8 GB
  RAM and 40 GB disk); static checks cannot prove the PowerShell works on a real DC.
- Session collection depends on SharpHound privileges; a missing HasSession edge in a real
  collection shows up as a `verify` mismatch, not a silent pass.
