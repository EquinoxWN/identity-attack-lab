# ADR 0002: Check attack paths offline against a model collection, keep BloodHound CE as the viewer

- **Status:** Accepted

## Context

M1 must show which paths in the lab lead to Domain Admin. BloodHound CE answers that, but it runs
as Docker containers (API, Neo4j, Postgres), needs an interactive login, and cannot run here
(no Docker locally, see WORKING_RULES.md). The lab VMs themselves need VirtualBox and a Windows ISO,
so a real collection is not available in CI either.

## Decision

- Render the lab spec into the SharpHound CE JSON format (`bloodhound/model/`) and commit it.
- Implement the path question offline (`paths.py`): breadth-first shortest path from each entry
  point to Tier Zero over the control edges BloodHound uses.
- `verify` compares the analysis with `expected_paths` in the spec, and the same command accepts a
  real SharpHound zip from the lab.
- BloodHound CE remains the interactive viewer: the model and `bloodhound/queries.cypher` can be
  loaded into it by hand.

## Consequences

- Positive: every change to a misconfiguration shows up as a test failure within a second; no
  container, VM or network is needed in CI; the same code checks the real lab later.
- Negative: the analyzer covers 12 edge kinds, not BloodHound's full set (no ADCS, GPO, delegation
  or trust edges), so it can miss paths BloodHound would show; the model's compatibility with a
  live BloodHound CE ingest is not yet proven. Both are listed as limitations in the README.
