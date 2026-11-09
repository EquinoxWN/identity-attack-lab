# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub:
**Security > Report a vulnerability** on this repository
(`https://github.com/EquinoxWN/identity-attack-lab/security/advisories/new`). Do not open a public issue.

Include what you found, how to reproduce it, and the impact you expect. You will get an answer
within 7 days. Fixes are released as soon as they are ready, and you are credited unless you ask
not to be.

## Supported versions

This project is pre-1.0. Only the latest commit on `main` receives fixes.

## Scope

- **In scope:** Anything that could expose the lab beyond the host (bridged networking, port forwards off loopback, unverified ISOs), real-looking credentials, unsafe parsing of the spec or of BloodHound collections (zip bombs, oversized files), and path analysis that hides a real path.
- **Out of scope:** Requests for attack tooling or step-by-step attack recipes. Never submit real credentials, real domain data or collections from networks you do not own: the lab and its fixtures stay local and fake.

## How this repository protects itself

- Every GitHub Action is pinned to a full commit SHA, and workflows run with read-only
  permissions and without persisted credentials.
- Dependabot update pull requests are paused (`open-pull-requests-limit: 0`) so the repository keeps a single `main` branch; dependencies are updated by hand and checked by the CI audit.
- CI runs lint, tests and a known-vulnerability audit (`make audit`) on every push and pull request.
