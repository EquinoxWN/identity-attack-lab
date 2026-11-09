"""Command line: validate and render the lab, check isolation, analyze BloodHound data.

Exit codes: 0 success, 1 a check failed (drift, isolation violation, path mismatch),
2 invalid input (bad spec, malformed collection, unknown arguments).
"""

from __future__ import annotations

import argparse
import sys
from collections.abc import Sequence
from pathlib import Path

from .bloodhound import CollectionError, load_collection
from .isolation import (
    Violation,
    check_answer_file,
    check_fake_secrets,
    check_packer,
    check_vagrantfile,
)
from .paths import Finding, analyze, normalize_path
from .render import drift, render_all, write_all
from .spec import LabSpec, SpecError, load_spec

DEFAULT_SPEC = Path("lab/lab.toml")
DEFAULT_MODEL = Path("bloodhound/model")


def _cmd_validate(args: argparse.Namespace) -> int:
    """Print a one-screen summary of a valid spec."""
    spec = load_spec(args.spec)
    print(f"spec: {args.spec} OK")
    print(f"domain: {spec.domain.fqdn} ({spec.domain.netbios}), network {spec.cidr}")
    for h in spec.hosts:
        print(f"host: {h.name:<6} {h.role:<6} {h.ip:<15} {h.memory_mb} MB, {h.cpus} vCPU")
    print(
        f"objects: {len(spec.users)} users, {len(spec.groups)} groups, {len(spec.acls)} ACL "
        f"misconfigurations, {len(spec.local_admins)} local admin grants, "
        f"{len(spec.sessions)} standing sessions, {len(spec.expected_paths)} expected paths"
    )
    return 0


def _cmd_render(args: argparse.Namespace) -> int:
    """Write (or with --check, compare) every generated file."""
    files = render_all(load_spec(args.spec))
    if args.check:
        stale = drift(args.root, files)
        for rel in stale:
            print(f"DRIFT {rel}: differs from the rendering of {args.spec}; run `make render`")
        print(f"render check: {len(files) - len(stale)}/{len(files)} generated files up to date")
        return 1 if stale else 0
    changed = write_all(args.root, files)
    print(f"render: {len(changed)} written, {len(files) - len(changed)} unchanged")
    return 0


def isolation_violations(root: Path) -> tuple[int, list[Violation]]:
    """Run every isolation and fake-secret check over the lab and Packer files."""
    checked = 0
    out: list[Violation] = []
    vagrantfile = root / "lab/Vagrantfile"
    targets = [
        (vagrantfile, check_vagrantfile),
        *((p, check_packer) for p in sorted((root / "packer").glob("*.pkr.hcl"))),
        *((p, check_answer_file) for p in sorted((root / "packer/answer").glob("*.xml"))),
    ]
    secret_files = [vagrantfile, *sorted((root / "lab/provision").glob("*.ps1"))]
    secret_files += sorted((root / "packer").rglob("*.pkr.hcl"))
    targets += [(p, check_fake_secrets) for p in secret_files]
    if len(targets) < 5:
        out.append(Violation(str(root), 0, "lab or Packer files are missing"))
    for path, check in targets:
        rel = path.relative_to(root).as_posix()
        if not path.is_file():
            out.append(Violation(rel, 0, "file is missing"))
            continue
        checked += 1
        out += check(path.read_text(encoding="utf-8"), rel)
    return checked, out


def _cmd_isolation(args: argparse.Namespace) -> int:
    """Fail on any network-exposure or real-looking secret problem."""
    checked, problems = isolation_violations(args.root)
    for v in problems:
        print(f"VIOLATION {v}")
    print(f"isolation: {checked} checks run, {len(problems)} violations")
    return 1 if problems else 0


def _print_findings(findings: list[Finding]) -> None:
    """Entry-point table."""
    print(f"{'START':<12} {'WHY':<28} {'HOPS':<5} PATH TO TIER ZERO")
    for f in findings:
        hops = "-" if f.hops is None else str(f.hops)
        print(f"{f.start:<12} {', '.join(f.reasons):<28} {hops:<5} {f.path or 'none'}")


def _cmd_paths(args: argparse.Namespace) -> int:
    """Shortest path into Tier Zero for every entry point of a collection."""
    graph, summary = load_collection(args.collection)
    counts = ", ".join(f"{k} {v}" for k, v in summary.objects.items())
    print(f"collection: {args.collection} ({summary.files} files; {counts})")
    findings = analyze(graph, set(args.owned))
    exposed = graph.exposed()
    principals = [n for n in graph.nodes.values() if n.kind in ("User", "Group", "Computer")]
    print(
        f"entry points: {len(findings)}; with a path to Tier Zero: "
        f"{sum(f.path is not None for f in findings)}; principals with any path to Tier Zero: "
        f"{sum(1 for n in principals if n.oid in exposed)} of {len(principals)}"
    )
    _print_findings(findings)
    return 0


def compare(spec: LabSpec, findings: list[Finding]) -> list[str]:
    """Differences between the designed paths and the analyzed ones (empty = match)."""
    problems = []
    observed = {f.start.casefold(): f for f in findings}
    expected = {p.start.casefold(): p for p in spec.expected_paths}
    for key, exp in sorted(expected.items()):
        got = observed.get(key)
        if got is None:
            problems.append(f"{exp.id}: {exp.start} is not an entry point in the collection")
        elif got.path is None:
            problems.append(f"{exp.id}: no path from {exp.start}; expected: {exp.path}")
        elif normalize_path(got.path) != normalize_path(exp.path):
            problems.append(
                f"{exp.id}: path differs\n  expected: {exp.path}\n  observed: {got.path}"
            )
    for key, got in sorted(observed.items()):
        if key not in expected and got.path is not None:
            problems.append(f"unexpected path from {got.start}: {got.path}")
    return problems


def _cmd_verify(args: argparse.Namespace) -> int:
    """Compare a collection with the paths the spec says the lab contains."""
    spec = load_spec(args.spec)
    owned = {u.name for u in spec.users if u.owned}
    graph, summary = load_collection(args.collection)
    findings = analyze(graph, owned)
    print(f"collection: {args.collection} ({summary.files} files)")
    _print_findings(findings)
    problems = compare(spec, findings)
    for p in problems:
        print(f"MISMATCH {p}")
    matched = len(spec.expected_paths) - sum(not p.startswith("unexpected") for p in problems)
    unexpected = sum(p.startswith("unexpected") for p in problems)
    print(
        f"verify: {matched}/{len(spec.expected_paths)} expected paths found, "
        f"{unexpected} unexpected paths"
    )
    return 1 if problems else 0


def build_parser() -> argparse.ArgumentParser:
    """Argument parser with one sub-command per task."""
    parser = argparse.ArgumentParser(prog="identity_attack_lab", description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("validate", help="validate lab/lab.toml")
    p.add_argument("--spec", type=Path, default=DEFAULT_SPEC)
    p.set_defaults(func=_cmd_validate)
    p = sub.add_parser("render", help="render the Vagrantfile, scripts and BloodHound model")
    p.add_argument("--spec", type=Path, default=DEFAULT_SPEC)
    p.add_argument("--root", type=Path, default=Path())
    p.add_argument("--check", action="store_true", help="fail if committed files differ")
    p.set_defaults(func=_cmd_render)
    p = sub.add_parser("isolation", help="static network-isolation and fake-secret checks")
    p.add_argument("--root", type=Path, default=Path())
    p.set_defaults(func=_cmd_isolation)
    p = sub.add_parser("paths", help="shortest paths to Tier Zero in a BloodHound collection")
    p.add_argument("collection", type=Path, nargs="?", default=DEFAULT_MODEL)
    p.add_argument("--owned", action="append", default=[], help="a principal you control")
    p.set_defaults(func=_cmd_paths)
    p = sub.add_parser("verify", help="compare a collection with the spec's expected paths")
    p.add_argument("collection", type=Path, nargs="?", default=DEFAULT_MODEL)
    p.add_argument("--spec", type=Path, default=DEFAULT_SPEC)
    p.set_defaults(func=_cmd_verify)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point; maps input errors to exit code 2."""
    args = build_parser().parse_args(argv)
    try:
        code: int = args.func(args)
    except (SpecError, CollectionError, KeyError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    return code


if __name__ == "__main__":
    sys.exit(main())
