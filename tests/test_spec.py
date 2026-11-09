"""Spec validation: the real lab loads, and every unsafe or inconsistent spec is rejected."""

from __future__ import annotations

import re
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest

from identity_attack_lab import __version__
from identity_attack_lab.spec import MAX_SPEC_BYTES, SpecError, load_spec, parse_spec

from .conftest import SPEC

Doc = dict[str, Any]


def test_version() -> None:
    assert __version__ == "0.1.0"


def test_lab_spec_loads() -> None:
    spec = load_spec(SPEC)
    assert spec.domain.fqdn == "corp.idlab.test"
    assert spec.dc.name == "DC01"
    assert [u.name for u in spec.users if u.owned] == ["alice", "bob"]
    assert len(spec.expected_paths) == 3
    assert spec.all_groups()[:3] == ("Domain Admins", "Domain Users", "Domain Computers")


def _set(path: str, value: Any) -> Callable[[Doc], None]:
    """Mutator that sets doc[a][b]... (integers index lists)."""

    def apply(doc: Doc) -> None:
        keys: list[Any] = [int(k) if k.isdigit() else k for k in path.split(".")]
        target: Any = doc
        for k in keys[:-1]:
            target = target[k]
        target[keys[-1]] = value

    return apply


def _drop(path: str) -> Callable[[Doc], None]:
    """Mutator that deletes doc[a][b]..."""

    def apply(doc: Doc) -> None:
        keys: list[Any] = [int(k) if k.isdigit() else k for k in path.split(".")]
        target: Any = doc
        for k in keys[:-1]:
            target = target[k]
        del target[keys[-1]]

    return apply


def _append(key: str, item: Any) -> Callable[[Doc], None]:
    """Mutator that appends to a top-level list."""
    return lambda doc: doc.setdefault(key, []).append(item)


BAD: dict[str, tuple[Callable[[Doc], None], str]] = {
    "real-tld": (_set("domain.fqdn", "corp.example.com"), "domain.fqdn"),
    "bad-netbios": (_set("domain.netbios", "idlab"), "domain.netbios"),
    "bad-sid": (_set("domain.sid", "S-1-5-32-544"), "domain.sid"),
    "missing-domain": (_drop("domain"), "missing key"),
    "unknown-top-key": (_set("extra", 1), "unknown key"),
    "unknown-domain-key": (_set("domain.forest", "x"), "unknown key"),
    "public-cidr": (_set("network.cidr", "8.8.8.0/24"), "host-only range"),
    "host-bits-cidr": (_set("network.cidr", "192.168.56.5/24"), "network.cidr"),
    "ipv6-cidr": (_set("network.cidr", "fd00::/64"), "host-only range"),
    "ip-outside": (_set("hosts.0.ip", "192.168.57.10"), "not a usable address"),
    "ip-broadcast": (_set("hosts.0.ip", "192.168.56.255"), "not a usable address"),
    "ip-host-adapter": (_set("hosts.0.ip", "192.168.56.1"), "host adapter"),
    "ip-garbage": (_set("hosts.0.ip", "not-an-ip"), "hosts[0].ip"),
    "duplicate-ip": (_set("hosts.1.ip", "192.168.56.10"), "duplicate"),
    "two-dcs": (_set("hosts.1.role", "dc"), "exactly one"),
    "no-dc": (_set("hosts.0.role", "member"), "exactly one"),
    "bad-role": (_set("hosts.0.role", "router"), "role"),
    "memory-too-small": (_set("hosts.0.memory_mb", 512), "outside"),
    "memory-bool": (_set("hosts.0.memory_mb", True), "integer"),
    "cpus-string": (_set("hosts.0.cpus", "2"), "integer"),
    "lowercase-host": (_set("hosts.0.name", "dc01"), "hosts[0].name"),
    "real-password": (_set("users.0.password", "Summer2026!xyzA"), "EXAMPLE-NOT-A-SECRET"),
    "weak-password": (_set("users.0.password", "EXAMPLE-NOT-A-SECRET"), "upper, lower"),
    "no-digit-password": (_set("users.0.password", "EXAMPLE-NOT-A-SECRET-abc"), "upper, lower"),
    "quote-password": (_set("users.0.password", "EXAMPLE-NOT-A-SECRET-a1'"), "quotes"),
    "dollar-password": (_set("domain.admin_password", "EXAMPLE-NOT-A-SECRET-a1$"), "quotes"),
    "unknown-group": (_set("users.2.groups", ["Nope"]), "unknown group"),
    "duplicate-membership": (_set("users.2.groups", ["Helpdesk", "helpdesk"]), "duplicate"),
    "duplicate-user": (_set("users.1.name", "alice"), "more than one principal"),
    "bad-user-name": (_set("users.0.name", "Alice Smith"), "users[0].name"),
    "bad-spn": (_set("users.4.spns", ["no-slash"]), "spns"),
    "flag-not-bool": (_set("users.0.owned", "yes"), "true or false"),
    "description-quote": (_set("users.0.description", "it's"), "description"),
    "groups-not-list": (_set("groups", "Helpdesk"), "expected a list"),
    "group-collides-builtin": (_set("groups", ["Domain Admins"]), "duplicate"),
    "user-named-like-group": (_set("users.0.name", "helpdesk"), "more than one principal"),
    "bad-right": (_set("acls.0.right", "ReadProperty"), "not one of"),
    "unknown-acl-principal": (_set("acls.0.principal", "mallory"), "unknown principal"),
    "computer-acl-principal": (_set("acls.0.principal", "WS01"), "user or group"),
    "dcsync-on-user": (_set("acls.2.target", "bob"), "DCSync cannot target a user"),
    "reset-on-group": (_set("acls.0.target", "IT Admins"), "cannot target a group"),
    "addmember-on-user": (_set("acls.1.right", "AddMember"), "cannot target a user"),
    "admin-on-user": (_set("local_admins.0.host", "alice"), "host must be a host"),
    "session-builtin-user": (_set("sessions.0.user", "Administrator"), "declared user"),
    "session-unknown-host": (_set("sessions.0.host", "WS99"), "unknown principal"),
    "path-wrong-start": (_set("expected_paths.0.path", "bob -GenericAll-> x"), "must begin"),
    "duplicate-path-id": (_set("expected_paths.1.id", "acl-dcsync"), "duplicate"),
    "bad-technique": (_set("expected_paths.0.technique", "T99"), "technique"),
    "table-not-table": (_append("acls", "alice"), "expected a table"),
    "too-many": (_set("groups", [f"G{i}" for i in range(501)]), "more than 500"),
}


@pytest.mark.parametrize("case", sorted(BAD))
def test_invalid_specs_are_rejected(doc: Doc, case: str) -> None:
    mutate, message = BAD[case]
    mutate(doc)
    with pytest.raises(SpecError, match=re.escape(message)):
        parse_spec(doc)


def test_names_resolve_case_insensitively(doc: Doc) -> None:
    doc["acls"][0]["principal"] = "HELPDESK"
    spec = parse_spec(doc)
    assert spec.acls[0].principal == "Helpdesk"


def test_defaults_apply(doc: Doc) -> None:
    del doc["hosts"][1]["memory_mb"]
    del doc["hosts"][1]["cpus"]
    spec = parse_spec(doc)
    assert (spec.hosts[1].memory_mb, spec.hosts[1].cpus) == (2048, 2)


def test_empty_optional_sections(doc: Doc) -> None:
    for key in ("groups", "users", "acls", "local_admins", "sessions", "expected_paths"):
        doc.pop(key)
    spec = parse_spec(doc)
    assert spec.users == ()
    assert spec.expected_paths == ()


def test_invalid_toml(tmp_path: Path) -> None:
    bad = tmp_path / "lab.toml"
    bad.write_text("[domain\n", encoding="utf-8")
    with pytest.raises(SpecError, match="invalid TOML"):
        load_spec(bad)


def test_oversized_spec(tmp_path: Path) -> None:
    big = tmp_path / "lab.toml"
    big.write_text("#" * (MAX_SPEC_BYTES + 1), encoding="utf-8")
    with pytest.raises(SpecError, match="limit"):
        load_spec(big)


def test_empty_spec_file(tmp_path: Path) -> None:
    empty = tmp_path / "lab.toml"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(SpecError, match="missing key"):
        load_spec(empty)
