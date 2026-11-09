"""Lab specification: load and validate `lab/lab.toml` into typed, immutable records.

The spec is the single source of truth for the lab. The Vagrantfile, the provisioning scripts and
the BloodHound model collection are all rendered from it, so every rule that keeps the lab safe
(reserved `.test` domain, host-only addresses, obviously fake passwords) is enforced here first.
Unknown keys are rejected at every level so a typo cannot silently drop a setting.
"""

from __future__ import annotations

import ipaddress
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

MAX_SPEC_BYTES = 1_000_000
MAX_ITEMS = 500
FAKE_MARKER = "EXAMPLE-NOT-A-SECRET"
# VirtualBox 6.1.28+ only allows host-only addresses in this range without extra host config.
HOST_ONLY_RANGE = ipaddress.IPv4Network("192.168.56.0/21")

BUILTIN_GROUPS = {"Domain Admins": 512, "Domain Users": 513, "Domain Computers": 515}
BUILTIN_USERS = {"Administrator": 500}
ACL_RIGHTS = (
    "GenericAll",
    "GenericWrite",
    "WriteDacl",
    "WriteOwner",
    "Owns",
    "ForceChangePassword",
    "AddMember",
    "AllExtendedRights",
    "DCSync",
)
DOMAIN_TARGET = "domain"

_FQDN = re.compile(r"^(?=.{1,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+test$")
_NETBIOS = re.compile(r"^[A-Z][A-Z0-9-]{0,14}$")
_DOMAIN_SID = re.compile(r"^S-1-5-21-\d{1,10}-\d{1,10}-\d{1,10}$")
_HOST = re.compile(r"^[A-Z][A-Z0-9-]{0,14}$")
_USER = re.compile(r"^[a-z][a-z0-9_.-]{0,19}$")
_GROUP = re.compile(r"^[A-Za-z][A-Za-z0-9 _-]{0,63}$")
_SPN = re.compile(r"^[A-Za-z][A-Za-z0-9-]{0,31}/[a-z0-9.-]{1,253}(:\d{1,5})?$")
_ID = re.compile(r"^[a-z0-9][a-z0-9-]{0,47}$")
_TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")


class SpecError(ValueError):
    """The lab spec is invalid; the message names the offending key."""


@dataclass(frozen=True)
class Domain:
    """AD domain identity and the fake DSRM/administrator password."""

    fqdn: str
    netbios: str
    sid: str
    admin_password: str


@dataclass(frozen=True)
class Host:
    """One Vagrant VM: domain controller or member."""

    name: str
    role: str
    ip: str
    memory_mb: int
    cpus: int


@dataclass(frozen=True)
class User:
    """A domain user and the misconfiguration flags it carries."""

    name: str
    password: str
    groups: tuple[str, ...]
    spns: tuple[str, ...]
    dont_require_preauth: bool
    owned: bool
    description: str


@dataclass(frozen=True)
class Acl:
    """An access-control entry: `principal` holds `right` over `target`."""

    principal: str
    right: str
    target: str


@dataclass(frozen=True)
class LocalAdmin:
    """`principal` is in the local Administrators group of `host`."""

    host: str
    principal: str


@dataclass(frozen=True)
class Session:
    """`user` keeps a logon session on `host` (a scheduled task in the lab)."""

    host: str
    user: str


@dataclass(frozen=True)
class ExpectedPath:
    """An attack path the lab is designed to contain, written as BloodHound would show it."""

    id: str
    technique: str
    start: str
    path: str


@dataclass(frozen=True)
class LabSpec:
    """The whole validated lab."""

    domain: Domain
    cidr: str
    hosts: tuple[Host, ...]
    groups: tuple[str, ...]
    users: tuple[User, ...]
    acls: tuple[Acl, ...]
    local_admins: tuple[LocalAdmin, ...]
    sessions: tuple[Session, ...]
    expected_paths: tuple[ExpectedPath, ...]

    @property
    def dc(self) -> Host:
        """The single domain controller."""
        return next(h for h in self.hosts if h.role == "dc")

    def all_groups(self) -> tuple[str, ...]:
        """Built-in groups followed by declared ones."""
        return (*BUILTIN_GROUPS, *self.groups)

    def all_users(self) -> tuple[str, ...]:
        """Built-in users followed by declared ones."""
        return (*BUILTIN_USERS, *(u.name for u in self.users))


def _keys(table: dict[str, Any], where: str, required: set[str], optional: set[str]) -> None:
    """Reject missing and unknown keys."""
    missing = required - table.keys()
    if missing:
        raise SpecError(f"{where}: missing key(s) {sorted(missing)}")
    unknown = table.keys() - required - optional
    if unknown:
        raise SpecError(f"{where}: unknown key(s) {sorted(unknown)}")


def _str(value: Any, where: str, pattern: re.Pattern[str] | None = None) -> str:
    """A string, optionally matching a pattern."""
    if not isinstance(value, str):
        raise SpecError(f"{where}: expected a string, got {type(value).__name__}")
    if pattern is not None and not pattern.fullmatch(value):
        raise SpecError(f"{where}: {value!r} does not match {pattern.pattern}")
    return value


def _int(value: Any, where: str, low: int, high: int) -> int:
    """An integer within [low, high] (booleans rejected)."""
    if isinstance(value, bool) or not isinstance(value, int):
        raise SpecError(f"{where}: expected an integer, got {type(value).__name__}")
    if not low <= value <= high:
        raise SpecError(f"{where}: {value} is outside {low}..{high}")
    return value


def _bool(value: Any, where: str) -> bool:
    """A real boolean."""
    if not isinstance(value, bool):
        raise SpecError(f"{where}: expected true or false, got {value!r}")
    return value


def _list(value: Any, where: str) -> list[Any]:
    """A bounded list."""
    if not isinstance(value, list):
        raise SpecError(f"{where}: expected a list, got {type(value).__name__}")
    if len(value) > MAX_ITEMS:
        raise SpecError(f"{where}: more than {MAX_ITEMS} entries")
    return value


def _tables(doc: dict[str, Any], key: str) -> list[dict[str, Any]]:
    """An optional array of tables."""
    items = _list(doc.get(key, []), key)
    for i, item in enumerate(items):
        if not isinstance(item, dict):
            raise SpecError(f"{key}[{i}]: expected a table")
    return items


def _password(value: Any, where: str) -> str:
    """A password that is visibly fake and still meets AD complexity rules."""
    pw = _str(value, where)
    if FAKE_MARKER not in pw:
        raise SpecError(f"{where}: lab passwords must contain {FAKE_MARKER!r}")
    classes = sum(
        [
            any(c.isupper() for c in pw),
            any(c.islower() for c in pw),
            any(c.isdigit() for c in pw),
            any(not c.isalnum() for c in pw),
        ]
    )
    if len(pw) > 127 or classes < 4:
        raise SpecError(f"{where}: needs upper, lower, digit and symbol, at most 127 chars")
    if any(c in pw for c in "'\"`$\r\n"):
        raise SpecError(f"{where}: quotes, backticks, '$' and newlines are not allowed")
    return pw


def _unique(names: list[str], where: str) -> None:
    """Fail on case-insensitive duplicates (AD names are case-insensitive)."""
    seen: set[str] = set()
    for name in names:
        key = name.casefold()
        if key in seen:
            raise SpecError(f"{where}: duplicate name {name!r}")
        seen.add(key)


def _domain(doc: dict[str, Any]) -> Domain:
    """The [domain] table."""
    table = doc.get("domain")
    if not isinstance(table, dict):
        raise SpecError("domain: missing [domain] table")
    _keys(table, "domain", {"fqdn", "netbios", "sid", "admin_password"}, set())
    return Domain(
        fqdn=_str(table["fqdn"], "domain.fqdn", _FQDN),
        netbios=_str(table["netbios"], "domain.netbios", _NETBIOS),
        sid=_str(table["sid"], "domain.sid", _DOMAIN_SID),
        admin_password=_password(table["admin_password"], "domain.admin_password"),
    )


def _network(doc: dict[str, Any]) -> ipaddress.IPv4Network:
    """The [network] table: a private host-only range."""
    table = doc.get("network")
    if not isinstance(table, dict):
        raise SpecError("network: missing [network] table")
    _keys(table, "network", {"cidr"}, set())
    text = _str(table["cidr"], "network.cidr")
    try:
        net = ipaddress.ip_network(text, strict=True)
    except ValueError as exc:
        raise SpecError(f"network.cidr: {exc}") from exc
    if not isinstance(net, ipaddress.IPv4Network) or not net.subnet_of(HOST_ONLY_RANGE):
        raise SpecError(
            f"network.cidr: {text} must be inside the host-only range {HOST_ONLY_RANGE}"
        )
    return net


def _hosts(doc: dict[str, Any], net: ipaddress.IPv4Network) -> tuple[Host, ...]:
    """The [[hosts]] tables: exactly one DC, unique names and addresses."""
    hosts = []
    for i, t in enumerate(_tables(doc, "hosts")):
        where = f"hosts[{i}]"
        _keys(t, where, {"name", "role", "ip"}, {"memory_mb", "cpus"})
        role = _str(t["role"], f"{where}.role")
        if role not in ("dc", "member"):
            raise SpecError(f"{where}.role: must be 'dc' or 'member'")
        ip_text = _str(t["ip"], f"{where}.ip")
        try:
            ip = ipaddress.ip_address(ip_text)
        except ValueError as exc:
            raise SpecError(f"{where}.ip: {exc}") from exc
        if ip not in net or ip in (net.network_address, net.broadcast_address):
            raise SpecError(f"{where}.ip: {ip_text} is not a usable address in {net}")
        if ip == net.network_address + 1:
            raise SpecError(f"{where}.ip: {ip_text} is the host adapter's own address")
        hosts.append(
            Host(
                name=_str(t["name"], f"{where}.name", _HOST),
                role=role,
                ip=ip_text,
                memory_mb=_int(t.get("memory_mb", 2048), f"{where}.memory_mb", 1024, 16384),
                cpus=_int(t.get("cpus", 2), f"{where}.cpus", 1, 8),
            )
        )
    if sum(h.role == "dc" for h in hosts) != 1:
        raise SpecError("hosts: exactly one host must have role 'dc'")
    _unique([h.name for h in hosts], "hosts")
    _unique([h.ip for h in hosts], "hosts (ip)")
    return tuple(hosts)


def _users(doc: dict[str, Any], groups: set[str]) -> tuple[User, ...]:
    """The [[users]] tables."""
    users = []
    for i, t in enumerate(_tables(doc, "users")):
        where = f"users[{i}]"
        _keys(
            t,
            where,
            {"name", "password"},
            {"groups", "spns", "dont_require_preauth", "owned", "description"},
        )
        member_of = tuple(_str(g, f"{where}.groups") for g in _list(t.get("groups", []), where))
        for g in member_of:
            if g.casefold() not in groups:
                raise SpecError(f"{where}.groups: unknown group {g!r}")
        _unique(list(member_of), f"{where}.groups")
        spns = tuple(_str(s, f"{where}.spns", _SPN) for s in _list(t.get("spns", []), where))
        users.append(
            User(
                name=_str(t["name"], f"{where}.name", _USER),
                password=_password(t["password"], f"{where}.password"),
                groups=member_of,
                spns=spns,
                dont_require_preauth=_bool(t.get("dont_require_preauth", False), where),
                owned=_bool(t.get("owned", False), where),
                description=_str(t.get("description", ""), f"{where}.description"),
            )
        )
        if len(users[-1].description) > 200 or any(c in users[-1].description for c in "'\"`$"):
            raise SpecError(f"{where}.description: at most 200 chars, no quotes or '$'")
    return tuple(users)


def _resolve(name: str, names: dict[str, str], where: str) -> str:
    """Canonical spelling of a known principal name (case-insensitive lookup)."""
    canonical = names.get(name.casefold())
    if canonical is None:
        raise SpecError(f"{where}: unknown principal {name!r}")
    return canonical


def _acls(doc: dict[str, Any], kinds: dict[str, str], names: dict[str, str]) -> tuple[Acl, ...]:
    """The [[acls]] tables, with the right checked against the target's kind."""
    acls = []
    for i, t in enumerate(_tables(doc, "acls")):
        where = f"acls[{i}]"
        _keys(t, where, {"principal", "right", "target"}, set())
        right = _str(t["right"], f"{where}.right")
        if right not in ACL_RIGHTS:
            raise SpecError(f"{where}.right: {right!r} is not one of {list(ACL_RIGHTS)}")
        principal = _resolve(_str(t["principal"], f"{where}.principal"), names, where)
        if kinds[principal.casefold()] not in ("user", "group"):
            raise SpecError(f"{where}.principal: must be a user or group")
        raw_target = _str(t["target"], f"{where}.target")
        if raw_target == DOMAIN_TARGET:
            target, kind = DOMAIN_TARGET, "domain"
        else:
            target = _resolve(raw_target, names, where)
            kind = kinds[target.casefold()]
        allowed = {
            "DCSync": {"domain"},
            "ForceChangePassword": {"user"},
            "AddMember": {"group"},
        }.get(right, {"user", "group", "computer", "domain"})
        if kind not in allowed:
            raise SpecError(f"{where}: {right} cannot target a {kind}")
        acls.append(Acl(principal=principal, right=right, target=target))
    return tuple(acls)


def _expected(doc: dict[str, Any], names: dict[str, str]) -> tuple[ExpectedPath, ...]:
    """The [[expected_paths]] tables."""
    paths = []
    for i, t in enumerate(_tables(doc, "expected_paths")):
        where = f"expected_paths[{i}]"
        _keys(t, where, {"id", "technique", "start", "path"}, set())
        start = _resolve(_str(t["start"], f"{where}.start"), names, where)
        path = _str(t["path"], f"{where}.path")
        if not path.casefold().startswith(start.casefold() + " -"):
            raise SpecError(f"{where}.path: must begin with the start principal {start!r}")
        paths.append(
            ExpectedPath(
                id=_str(t["id"], f"{where}.id", _ID),
                technique=_str(t["technique"], f"{where}.technique", _TECHNIQUE),
                start=start,
                path=path,
            )
        )
    _unique([p.id for p in paths], "expected_paths")
    _unique([p.start for p in paths], "expected_paths (start)")
    return tuple(paths)


def parse_spec(doc: dict[str, Any]) -> LabSpec:
    """Validate a decoded TOML document."""
    _keys(
        doc,
        "spec",
        {"domain", "network", "hosts"},
        {"groups", "users", "acls", "local_admins", "sessions", "expected_paths"},
    )
    domain = _domain(doc)
    net = _network(doc)
    hosts = _hosts(doc, net)
    groups = tuple(_str(g, "groups", _GROUP) for g in _list(doc.get("groups", []), "groups"))
    _unique([*BUILTIN_GROUPS, *groups], "groups")
    users = _users(doc, {g.casefold() for g in (*BUILTIN_GROUPS, *groups)})
    kinds: dict[str, str] = {}
    names: dict[str, str] = {}
    for kind, items in (
        ("group", (*BUILTIN_GROUPS, *groups)),
        ("user", (*BUILTIN_USERS, *(u.name for u in users))),
        ("computer", tuple(h.name for h in hosts)),
    ):
        for name in items:
            if name.casefold() in names:
                raise SpecError(f"name {name!r} is used by more than one principal")
            names[name.casefold()] = name
            kinds[name.casefold()] = kind
    acls = _acls(doc, kinds, names)
    local_admins = []
    for i, t in enumerate(_tables(doc, "local_admins")):
        where = f"local_admins[{i}]"
        _keys(t, where, {"host", "principal"}, set())
        host = _resolve(_str(t["host"], f"{where}.host"), names, where)
        principal = _resolve(_str(t["principal"], f"{where}.principal"), names, where)
        if kinds[host.casefold()] != "computer" or kinds[principal.casefold()] == "computer":
            raise SpecError(f"{where}: host must be a host and principal a user or group")
        local_admins.append(LocalAdmin(host=host, principal=principal))
    sessions = []
    for i, t in enumerate(_tables(doc, "sessions")):
        where = f"sessions[{i}]"
        _keys(t, where, {"host", "user"}, set())
        host = _resolve(_str(t["host"], f"{where}.host"), names, where)
        user = _resolve(_str(t["user"], f"{where}.user"), names, where)
        if kinds[host.casefold()] != "computer" or user not in {u.name for u in users}:
            raise SpecError(f"{where}: host must be a host and user a declared user")
        sessions.append(Session(host=host, user=user))
    return LabSpec(
        domain=domain,
        cidr=str(net),
        hosts=hosts,
        groups=groups,
        users=users,
        acls=acls,
        local_admins=tuple(local_admins),
        sessions=tuple(sessions),
        expected_paths=_expected(doc, names),
    )


def load_spec(path: Path) -> LabSpec:
    """Read, size-check and validate a lab spec file."""
    size = path.stat().st_size
    if size > MAX_SPEC_BYTES:
        raise SpecError(f"{path}: {size} bytes is over the {MAX_SPEC_BYTES}-byte limit")
    try:
        doc = tomllib.loads(path.read_text(encoding="utf-8"))
    except tomllib.TOMLDecodeError as exc:
        raise SpecError(f"{path}: invalid TOML: {exc}") from exc
    return parse_spec(doc)
