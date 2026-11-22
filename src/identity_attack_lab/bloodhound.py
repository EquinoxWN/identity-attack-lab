"""BloodHound CE data: export the lab's designed state, load a real collection into a Graph.

`model_collection` turns the lab spec into the JSON files SharpHound CE (format version 6) writes,
so the designed domain can be explored in BloodHound CE before any VM exists, and so the path
analysis has a known-good input. `load_collection` reads the same format back, from a directory or
from the zip SharpHound or bloodhound-ce-python produce, with size limits and no extraction to disk.
"""

from __future__ import annotations

import json
import zipfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .paths import Graph, Node
from .spec import BUILTIN_GROUPS, BUILTIN_USERS, DOMAIN_TARGET, LabSpec

FORMAT_VERSION = 6
MAX_FILE_BYTES = 100 * 1024 * 1024
MAX_TOTAL_BYTES = 500 * 1024 * 1024
MAX_ZIP_ENTRIES = 200
MAX_ZIP_RATIO = 200
LOADED_TYPES = ("users", "groups", "computers", "domains")
# RIDs and well-known SIDs whose control means control of the domain.
TIER_ZERO_SUFFIXES = ("-512", "-516", "-518", "-519", "-S-1-5-32-544")
ACE_RIGHTS = frozenset(
    {
        "GenericAll",
        "GenericWrite",
        "WriteDacl",
        "WriteOwner",
        "Owns",
        "ForceChangePassword",
        "AddMember",
        "AllExtendedRights",
    }
)
_GROUP_RID_BASE, _USER_RID_BASE, _HOST_RID_BASE = 1101, 1201, 1001


class CollectionError(ValueError):
    """A collection file is malformed or too large; the message names the file."""


@dataclass
class _Ids:
    """Deterministic SIDs and BloodHound names for every principal in a spec."""

    spec: LabSpec
    sid: dict[str, str] = field(default_factory=dict)
    kind: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        """Assign SIDs: built-in RIDs first, then declared objects in spec order."""
        d = self.spec.domain.sid
        for name, rid in {**BUILTIN_GROUPS, "Domain Controllers": 516}.items():
            self._put(name, f"{d}-{rid}", "Group")
        for name, rid in BUILTIN_USERS.items():
            self._put(name, f"{d}-{rid}", "User")
        for i, g in enumerate(self.spec.groups):
            self._put(g, f"{d}-{_GROUP_RID_BASE + i}", "Group")
        for i, u in enumerate(self.spec.users):
            self._put(u.name, f"{d}-{_USER_RID_BASE + i}", "User")
        for i, h in enumerate(self.spec.hosts):
            self._put(h.name, f"{d}-{_HOST_RID_BASE + i}", "Computer")
        self._put(DOMAIN_TARGET, d, "Domain")

    def _put(self, name: str, sid: str, kind: str) -> None:
        """Record one principal."""
        self.sid[name.casefold()] = sid
        self.kind[name.casefold()] = kind

    def of(self, name: str) -> str:
        """SID of a principal name."""
        return self.sid[name.casefold()]

    def bh_name(self, name: str) -> str:
        """Name as BloodHound shows it (`ALICE@CORP.IDLAB.TEST`, `WS01.CORP.IDLAB.TEST`)."""
        fqdn = self.spec.domain.fqdn.upper()
        kind = self.kind[name.casefold()]
        if kind == "Domain":
            return fqdn
        if kind == "Computer":
            return f"{name.upper()}.{fqdn}"
        return f"{name.upper()}@{fqdn}"


def _dn(spec: LabSpec, cn: str, container: str = "CN=Users") -> str:
    """Distinguished name in the lab domain."""
    dc = ",".join(f"DC={label}" for label in spec.domain.fqdn.split("."))
    return f"CN={cn},{container},{dc}"


def _aces(spec: LabSpec, ids: _Ids, target: str) -> list[dict[str, Any]]:
    """ACEs on `target` from the spec (DCSync expands to its two extended rights)."""
    aces: list[dict[str, Any]] = []
    for acl in spec.acls:
        if acl.target.casefold() != target.casefold():
            continue
        rights = ["GetChanges", "GetChangesAll"] if acl.right == "DCSync" else [acl.right]
        aces.extend(
            {
                "PrincipalSID": ids.of(acl.principal),
                "PrincipalType": ids.kind[acl.principal.casefold()],
                "RightName": right,
                "IsInherited": False,
            }
            for right in rights
        )
    return aces


def _common(spec: LabSpec, ids: _Ids, name: str) -> dict[str, Any]:
    """Fields every SharpHound object carries."""
    return {
        "ObjectIdentifier": ids.of(name),
        "Aces": _aces(spec, ids, name),
        "IsDeleted": False,
        "IsACLProtected": False,
        "ContainedBy": None,
    }


def _props(spec: LabSpec, ids: _Ids, name: str, **extra: Any) -> dict[str, Any]:
    """Base properties of a principal."""
    return {
        "name": ids.bh_name(name),
        "domain": spec.domain.fqdn.upper(),
        "domainsid": spec.domain.sid,
        **extra,
    }


def _meta(kind: str, data: list[dict[str, Any]]) -> dict[str, Any]:
    """Wrap objects in the collection envelope."""
    return {
        "data": data,
        "meta": {"methods": 0, "type": kind, "count": len(data), "version": FORMAT_VERSION},
    }


def model_collection(spec: LabSpec) -> dict[str, dict[str, Any]]:
    """The lab as SharpHound CE JSON: file name -> document."""
    ids = _Ids(spec)
    da_members = {"administrator"} | {
        u.name.casefold() for u in spec.users if "domain admins" in {g.casefold() for g in u.groups}
    }
    users = []
    for name in spec.all_users():
        user = next((u for u in spec.users if u.name == name), None)
        users.append(
            {
                **_common(spec, ids, name),
                "Properties": _props(
                    spec,
                    ids,
                    name,
                    samaccountname=name,
                    distinguishedname=_dn(spec, name),
                    enabled=True,
                    hasspn=bool(user and user.spns),
                    serviceprincipalnames=list(user.spns) if user else [],
                    dontreqpreauth=bool(user and user.dont_require_preauth),
                    admincount=name.casefold() in da_members,
                    description=(user.description or None) if user else None,
                ),
                "PrimaryGroupSID": ids.of("Domain Users"),
                "AllowedToDelegate": [],
                "SPNTargets": [],
                "HasSIDHistory": [],
            }
        )
    # Domain Users membership comes from PrimaryGroupSID, as in a real collection.
    member_names: dict[str, list[str]] = {g.casefold(): [] for g in spec.all_groups()}
    member_names["domain admins"].append("Administrator")
    for u in spec.users:
        for g in u.groups:
            if g.casefold() != "domain users":
                member_names[g.casefold()].append(u.name)
    groups = []
    for name in (*spec.all_groups(), "Domain Controllers"):
        if name == "Domain Controllers":
            members = [{"ObjectIdentifier": ids.of(spec.dc.name), "ObjectType": "Computer"}]
        else:
            members = [
                {"ObjectIdentifier": ids.of(u), "ObjectType": "User"}
                for u in member_names[name.casefold()]
            ]
        groups.append(
            {
                **_common(spec, ids, name),
                "Properties": _props(
                    spec, ids, name, samaccountname=name, distinguishedname=_dn(spec, name)
                ),
                "Members": members,
            }
        )
    computers = []
    for host in spec.hosts:
        is_dc = host.role == "dc"
        csid = ids.of(host.name)
        admins = [{"ObjectIdentifier": ids.of("Domain Admins"), "ObjectType": "Group"}] + [
            {
                "ObjectIdentifier": ids.of(la.principal),
                "ObjectType": ids.kind[la.principal.casefold()],
            }
            for la in spec.local_admins
            if la.host == host.name
        ]
        local_groups = (
            []
            if is_dc
            else [
                {
                    "ObjectIdentifier": f"{csid}-544",
                    "Name": f"ADMINISTRATORS@{ids.bh_name(host.name)}",
                    "Results": admins,
                    "LocalNames": [],
                    "Collected": True,
                    "FailureReason": None,
                }
            ]
        )
        sessions = [
            {"UserSID": ids.of(s.user), "ComputerSID": csid}
            for s in spec.sessions
            if s.host == host.name
        ]
        container = "OU=Domain Controllers" if is_dc else "CN=Computers"
        computers.append(
            {
                **_common(spec, ids, host.name),
                "Properties": _props(
                    spec,
                    ids,
                    host.name,
                    samaccountname=f"{host.name}$",
                    distinguishedname=_dn(spec, host.name, container),
                    enabled=True,
                    isdc=is_dc,
                    unconstraineddelegation=is_dc,
                    operatingsystem="Windows Server 2022 Standard Evaluation",
                ),
                "PrimaryGroupSID": ids.of("Domain Controllers" if is_dc else "Domain Computers"),
                "IsDC": is_dc,
                "DomainSID": spec.domain.sid,
                "LocalGroups": local_groups,
                "Sessions": {"Results": sessions, "Collected": True, "FailureReason": None},
                "PrivilegedSessions": {"Results": [], "Collected": True, "FailureReason": None},
                "RegistrySessions": {"Results": [], "Collected": True, "FailureReason": None},
                "UserRights": [],
                "AllowedToDelegate": [],
                "AllowedToAct": [],
                "HasSIDHistory": [],
                "DumpSMSAPassword": [],
                "Status": None,
            }
        )
    domain = {
        **_common(spec, ids, DOMAIN_TARGET),
        "Properties": _props(spec, ids, DOMAIN_TARGET, functionallevel="2016"),
        "Trusts": [],
        "Links": [],
        "ChildObjects": [],
    }
    return {
        "users.json": _meta("users", users),
        "groups.json": _meta("groups", groups),
        "computers.json": _meta("computers", computers),
        "domains.json": _meta("domains", [domain]),
    }


@dataclass(frozen=True)
class LoadSummary:
    """What a collection contained."""

    files: int
    objects: dict[str, int]
    skipped_types: tuple[str, ...]


def _read_docs(path: Path) -> list[tuple[str, bytes]]:
    """Raw JSON files from a directory or a zip, size-limited, never extracted to disk."""
    out: list[tuple[str, bytes]] = []
    if path.is_dir():
        files = sorted(p for p in path.iterdir() if p.suffix.lower() == ".json" and p.is_file())
        total = 0
        for f in files:
            size = f.stat().st_size
            total += size
            if size > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
                raise CollectionError(f"{f}: collection exceeds the size limit")
            out.append((f.name, f.read_bytes()))
    elif path.is_file() and path.suffix.lower() == ".zip":
        try:
            with zipfile.ZipFile(path) as zf:
                infos = [i for i in zf.infolist() if i.filename.lower().endswith(".json")]
                if len(zf.infolist()) > MAX_ZIP_ENTRIES:
                    raise CollectionError(f"{path}: more than {MAX_ZIP_ENTRIES} entries")
                total = 0
                for info in sorted(infos, key=lambda i: i.filename):
                    total += info.file_size
                    ratio = info.file_size / max(info.compress_size, 1)
                    if info.file_size > MAX_FILE_BYTES or total > MAX_TOTAL_BYTES:
                        raise CollectionError(f"{path}:{info.filename}: over the size limit")
                    if ratio > MAX_ZIP_RATIO:
                        raise CollectionError(
                            f"{path}:{info.filename}: compression ratio {ratio:.0f}"
                        )
                    data = zf.read(info)
                    if len(data) != info.file_size:
                        raise CollectionError(f"{path}:{info.filename}: size mismatch")
                    out.append((info.filename, data))
        except zipfile.BadZipFile as exc:
            raise CollectionError(f"{path}: not a valid zip: {exc}") from exc
    else:
        raise CollectionError(f"{path}: expected a directory of .json files or a .zip")
    if not out:
        raise CollectionError(f"{path}: no .json files found")
    return out


def _parse(name: str, raw: bytes) -> tuple[str, list[dict[str, Any]]]:
    """Decode one collection file into (type, objects)."""
    try:
        doc = json.loads(raw.decode("utf-8-sig"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CollectionError(f"{name}: invalid JSON: {exc}") from exc
    if not isinstance(doc, dict) or not isinstance(doc.get("meta"), dict):
        raise CollectionError(f"{name}: expected an object with 'data' and 'meta'")
    kind, data = doc["meta"].get("type"), doc.get("data")
    if not isinstance(kind, str) or not isinstance(data, list):
        raise CollectionError(f"{name}: meta.type must be a string and data a list")
    for i, obj in enumerate(data):
        if not isinstance(obj, dict) or not isinstance(obj.get("ObjectIdentifier"), str):
            raise CollectionError(f"{name}: data[{i}] has no string ObjectIdentifier")
    return kind.lower(), data


def _list_of(obj: dict[str, Any], key: str, where: str) -> list[dict[str, Any]]:
    """An optional list of objects."""
    value = obj.get(key)
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(v, dict) for v in value):
        raise CollectionError(f"{where}: {key} must be a list of objects")
    return value


def _sid(entry: dict[str, Any], key: str, where: str) -> str:
    """A required SID string inside a nested entry."""
    value = entry.get(key)
    if not isinstance(value, str) or not value:
        raise CollectionError(f"{where}: missing {key}")
    return value


def _add_aces(graph: Graph, obj: dict[str, Any], where: str, is_domain: bool) -> None:
    """Control edges from an object's ACEs (GetChanges + GetChangesAll on a domain = DCSync)."""
    oid = obj["ObjectIdentifier"]
    replication: dict[str, set[str]] = {}
    for ace in _list_of(obj, "Aces", where):
        right, principal = ace.get("RightName"), _sid(ace, "PrincipalSID", where)
        if right in ACE_RIGHTS:
            graph.add_edge(principal, str(right), oid)
        elif is_domain and right in ("GetChanges", "GetChangesAll"):
            replication.setdefault(principal, set()).add(str(right))
    for principal, rights in sorted(replication.items()):
        if rights == {"GetChanges", "GetChangesAll"}:
            graph.add_edge(principal, "DCSync", oid)


def load_collection(path: Path) -> tuple[Graph, LoadSummary]:
    """Build the attack graph from SharpHound CE / bloodhound-ce-python output."""
    graph = Graph()
    counts: dict[str, int] = {}
    skipped: set[str] = set()
    parsed = [_parse(n, raw) for n, raw in _read_docs(path)]
    # Nodes first so that edges never create placeholders for objects that exist.
    for kind, data in parsed:
        if kind not in LOADED_TYPES:
            skipped.add(kind)
            continue
        counts[kind] = counts.get(kind, 0) + len(data)
        for obj in data:
            props = obj.get("Properties") or {}
            if not isinstance(props, dict):
                raise CollectionError(f"{kind}: Properties must be an object")
            oid = obj["ObjectIdentifier"]
            name = props.get("name") if isinstance(props.get("name"), str) else oid
            enabled = props.get("enabled", True) is not False
            graph.add_node(
                Node(
                    oid=oid,
                    kind={"users": "User", "groups": "Group", "computers": "Computer"}.get(
                        kind, "Domain"
                    ),
                    name=str(name),
                    tier_zero=kind == "domains"
                    or (kind == "users" and oid.endswith("-500"))
                    or (kind == "groups" and oid.upper().endswith(TIER_ZERO_SUFFIXES))
                    or (
                        kind == "computers"
                        and (obj.get("IsDC") is True or props.get("isdc") is True)
                    ),
                    has_spn=kind == "users" and enabled and props.get("hasspn") is True,
                    dont_req_preauth=kind == "users"
                    and enabled
                    and props.get("dontreqpreauth") is True,
                )
            )
    for kind, data in parsed:
        if kind not in LOADED_TYPES:
            continue
        for obj in data:
            oid = obj["ObjectIdentifier"]
            where = f"{kind}:{oid}"
            _add_aces(graph, obj, where, kind == "domains")
            pg = obj.get("PrimaryGroupSID")
            if isinstance(pg, str) and pg:
                graph.add_edge(oid, "MemberOf", pg)
            for member in _list_of(obj, "Members", where):
                graph.add_edge(_sid(member, "ObjectIdentifier", where), "MemberOf", oid)
            for group in _list_of(obj, "LocalGroups", where):
                gid = _sid(group, "ObjectIdentifier", where)
                if gid.endswith("-544") and group.get("Collected", True) is not False:
                    for member in _list_of(group, "Results", where):
                        graph.add_edge(_sid(member, "ObjectIdentifier", where), "AdminTo", oid)
            for key in ("Sessions", "PrivilegedSessions", "RegistrySessions"):
                block = obj.get(key)
                if block is None:
                    continue
                if not isinstance(block, dict):
                    raise CollectionError(f"{where}: {key} must be an object")
                for s in _list_of(block, "Results", where):
                    graph.add_edge(oid, "HasSession", _sid(s, "UserSID", where))
    if not counts:
        raise CollectionError(f"{path}: no users, groups, computers or domains data")
    return graph, LoadSummary(len(parsed), dict(sorted(counts.items())), tuple(sorted(skipped)))
