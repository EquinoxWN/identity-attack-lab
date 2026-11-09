"""BloodHound data: the model matches the spec, and real-collection parsing is strict and bounded."""

from __future__ import annotations

import json
import zipfile
from pathlib import Path
from typing import Any

import pytest

from identity_attack_lab import bloodhound
from identity_attack_lab.bloodhound import CollectionError, load_collection, model_collection
from identity_attack_lab.paths import analyze, normalize_path
from identity_attack_lab.spec import load_spec, parse_spec

from .conftest import ROOT, SPEC

D = "S-1-5-21-1-2-3"


def _write(dir_: Path, docs: dict[str, Any]) -> Path:
    """Write collection documents into a directory."""
    dir_.mkdir(parents=True, exist_ok=True)
    for name, doc in docs.items():
        (dir_ / name).write_text(json.dumps(doc), encoding="utf-8")
    return dir_


def _env(kind: str, data: list[dict[str, Any]]) -> dict[str, Any]:
    """Collection envelope."""
    return {"data": data, "meta": {"type": kind, "count": len(data), "version": 6}}


def _user(rid: int, name: str, **props: Any) -> dict[str, Any]:
    """Minimal user object."""
    return {"ObjectIdentifier": f"{D}-{rid}", "Properties": {"name": name, **props}}


def test_model_documents_have_the_collection_envelope() -> None:
    docs = model_collection(load_spec(SPEC))
    assert sorted(docs) == ["computers.json", "domains.json", "groups.json", "users.json"]
    for name, doc in docs.items():
        assert doc["meta"]["type"] == name.removesuffix(".json")
        assert doc["meta"]["count"] == len(doc["data"])
        assert doc["meta"]["version"] == 6


def test_model_marks_the_misconfigurations() -> None:
    docs = model_collection(load_spec(SPEC))
    users = {u["Properties"]["samaccountname"]: u for u in docs["users.json"]["data"]}
    assert users["svc_sql"]["Properties"]["hasspn"] is True
    assert users["carol"]["Properties"]["dontreqpreauth"] is True
    assert users["alice"]["Properties"]["hasspn"] is False
    assert users["da_admin"]["Properties"]["admincount"] is True
    domain_rights = sorted(a["RightName"] for a in docs["domains.json"]["data"][0]["Aces"])
    assert domain_rights == ["GetChanges", "GetChangesAll"]
    ws01 = next(c for c in docs["computers.json"]["data"] if not c["IsDC"])
    assert len(ws01["Sessions"]["Results"]) == 1
    assert ws01["LocalGroups"][0]["ObjectIdentifier"].endswith("-544")


def test_committed_model_reproduces_every_expected_path() -> None:
    spec = load_spec(SPEC)
    graph, summary = load_collection(ROOT / "bloodhound" / "model")
    assert summary.files == 4
    assert summary.skipped_types == ()
    owned = {u.name for u in spec.users if u.owned}
    found = {f.start.casefold(): f for f in analyze(graph, owned)}
    for exp in spec.expected_paths:
        got = found[exp.start.casefold()].path
        assert got is not None
        assert normalize_path(got) == normalize_path(exp.path)
    assert found["bob"].path is None


def test_removing_a_misconfiguration_removes_its_path(doc: dict[str, Any], tmp_path: Path) -> None:
    doc["acls"] = [a for a in doc["acls"] if a["right"] != "DCSync"]
    spec = parse_spec(doc)
    graph, _ = load_collection(_write(tmp_path / "c", model_collection(spec)))
    alice = next(f for f in analyze(graph, {"alice"}) if f.start == "ALICE")
    assert alice.path is None


def _domain(rights: list[str]) -> dict[str, Any]:
    """Domain document whose ACEs grant `rights` to user 1100."""
    aces = [{"PrincipalSID": f"{D}-1100", "RightName": r} for r in rights]
    obj = {"ObjectIdentifier": D, "Properties": {"name": "D.TEST"}, "Aces": aces}
    return _env("domains", [obj])


def test_dcsync_needs_both_replication_rights(tmp_path: Path) -> None:
    users = _env("users", [_user(1100, "U@D.TEST")])
    one = _write(tmp_path / "one", {"u.json": users, "d.json": _domain(["GetChanges"])})
    both = _write(
        tmp_path / "both", {"u.json": users, "d.json": _domain(["GetChanges", "GetChangesAll"])}
    )
    assert load_collection(one)[0].shortest_path(f"{D}-1100") is None
    path = load_collection(both)[0].shortest_path(f"{D}-1100")
    assert path is not None
    assert path[0].kind == "DCSync"


def test_disabled_users_are_not_roastable(tmp_path: Path) -> None:
    users = _env(
        "users",
        [
            _user(1101, "OFF@D.TEST", enabled=False, hasspn=True, dontreqpreauth=True),
            _user(1102, "ON@D.TEST", enabled=True, hasspn=True),
        ],
    )
    graph, _ = load_collection(_write(tmp_path / "c", {"users.json": users}))
    assert [f.start for f in analyze(graph, set())] == ["ON"]


def test_tier_zero_detection(tmp_path: Path) -> None:
    docs = {
        "u.json": _env("users", [_user(500, "ADMINISTRATOR@D.TEST"), _user(1100, "X@D.TEST")]),
        "g.json": _env(
            "groups",
            [
                {"ObjectIdentifier": f"{D}-512", "Properties": {"name": "DA"}},
                {"ObjectIdentifier": "D.TEST-S-1-5-32-544", "Properties": {"name": "ADMINS"}},
                {"ObjectIdentifier": f"{D}-1200", "Properties": {"name": "PLAIN"}},
            ],
        ),
        "c.json": _env(
            "computers",
            [
                {"ObjectIdentifier": f"{D}-1000", "Properties": {"name": "DC"}, "IsDC": True},
                {"ObjectIdentifier": f"{D}-1001", "Properties": {"name": "WS"}, "IsDC": False},
            ],
        ),
    }
    graph, _ = load_collection(_write(tmp_path / "c", docs))
    assert graph.tier_zero() == {f"{D}-500", f"{D}-512", "D.TEST-S-1-5-32-544", f"{D}-1000"}


def test_local_groups_other_than_administrators_are_ignored(tmp_path: Path) -> None:
    comp = {
        "ObjectIdentifier": f"{D}-1001",
        "Properties": {"name": "WS.D.TEST"},
        "LocalGroups": [
            {"ObjectIdentifier": f"{D}-1001-555", "Results": [{"ObjectIdentifier": f"{D}-1100"}]},
            {
                "ObjectIdentifier": f"{D}-1001-544",
                "Collected": False,
                "Results": [{"ObjectIdentifier": f"{D}-1101"}],
            },
            {"ObjectIdentifier": f"{D}-1001-544", "Results": [{"ObjectIdentifier": f"{D}-1102"}]},
        ],
    }
    graph, _ = load_collection(_write(tmp_path / "c", {"c.json": _env("computers", [comp])}))
    assert [(e.src, e.kind) for e in graph.edges()] == [(f"{D}-1102", "AdminTo")]


def test_zip_collection_and_skipped_types(tmp_path: Path) -> None:
    archive = tmp_path / "20261109_BloodHound.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, doc in model_collection(load_spec(SPEC)).items():
            zf.writestr(name, json.dumps(doc))
        zf.writestr("gpos.json", json.dumps(_env("gpos", [])))
        zf.writestr("readme.txt", "not json")
    _, summary = load_collection(archive)
    assert summary.files == 5
    assert summary.skipped_types == ("gpos",)
    assert summary.objects["users"] == 8


def test_zip_bomb_ratio_rejected(tmp_path: Path) -> None:
    archive = tmp_path / "bomb.zip"
    with zipfile.ZipFile(archive, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("users.json", " " * 2_000_000)
    with pytest.raises(CollectionError, match="compression ratio"):
        load_collection(archive)


def test_too_many_zip_entries(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bloodhound, "MAX_ZIP_ENTRIES", 2)
    archive = tmp_path / "many.zip"
    with zipfile.ZipFile(archive, "w") as zf:
        for i in range(3):
            zf.writestr(f"{i}.json", "{}")
    with pytest.raises(CollectionError, match="entries"):
        load_collection(archive)


def test_oversized_file_rejected(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(bloodhound, "MAX_FILE_BYTES", 10)
    _write(tmp_path / "c", {"users.json": _env("users", [])})
    with pytest.raises(CollectionError, match="size limit"):
        load_collection(tmp_path / "c")


MALFORMED = [
    ("{not json", "invalid JSON"),
    ("[]", "'data' and 'meta'"),
    ('{"meta": {"type": 1}, "data": []}', "meta.type"),
    ('{"meta": {"type": "users"}, "data": [{"Properties": {}}]}', "ObjectIdentifier"),
    ('{"meta": {"type": "users"}, "data": [{"ObjectIdentifier": "x", "Properties": 3}]}', "Prop"),
    (
        '{"meta": {"type": "groups"}, "data": [{"ObjectIdentifier": "x", "Members": [{}]}]}',
        "missing",
    ),
    ('{"meta": {"type": "users"}, "data": [{"ObjectIdentifier": "x", "Aces": {}}]}', "list of obj"),
    (
        '{"meta": {"type": "computers"}, "data": [{"ObjectIdentifier": "x", "Sessions": []}]}',
        "Sess",
    ),
    ('{"meta": {"type": "gpos"}, "data": []}', "no users, groups"),
]


@pytest.mark.parametrize(("content", "message"), MALFORMED)
def test_malformed_files_rejected(tmp_path: Path, content: str, message: str) -> None:
    (tmp_path / "f.json").write_text(content, encoding="utf-8")
    with pytest.raises(CollectionError, match=message):
        load_collection(tmp_path)


def test_bad_inputs(tmp_path: Path) -> None:
    with pytest.raises(CollectionError, match=r"no \.json"):
        load_collection(tmp_path)
    (tmp_path / "x.zip").write_bytes(b"not a zip")
    with pytest.raises(CollectionError, match="valid zip"):
        load_collection(tmp_path / "x.zip")
    with pytest.raises(CollectionError, match="expected a directory"):
        load_collection(tmp_path / "missing.json")


def test_utf8_bom_is_accepted(tmp_path: Path) -> None:
    raw = json.dumps(_env("users", [_user(1100, "U@D.TEST")])).encode("utf-8")
    (tmp_path / "users.json").write_bytes(b"\xef\xbb\xbf" + raw)
    graph, _ = load_collection(tmp_path)
    assert f"{D}-1100" in graph.nodes
