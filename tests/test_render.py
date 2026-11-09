"""Rendering: committed files match the spec, writes are atomic and idempotent."""

from __future__ import annotations

import dataclasses
import os
import re
from pathlib import Path
from typing import Any

import pytest

from identity_attack_lab.render import (
    BOX_PASSWORD,
    atomic_write,
    drift,
    render_all,
    render_vagrantfile,
    write_all,
)
from identity_attack_lab.spec import load_spec, parse_spec

from .conftest import ROOT, SPEC


def test_committed_files_match_the_spec() -> None:
    files = render_all(load_spec(SPEC))
    assert len(files) == 9
    assert drift(ROOT, files) == []


def test_rendering_is_deterministic() -> None:
    assert render_all(load_spec(SPEC)) == render_all(load_spec(SPEC))


def test_write_all_is_idempotent_and_drift_detects_edits(tmp_path: Path) -> None:
    files = render_all(load_spec(SPEC))
    assert len(write_all(tmp_path, files)) == 9
    assert write_all(tmp_path, files) == []
    assert drift(tmp_path, files) == []
    vf = tmp_path / "lab" / "Vagrantfile"
    vf.write_text(vf.read_text(encoding="utf-8") + "# edit\n", encoding="utf-8")
    (tmp_path / "bloodhound" / "model" / "users.json").unlink()
    assert drift(tmp_path, files) == ["bloodhound/model/users.json", "lab/Vagrantfile"]


def test_crlf_checkout_is_not_drift(tmp_path: Path) -> None:
    files = {"a.txt": "one\ntwo\n"}
    (tmp_path / "a.txt").write_bytes(b"one\r\ntwo\r\n")
    assert drift(tmp_path, files) == []
    assert atomic_write(tmp_path / "a.txt", "one\ntwo\n") is False


def test_atomic_write_leaves_no_temp_file_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = tmp_path / "out.txt"
    target.write_text("old\n", encoding="utf-8")

    def boom(src: str, dst: Path) -> None:
        raise OSError("disk full")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(OSError, match="disk full"):
        atomic_write(target, "new\n")
    assert target.read_text(encoding="utf-8") == "old\n"
    assert [p.name for p in tmp_path.iterdir()] == ["out.txt"]


def test_vagrantfile_brings_the_dc_up_first(doc: dict[str, Any]) -> None:
    doc["hosts"].reverse()
    text = render_vagrantfile(parse_spec(doc))
    assert text.index("define 'dc01'") < text.index("define 'ws01'")


def test_forwarded_ports_are_unique_per_vm() -> None:
    text = render_vagrantfile(load_spec(SPEC))
    hosts = re.findall(r"host: (\d+), host_ip", text)
    assert len(hosts) == 6
    assert len(set(hosts)) == 6


def test_seed_script_contains_each_misconfiguration() -> None:
    text = render_all(load_spec(SPEC))["lab/provision/seed-domain.ps1"]
    assert "Add-LabSpn 'svc_sql' 'MSSQLSvc/ws01.corp.idlab.test:1433'" in text
    assert "Set-ADAccountControl -Identity 'carol' -DoesNotRequirePreAuth $true" in text
    assert "'IDLAB\\Helpdesk:CA;Reset Password'" in text
    assert "'IDLAB\\alice:GA'" in text
    assert "'IDLAB\\svc_backup:CA;Replicating Directory Changes All'" in text
    assert "Add-LabMember 'Domain Admins' 'da_admin'" in text


def test_owns_right_sets_the_owner(doc: dict[str, Any]) -> None:
    doc["acls"][1]["right"] = "Owns"
    text = render_all(parse_spec(doc))["lab/provision/seed-domain.ps1"]
    assert "Set-LabOwner (Get-Dn 'User' 'svc_backup') 'IDLAB\\alice'" in text


def test_member_scripts_grant_admin_and_session() -> None:
    files = render_all(load_spec(SPEC))
    seed = files["lab/provision/member-ws01.ps1"]
    assert "Add-LocalGroupMember -Group Administrators -Member 'IDLAB\\IT Admins'" in seed
    assert "-User 'IDLAB\\da_admin' -Password 'EXAMPLE-NOT-A-SECRET-DomainAdmin1!'" in seed
    join = files["lab/provision/member-join-ws01.ps1"]
    assert "-ServerAddresses '192.168.56.10'" in join


def test_box_password_matches_packer_and_answer_files() -> None:
    hcl = (ROOT / "packer" / "windows-server-2022.pkr.hcl").read_text(encoding="utf-8")
    assert f'default   = "{BOX_PASSWORD}"' in hcl
    for xml in (ROOT / "packer" / "answer").glob("*.xml"):
        assert BOX_PASSWORD in xml.read_text(encoding="utf-8")


def test_renderer_refuses_non_ascii_even_if_validation_is_bypassed() -> None:
    spec = load_spec(SPEC)
    evil = dataclasses.replace(spec.users[0], description="x\u2019y")
    bad = dataclasses.replace(spec, users=(evil, *spec.users[1:]))
    with pytest.raises(ValueError, match=r"U\+2019 is not printable ASCII"):
        render_all(bad)
