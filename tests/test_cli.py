"""Command line: exit codes and output for every sub-command, including failure paths."""

from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from identity_attack_lab.cli import compare, main
from identity_attack_lab.paths import Finding
from identity_attack_lab.spec import load_spec

from .conftest import ROOT, SPEC

MODEL = str(ROOT / "bloodhound" / "model")


def test_validate(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["validate", "--spec", str(SPEC)]) == 0
    assert "3 expected paths" in capsys.readouterr().out


def test_render_check_passes_on_repo_and_fails_on_empty_root(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["render", "--spec", str(SPEC), "--root", str(ROOT), "--check"]) == 0
    assert main(["render", "--spec", str(SPEC), "--root", str(tmp_path), "--check"]) == 1
    assert "0/9 generated files up to date" in capsys.readouterr().out
    assert main(["render", "--spec", str(SPEC), "--root", str(tmp_path)]) == 0
    assert main(["render", "--spec", str(SPEC), "--root", str(tmp_path), "--check"]) == 0


def test_isolation(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["isolation", "--root", str(ROOT)]) == 0
    assert "0 violations" in capsys.readouterr().out
    assert main(["isolation", "--root", str(tmp_path)]) == 1


def test_paths(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["paths", MODEL, "--owned", "alice"]) == 0
    out = capsys.readouterr().out
    assert "entry points: 3; with a path to Tier Zero: 3" in out
    assert "principals with any path to Tier Zero: 9 of 16" in out


def test_verify_model_matches(capsys: pytest.CaptureFixture[str]) -> None:
    assert main(["verify", MODEL, "--spec", str(SPEC)]) == 0
    assert "verify: 3/3 expected paths found, 0 unexpected paths" in capsys.readouterr().out


def test_verify_fails_when_the_lab_differs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    spec_text = SPEC.read_text(encoding="utf-8").replace(
        'principal = "alice"\nright = "GenericAll"', 'principal = "bob"\nright = "GenericAll"'
    )
    changed = tmp_path / "lab.toml"
    changed.write_text(spec_text, encoding="utf-8")
    assert main(["render", "--spec", str(changed), "--root", str(tmp_path)]) == 0
    collection = str(tmp_path / "bloodhound" / "model")
    assert main(["verify", collection, "--spec", str(SPEC)]) == 1
    out = capsys.readouterr().out
    assert "MISMATCH acl-dcsync: no path from alice" in out
    assert "unexpected path from BOB" in out
    assert "verify: 2/3 expected paths found, 1 unexpected paths" in out


def test_compare_reports_each_kind_of_difference() -> None:
    spec = load_spec(SPEC)
    findings = [
        Finding("alice", ("owned",), "alice -Owns-> svc_backup -DCSync-> corp.idlab.test", 2),
        Finding("CAROL", ("asrep-roastable",), None, None),
    ]
    problems = compare(spec, findings)
    assert problems[0].startswith("acl-dcsync: path differs")
    assert problems[1].startswith("asrep-password-reset: no path from carol")
    assert (
        problems[2] == "kerberoast-admin-session: svc_sql is not an entry point in the collection"
    )
    assert len(problems) == 3


def test_input_errors_exit_2(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    bad = tmp_path / "lab.toml"
    bad.write_text("[domain\n", encoding="utf-8")
    assert main(["validate", "--spec", str(bad)]) == 2
    assert main(["validate", "--spec", str(tmp_path / "missing.toml")]) == 2
    assert main(["paths", str(tmp_path)]) == 2
    copy = tmp_path / "model"
    shutil.copytree(MODEL, copy)
    assert main(["paths", str(copy), "--owned", "mallory"]) == 2
    assert "error:" in capsys.readouterr().err


def test_unknown_command_exits_2() -> None:
    with pytest.raises(SystemExit) as exc:
        main(["explode"])
    assert exc.value.code == 2
