"""Isolation checks: the shipped files pass, and each kind of exposure is caught."""

from __future__ import annotations

from pathlib import Path

import pytest

from identity_attack_lab.cli import isolation_violations
from identity_attack_lab.isolation import (
    check_answer_file,
    check_fake_secrets,
    check_packer,
    check_vagrantfile,
)

from .conftest import ROOT

VAGRANTFILE = (ROOT / "lab" / "Vagrantfile").read_text(encoding="utf-8")
PACKER = (ROOT / "packer" / "windows-server-2022.pkr.hcl").read_text(encoding="utf-8")
ANSWER = (ROOT / "packer" / "answer" / "Autounattend.xml").read_text(encoding="utf-8")


def test_shipped_files_pass() -> None:
    checked, problems = isolation_violations(ROOT)
    assert checked == 10
    assert problems == []


def test_missing_files_are_violations(tmp_path: Path) -> None:
    _, problems = isolation_violations(tmp_path)
    messages = [p.message for p in problems]
    assert "lab or Packer files are missing" in messages
    assert "file is missing" in messages


VAGRANT_EXPOSURES = {
    "public": (
        "    h.vm.network 'private_network', ip: '192.168.56.10'",
        "    h.vm.network 'public_network'",
        "bridged",
    ),
    "bridge": ("ip: '192.168.56.10'", "ip: '192.168.56.10', bridge: 'eth0'", "bridged"),
    "bad-ip": ("ip: '192.168.56.10'", "ip: '10.1.2.3'", "outside the host-only"),
    "no-ip": (
        "'private_network', ip: '192.168.56.10'",
        "'private_network', type: 'dhcp'",
        "static ip",
    ),
    "unbound-port": ("host: 55985, host_ip: '127.0.0.1'", "host: 55985", "host_ip"),
    "any-port": ("host: 55985, host_ip: '127.0.0.1'", "host: 55985, host_ip: '0.0.0.0'", "host_ip"),
    "rdp-default": (
        "id: 'rdp', guest: 3389, host: 53389",
        "id: 'rdpx', guest: 3389, host: 53389",
        "default port",
    ),
    "shared-folder": ("'/vagrant', disabled: true", "'/vagrant'", "synced folder"),
}


@pytest.mark.parametrize("case", sorted(VAGRANT_EXPOSURES))
def test_vagrantfile_exposures_are_caught(case: str) -> None:
    old, new, message = VAGRANT_EXPOSURES[case]
    assert old in VAGRANTFILE
    problems = check_vagrantfile(VAGRANTFILE.replace(old, new, 1))
    assert any(message in p.message for p in problems), problems


def test_comment_mentioning_public_network_is_fine() -> None:
    assert check_vagrantfile(VAGRANTFILE + "# never use public_network here\n") == []


def test_empty_vagrantfile_fails() -> None:
    messages = [p.message for p in check_vagrantfile("")]
    assert "no VM is defined" in messages


PACKER_EXPOSURES = {
    "gui": ("headless             = true", "headless             = false", "headless"),
    "vrdp-any": ('vrdp_bind_address    = "127.0.0.1"', 'vrdp_bind_address    = "0.0.0.0"', "vrdp"),
    "no-checksum": (
        "iso_checksum         = var.iso_checksum",
        'iso_checksum         = "none"',
        "none",
    ),
    "weak-validation": ("^sha256:[0-9a-f]{64}$", "^.*$", "validate sha256"),
    "http-server": (
        "  headless             = true",
        '  headless             = true\n  http_directory = "http"',
        "HTTP",
    ),
}


@pytest.mark.parametrize("case", sorted(PACKER_EXPOSURES))
def test_packer_exposures_are_caught(case: str) -> None:
    old, new, message = PACKER_EXPOSURES[case]
    assert old in PACKER
    problems = check_packer(PACKER.replace(old, new, 1))
    assert any(message in p.message for p in problems), problems


def test_answer_file_password_must_be_fake() -> None:
    assert check_answer_file(ANSWER, "a.xml") == []
    real = ANSWER.replace("EXAMPLE-NOT-A-SECRET-Vagrant1!", "Summer2026!", 1)
    assert len(check_answer_file(real, "a.xml")) == 1
    assert "invalid XML" in check_answer_file("<unattend", "a.xml")[0].message
    assert "no password" in check_answer_file("<unattend/>", "a.xml")[0].message


def test_fake_secret_literals() -> None:
    assert check_fake_secrets("config.winrm.password = 'EXAMPLE-NOT-A-SECRET-x1!'", "f") == []
    bad = check_fake_secrets("config.winrm.password = 'Winter2026!'", "f")
    assert [str(v) for v in bad] == ["f:1: password literal without EXAMPLE-NOT-A-SECRET"]
    assert check_fake_secrets("-Password $secure 'x'", "f") == []
