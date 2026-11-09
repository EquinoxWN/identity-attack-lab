"""Static isolation checks: the lab must not be reachable from outside the host machine.

These run on the rendered Vagrantfile and the hand-written Packer template, so a hand edit that
adds a bridged adapter, an unbound port forward or an unverified ISO fails `make check-isolation`
and CI before any VM is started.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from xml.etree import ElementTree

from .spec import FAKE_MARKER, HOST_ONLY_RANGE

REQUIRED_PORT_IDS = ("winrm", "winrm-ssl", "rdp")
_DEFINE = re.compile(r"^\s*config\.vm\.define\s+'([^']+)'")
_PRIVATE_IP = re.compile(r"'private_network'.*\bip:\s*'([^']+)'")
_PORT_ID = re.compile(r"'forwarded_port'.*\bid:\s*'([^']+)'")
_PASSWORDISH = re.compile(r"(password|Password)\b[^\n]*?['\">]([^'\"<\n]{6,})['\"<]")


@dataclass(frozen=True)
class Violation:
    """One isolation problem, with file and 1-based line (0 = whole file)."""

    file: str
    line: int
    message: str

    def __str__(self) -> str:
        """`file:line: message`."""
        return f"{self.file}:{self.line}: {self.message}"


def check_vagrantfile(text: str, name: str = "Vagrantfile") -> list[Violation]:
    """Host-only networking, loopback-only port forwards, no shared folders."""
    out: list[Violation] = []
    ports: dict[str, set[str]] = {}
    current: str | None = None
    lines = text.splitlines()
    for no, raw in enumerate(lines, 1):
        line = raw.split("#", 1)[0]
        if not line.strip():
            continue
        if m := _DEFINE.match(line):
            current = m.group(1)
            ports[current] = set()
        if "public_network" in line or "bridge:" in line:
            out.append(Violation(name, no, "bridged/public network adapter is not allowed"))
        if "private_network" in line:
            ip_m = _PRIVATE_IP.search(line)
            if not ip_m:
                out.append(Violation(name, no, "private_network needs a static ip"))
            else:
                try:
                    ok = ipaddress.ip_address(ip_m.group(1)) in HOST_ONLY_RANGE
                except ValueError:
                    ok = False
                if not ok:
                    msg = f"ip {ip_m.group(1)} is outside the host-only range {HOST_ONLY_RANGE}"
                    out.append(Violation(name, no, msg))
        if "forwarded_port" in line:
            if "host_ip: '127.0.0.1'" not in line:
                out.append(Violation(name, no, "forwarded_port must set host_ip: '127.0.0.1'"))
            id_m = _PORT_ID.search(line)
            if current is not None and id_m:
                ports[current].add(id_m.group(1))
        if "synced_folder" in line and "disabled: true" not in line:
            out.append(Violation(name, no, "synced folders must be disabled"))
    if not ports:
        out.append(Violation(name, 0, "no VM is defined"))
    for vm, ids in sorted(ports.items()):
        missing = [p for p in REQUIRED_PORT_IDS if p not in ids]
        if missing:
            out.append(Violation(name, 0, f"VM {vm!r} does not override default port(s) {missing}"))
    if not any("synced_folder" in ln and "disabled: true" in ln for ln in lines):
        out.append(Violation(name, 0, "the default /vagrant synced folder is not disabled"))
    return out


def check_packer(text: str, name: str = "packer template") -> list[Violation]:
    """Headless build, loopback-only VRDP, no HTTP server, checksum-verified ISO."""
    out: list[Violation] = []
    body = "\n".join(line.split("#", 1)[0] for line in text.splitlines())
    required = {
        r"^\s*headless\s*=\s*true\s*$": "headless = true is required",
        r'^\s*vrdp_bind_address\s*=\s*"127\.0\.0\.1"\s*$': 'vrdp_bind_address = "127.0.0.1" is required',
        r"^\s*iso_checksum\s*=\s*var\.iso_checksum\s*$": "iso_checksum must come from the validated variable",
        r"\^sha256:\[0-9a-f\]\{64\}\$": "the iso_checksum variable must validate sha256:<64 hex>",
    }
    for pattern, message in required.items():
        if not re.search(pattern, body, re.M):
            out.append(Violation(name, 0, message))
    for no, line in enumerate(body.splitlines(), 1):
        if re.search(r"^\s*http_(directory|content)\s*=", line):
            out.append(Violation(name, no, "the Packer HTTP server is not used; use floppy_files"))
        if re.search(r'iso_checksum\s*=\s*"none"', line):
            out.append(Violation(name, no, "iso_checksum = none skips verification"))
        if "public_network" in line or "bridgedadapter" in line.lower().replace(" ", ""):
            out.append(Violation(name, no, "bridged networking is not allowed"))
    return out


def check_answer_file(text: str, name: str) -> list[Violation]:
    """Every <...Password><Value> in a Windows answer file must carry the fake marker."""
    try:
        # Repository file written by us, not untrusted input; expat refuses entity expansion bombs.
        root = ElementTree.fromstring(text)  # noqa: S314
    except ElementTree.ParseError as exc:
        return [Violation(name, 0, f"invalid XML: {exc}")]
    out = []
    count = 0
    for elem in root.iter():
        if elem.tag.endswith("Password"):
            count += 1
            values = [v.text or "" for v in elem if v.tag.endswith("Value")]
            if not values or any(FAKE_MARKER not in v for v in values):
                out.append(Violation(name, 0, f"{elem.tag.split('}')[-1]} without {FAKE_MARKER}"))
    if count == 0:
        out.append(Violation(name, 0, "no password elements found (wrong file?)"))
    return out


def check_fake_secrets(text: str, name: str) -> list[Violation]:
    """Every password-looking literal must carry the visibly-fake marker."""
    out = []
    for no, line in enumerate(text.splitlines(), 1):
        for m in _PASSWORDISH.finditer(line):
            value = m.group(2)
            if "$" in value or value.startswith(("var.", "ConvertTo-SecureString")):
                continue
            if FAKE_MARKER not in value:
                out.append(Violation(name, no, f"password literal without {FAKE_MARKER}"))
    return out
