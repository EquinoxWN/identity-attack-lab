.PHONY: setup lint types test render render-check isolation verify paths packer-validate ps-parse audit bench ci

PY ?= python

setup:
	$(PY) -m pip install --upgrade pip
	$(PY) -m pip install -e ".[dev]"

lint:
	$(PY) -m ruff check .
	$(PY) -m ruff format --check .

types:
	$(PY) -m mypy

test:
	$(PY) -m pytest -q

# Regenerate lab/Vagrantfile, lab/provision/*.ps1 and bloodhound/model/*.json from lab/lab.toml.
render:
	$(PY) -m identity_attack_lab render

# Fail if a committed generated file no longer matches lab/lab.toml.
render-check:
	$(PY) -m identity_attack_lab render --check

# Host-only networking, loopback-only port forwards, checksum-verified ISO, fake passwords only.
isolation:
	$(PY) -m identity_attack_lab isolation

# The designed attack paths must be exactly what the analysis finds (exit 1 otherwise).
verify:
	$(PY) -m identity_attack_lab verify

paths:
	$(PY) -m identity_attack_lab paths --owned alice --owned bob

# Needs packer on PATH; plugins and cache stay in .tmp/.
packer-validate:
	PACKER_PLUGIN_PATH=.tmp/packer-plugins PACKER_CONFIG_DIR=.tmp/packer-config CHECKPOINT_DISABLE=1 packer init packer/
	packer fmt -check packer/
	PACKER_PLUGIN_PATH=.tmp/packer-plugins PACKER_CONFIG_DIR=.tmp/packer-config CHECKPOINT_DISABLE=1 \
	  packer validate -var iso_url=file:///dev/null -var iso_checksum=sha256:0000000000000000000000000000000000000000000000000000000000000000 packer/

# Parses (never runs) every PowerShell script.
ps-parse:
	pwsh -NoProfile -File scripts/ps-parse.ps1

audit:
	$(PY) -m pip_audit --skip-editable --cache-dir .tmp/pip-audit

bench: render-check isolation verify paths

ci: setup lint types test render-check isolation verify
