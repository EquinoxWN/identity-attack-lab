# Builds the lab's Windows Server 2022 Vagrant box (idlab/windows-server-2022) with VirtualBox.
# Lab only: headless, VRDP bound to 127.0.0.1, no HTTP server, ISO checksum required. The box is
# generalized with sysprep so the domain controller and the members get different machine SIDs.
#
#   packer init packer/
#   packer build -var iso_url=file:///path/to/ws2022-eval.iso -var iso_checksum=sha256:<hash> packer/
#   vagrant box add idlab/windows-server-2022 .tmp/boxes/idlab-ws2022-virtualbox.box

packer {
  required_version = ">= 1.11.0"
  required_plugins {
    virtualbox = {
      source  = "github.com/hashicorp/virtualbox"
      version = "= 1.1.5"
    }
    vagrant = {
      source  = "github.com/hashicorp/vagrant"
      version = "= 1.1.6"
    }
  }
}

variable "iso_url" {
  type        = string
  description = "Windows Server 2022 evaluation ISO from the Microsoft Evaluation Center (https:// or file:)."
  validation {
    condition     = can(regex("^(https://|file:)", var.iso_url))
    error_message = "The iso_url must start with https:// or file:."
  }
}

variable "iso_checksum" {
  type        = string
  description = "SHA-256 of the ISO as sha256:<64 hex digits>; skipping verification is not allowed."
  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.iso_checksum))
    error_message = "The iso_checksum must be sha256:<64 lowercase hex digits>."
  }
}

# Same value as BOX_PASSWORD in src/identity_attack_lab/render.py and the answer files.
variable "winrm_password" {
  type      = string
  default   = "EXAMPLE-NOT-A-SECRET-Vagrant1!"
  sensitive = true
}

variable "cpus" {
  type    = number
  default = 2
}

variable "memory_mb" {
  type    = number
  default = 4096
}

source "virtualbox-iso" "ws2022" {
  guest_os_type        = "Windows2022_64"
  iso_url              = var.iso_url
  iso_checksum         = var.iso_checksum
  iso_interface        = "sata"
  hard_drive_interface = "sata"
  disk_size            = 61440
  cpus                 = var.cpus
  memory               = var.memory_mb
  gfx_controller       = "vboxsvga"
  gfx_vram_size        = 128
  headless             = true
  vrdp_bind_address    = "127.0.0.1"
  guest_additions_mode = "disable"
  floppy_files = [
    "${path.root}/answer/Autounattend.xml",
    "${path.root}/scripts/enable-winrm.ps1",
  ]
  vboxmanage = [
    ["modifyvm", "{{.Name}}", "--clipboard-mode", "disabled", "--drag-and-drop", "disabled"],
  ]
  communicator     = "winrm"
  winrm_username   = "vagrant"
  winrm_password   = var.winrm_password
  winrm_timeout    = "2h"
  shutdown_command = "C:\\Windows\\System32\\Sysprep\\sysprep.exe /generalize /oobe /quiet /shutdown /unattend:C:\\Windows\\Panther\\Unattend\\unattend.xml"
  shutdown_timeout = "30m"
}

build {
  sources = ["source.virtualbox-iso.ws2022"]

  provisioner "powershell" {
    inline = ["New-Item -ItemType Directory -Force -Path C:\\Windows\\Panther\\Unattend | Out-Null"]
  }

  provisioner "file" {
    source      = "${path.root}/answer/sysprep-unattend.xml"
    destination = "C:\\Windows\\Panther\\Unattend\\unattend.xml"
  }

  post-processor "vagrant" {
    output              = "${path.root}/../.tmp/boxes/idlab-ws2022-{{.Provider}}.box"
    keep_input_artifact = false
  }
}
