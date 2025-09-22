resource "proxmox_virtual_environment_vm" "rocky9" {
  name        = var.vm_name
  vm_id       = 4000
  description = "VM создана с Terraform, статический IP и SSH ключи"

  node_name = "selebry"

  clone {
    vm_id     = 2000
    node_name = "selebry"
  }

  agent {
    enabled = true
  }

  cpu {
    cores   = 2
    sockets = 2
    type    = "host"
  }

  memory {
    dedicated = 2048
  }

  scsi_hardware = "virtio-scsi-single"

  disk {
    datastore_id = var.storage_name
    interface    = "virtio0"
    iothread     = true
    discard      = "on"
    size         = 10
  }

  boot_order = ["virtio0"]

  network_device {
    bridge = "vmbr0"
    model  = "virtio"
  }

  # Настройка cloud-init с статическим IP и SSH ключами
  initialization {
    ip_config {
      ipv4 {
        address = var.vm_ip_address
        gateway = var.vm_gateway
      }
    }

    dns {
      servers = ["8.8.8.8", "8.8.4.4"]
    }

    user_account {
      username = "selebry"
      password = "12345678"
      keys     = [trimspace(tls_private_key.vm_ssh_key.public_key_openssh)]
    }
  }

  # Зависимость от создания SSH ключей
  depends_on = [
    tls_private_key.vm_ssh_key
  ]
}