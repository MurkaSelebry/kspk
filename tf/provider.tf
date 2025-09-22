terraform {
  required_providers {
    proxmox = {
      source = "bpg/proxmox"
    }
    tls = {
      source = "hashicorp/tls"
    }
    local = {
      source = "hashicorp/local"
    }
  }
}

provider "proxmox" {
  endpoint = "https://192.168.206.134:8006/"
  username = "root@pam"
  password = "12345678"
  insecure = true
  ssh {
    agent = true
  }
}