variable "storage_name" {
  type = string
}

variable "vm_ip_address" {
  description = "IP адрес для VM"
  type        = string
  default     = "192.168.206.100/24"
}

variable "vm_gateway" {
  description = "Gateway для VM"
  type        = string
  default     = "192.168.206.1"
}

variable "vm_name" {
  description = "Имя VM"
  type        = string
  default     = "Rocky9-Terraform"
}