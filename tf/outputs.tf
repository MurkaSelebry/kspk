output "vm_ip_address" {
  description = "IP адрес созданной VM"
  value       = var.vm_ip_address
}

output "ssh_connection_command" {
  description = "Команда для подключения по SSH"
  value       = "ssh -i ssh-keys/${var.vm_name}-private-key.pem root@${split("/", var.vm_ip_address)[0]}"
}

output "private_key_location" {
  description = "Путь к приватному SSH ключу"
  value       = local_file.private_key.filename
}

output "public_key_content" {
  description = "Содержимое публичного SSH ключа"
  value       = tls_private_key.vm_ssh_key.public_key_openssh
  sensitive   = true
}