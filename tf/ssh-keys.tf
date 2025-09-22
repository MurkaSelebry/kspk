# Генерация SSH ключей
resource "tls_private_key" "vm_ssh_key" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

# Сохранение приватного ключа в файл
resource "local_file" "private_key" {
  content         = tls_private_key.vm_ssh_key.private_key_pem
  filename        = "${path.module}/ssh-keys/${var.vm_name}-private-key.pem"
  file_permission = "0600"
}

# Сохранение публичного ключа в файл
resource "local_file" "public_key" {
  content  = tls_private_key.vm_ssh_key.public_key_openssh
  filename = "${path.module}/ssh-keys/${var.vm_name}-public-key.pub"
}