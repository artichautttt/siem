output "instance_id" {
  value = aws_instance.mini_siem.id
}

output "public_ip" {
  value = aws_instance.mini_siem.public_ip
}

output "security_group_id" {
  value = aws_security_group.mini_siem.id
}
