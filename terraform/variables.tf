variable "aws_region" {
  description = "Région AWS cible"
  type        = string
  default     = "eu-north-1"
}

variable "instance_type" {
  description = "Type d'instance EC2 (rester dans les limites du Free Tier)"
  type        = string
  default     = "t3.micro"
}

variable "key_name" {
  description = "Nom de la paire de clés EC2 existante utilisée pour le SSH"
  type        = string
  default     = "mini-siem-key"
}

variable "app_name" {
  description = "Nom utilisé pour tagger les ressources"
  type        = string
  default     = "mini-siem"
}

variable "subnet_id" {
  description = <<-EOT
    Subnet du VPC par défaut où placer l'instance. Fixé au subnet déjà utilisé
    par l'instance existante (au lieu de piocher automatiquement le premier
    subnet retourné par la data source, dont l'ordre n'est pas garanti) pour
    éviter un remplacement d'instance au premier `terraform import` : changer
    le subnet d'une aws_instance force aussi sa recréation.
  EOT
  type        = string
  default     = "subnet-05c1aaa5d5e0992bf" # eu-north-1b
}

variable "ami_id" {
  description = <<-EOT
    AMI Ubuntu utilisée. Fixée à l'AMI exacte déjà déployée sur l'instance
    existante (plutôt qu'une data source "most_recent") pour que le premier
    `terraform import` ne déclenche pas un remplacement d'instance : changer
    l'AMI d'une aws_instance force sa recréation.
  EOT
  type        = string
  default     = "ami-0aba19e56f3eaec05" # ubuntu-resolute-26.04-amd64-server
}
