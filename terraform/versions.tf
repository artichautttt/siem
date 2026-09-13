terraform {
  required_version = ">= 1.5"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }

  # State distant : bucket S3 créé hors Terraform (problème de l'œuf et de la
  # poule classique pour un backend), versioning + chiffrement + accès public
  # bloqué activés (voir README, section Terraform). Reste dans les limites du
  # Free Tier S3 pour un fichier d'état de quelques Ko.
  backend "s3" {
    bucket = "mini-siem-tfstate-579661925343"
    key    = "mini-siem/terraform.tfstate"
    region = "eu-north-1"
  }
}

provider "aws" {
  region = var.aws_region
}
