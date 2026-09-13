# Utilise le VPC et le subnet par défaut du compte (pas de VPC dédié créé :
# plus simple, toujours dans les limites du Free Tier, cohérent avec l'infra
# actuellement provisionnée manuellement).
data "aws_vpc" "default" {
  default = true
}

resource "aws_security_group" "mini_siem" {
  # Le nom (et la description) d'un security group sont immuables côté AWS :
  # les changer forcerait sa destruction/recréation (et une coupure de
  # connectivité pour l'instance). On garde donc le nom déjà existant plutôt
  # que de le renommer "proprement" — seules les règles ingress sont gérées
  # ci-dessous (mise à jour en place, sans remplacement).
  name        = "launch-wizard-1"
  description = "launch-wizard-1 created 2026-09-13T09:30:41.527Z"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "SSH"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Backend API Flask"
    from_port   = 5000
    to_port     = 5000
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Frontend Angular/Nginx"
    from_port   = 4200
    to_port     = 4200
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${var.app_name}-sg"
  }
}

resource "aws_instance" "mini_siem" {
  ami                    = var.ami_id
  instance_type          = var.instance_type
  key_name               = var.key_name
  subnet_id              = var.subnet_id
  vpc_security_group_ids = [aws_security_group.mini_siem.id]

  root_block_device {
    # Agrandi de 8 à 20 Go le 2026-09-13 : le build de l'image backend
    # (scikit-learn + numpy + scipy, ajoutés pour la détection ML) faisait
    # échouer "docker compose build" par manque d'espace disque sur
    # l'instance. Reste dans les limites du Free Tier (30 Go d'EBS inclus).
    volume_size = 20
    volume_type = "gp3"
  }

  tags = {
    Name = var.app_name
  }
}
