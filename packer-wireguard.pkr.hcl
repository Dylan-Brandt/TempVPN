packer {
  required_plugins {
    amazon-ebs = {
      version = ">= 1.8.0"
      source = "github.com/hashicorp/amazon"
    }
  }
}

variable "aws_region" {
  type    = string
  default = "us-east-2"
}

variable "ami_name" {
  type    = string
  default = "wireguard-prebaked-{{timestamp}}"
}

source "amazon-ebs" "ubuntu" {
  region               = var.aws_region
  instance_type        = "t3.micro"
  ssh_username         = "ubuntu"
  ami_name             = var.ami_name
  ami_description      = "Pre-baked WireGuard VPN AMI with dependencies installed"

  source_ami_filter {
    filters = {
      name                = "ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"
      root-device-type    = "ebs"
      virtualization-type = "hvm"
    }
    owners      = ["099720109477"]
    most_recent = true
  }
}

build {
  sources = ["source.amazon-ebs.ubuntu"]

  provisioner "shell" {
    inline = [
      "sudo apt update",
      "sudo apt-get update -yq",
      "sudo apt-get upgrade -yq",
      "sudo apt-get install -yq wireguard iptables jq awscli"
    ]
  }

  provisioner "shell" {
    inline = [
      "sudo apt-get autoremove -yq",
      "sudo apt-get clean -yq"
    ]
  }
}
