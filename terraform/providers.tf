terraform {
  required_version = ">= 1.5.0"
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.30"
    }
  }
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "CloudShield"
      Environment = var.environment
      ManagedBy   = "Terraform"
      Repository  = "https://github.com/cloudshield/cloudshield"
    }
  }
}
