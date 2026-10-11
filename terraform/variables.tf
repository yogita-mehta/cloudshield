variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

variable "environment" {
  description = "Deployment environment name"
  type        = string
  default     = "production"
}

variable "vpc_cidr" {
  description = "CIDR block for the CloudShield VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets (Nginx Proxies)"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets (Backend Server Pool)"
  type        = list(string)
  default     = ["10.0.11.0/24", "10.0.12.0/24"]
}

variable "domain_name" {
  description = "Domain name for Route53 DNS Failover (e.g., cloudshield.example.com)"
  type        = string
  default     = "cloudshield.internal"
}

variable "instance_type_nginx" {
  description = "EC2 instance type for active-active Nginx reverse proxies"
  type        = string
  default     = "t3.small"
}

variable "instance_type_backend" {
  description = "EC2 instance type for backend application pool"
  type        = string
  default     = "t3.medium"
}

variable "asg_min_size" {
  description = "Minimum backend pool instances"
  type        = number
  default     = 2
}

variable "asg_max_size" {
  description = "Maximum backend pool instances (Tier 3 scale-out capacity)"
  type        = number
  default     = 8
}

variable "asg_desired_capacity" {
  description = "Baseline desired backend pool instances"
  type        = number
  default     = 2
}

variable "admin_cidr" {
  description = "CIDR block permitted for SSH access"
  type        = string
  default     = "0.0.0.0/0"
}
