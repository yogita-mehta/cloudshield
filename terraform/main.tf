data "aws_availability_zones" "available" {
  state = "available"
}

data "aws_ami" "ubuntu" {
  most_recent = true
  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-jammy-22.04-amd64-server-*"]
  }
  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }
  owners = ["099720109477"] # Canonical
}

# ==============================================================================
# 1. NETWORKING (VPC, SUBNETS, GATEWAYS, ROUTING)
# ==============================================================================

resource "aws_vpc" "main" {
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true

  tags = {
    Name = "cloudshield-vpc"
  }
}

resource "aws_internet_gateway" "igw" {
  vpc_id = aws_vpc.main.id

  tags = {
    Name = "cloudshield-igw"
  }
}

# Public Subnets (Nginx Proxies)
resource "aws_subnet" "public" {
  count                   = 2
  vpc_id                  = aws_vpc.main.id
  cidr_block              = var.public_subnet_cidrs[count.index]
  availability_zone       = data.aws_availability_zones.available.names[count.index]
  map_public_ip_on_launch = true

  tags = {
    Name = "cloudshield-public-subnet-${count.index + 1}"
    Tier = "Public"
  }
}

# Private Subnets (Backend Application Server Pool)
resource "aws_subnet" "private" {
  count             = 2
  vpc_id            = aws_vpc.main.id
  cidr_block        = var.private_subnet_cidrs[count.index]
  availability_zone = data.aws_availability_zones.available.names[count.index]

  tags = {
    Name = "cloudshield-private-subnet-${count.index + 1}"
    Tier = "Private"
  }
}

# Elastic IP for NAT Gateway
resource "aws_eip" "nat" {
  domain = "vpc"

  tags = {
    Name = "cloudshield-nat-eip"
  }
}

# NAT Gateway for Backend Private Subnets outbound internet access
resource "aws_nat_gateway" "nat" {
  allocation_id = aws_eip.nat.id
  subnet_id     = aws_subnet.public[0].id

  tags = {
    Name = "cloudshield-nat-gw"
  }
  depends_on = [aws_internet_gateway.igw]
}

# Public Route Table
resource "aws_route_table" "public" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block = "0.0.0.0/0"
    gateway_id = aws_internet_gateway.igw.id
  }

  tags = {
    Name = "cloudshield-public-rt"
  }
}

resource "aws_route_table_association" "public" {
  count          = 2
  subnet_id      = aws_subnet.public[count.index].id
  route_table_id = aws_route_table.public.id
}

# Private Route Table
resource "aws_route_table" "private" {
  vpc_id = aws_vpc.main.id

  route {
    cidr_block     = "0.0.0.0/0"
    nat_gateway_id = aws_nat_gateway.nat.id
  }

  tags = {
    Name = "cloudshield-private-rt"
  }
}

resource "aws_route_table_association" "private" {
  count          = 2
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private.id
}

# ==============================================================================
# 2. SECURITY GROUPS (LEAST PRIVILEGE)
# ==============================================================================

# Public Proxy Security Group
resource "aws_security_group" "nginx_sg" {
  name        = "cloudshield-nginx-sg"
  description = "Allows public inbound HTTP/HTTPS traffic to Nginx reverse proxies"
  vpc_id      = aws_vpc.main.id

  ingress {
    description = "Inbound HTTP"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Inbound HTTPS"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "Admin SSH access"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.admin_cidr]
  }

  egress {
    description = "Allow all outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "cloudshield-nginx-sg"
  }
}

# Private Backend Server Pool Security Group (Strict Isolation)
resource "aws_security_group" "backend_sg" {
  name        = "cloudshield-backend-sg"
  description = "Restricts inbound traffic strictly to Nginx proxy instances"
  vpc_id      = aws_vpc.main.id

  ingress {
    description     = "Inbound FastAPI application traffic from Nginx proxies only"
    from_port       = 8000
    to_port         = 8000
    protocol        = "tcp"
    security_groups = [aws_security_group.nginx_sg.id]
  }

  ingress {
    description = "Admin SSH via bastion/private subnet"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    description = "Allow all outbound traffic (for updates and Prometheus metrics)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "cloudshield-backend-sg"
  }
}

# ==============================================================================
# 3. IAM ROLES & INSTANCE PROFILES (NO HARDCODED SECRETS)
# ==============================================================================

resource "aws_iam_role" "cloudshield_role" {
  name = "cloudshield-instance-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Action = "sts:AssumeRole"
        Effect = "Allow"
        Principal = {
          Service = "ec2.amazonaws.com"
        }
      }
    ]
  })
}

resource "aws_iam_policy" "cloudshield_policy" {
  name        = "cloudshield-mitigation-policy"
  description = "Least privilege policy allowing Route53 DNS record updates and Auto-Scaling capacity modification"

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "route53:GetChange",
          "route53:ChangeResourceRecordSets",
          "route53:ListResourceRecordSets",
          "route53:GetHealthCheck",
          "route53:GetHealthCheckStatus"
        ]
        Resource = "*"
      },
      {
        Effect = "Allow"
        Action = [
          "autoscaling:SetDesiredCapacity",
          "autoscaling:DescribeAutoScalingGroups",
          "autoscaling:DescribeAutoScalingInstances"
        ]
        Resource = "*"
      }
    ]
  })
}

resource "aws_iam_role_policy_attachment" "cloudshield_attach" {
  role       = aws_iam_role.cloudshield_role.name
  policy_arn = aws_iam_policy.cloudshield_policy.arn
}

resource "aws_iam_instance_profile" "cloudshield_profile" {
  name = "cloudshield-instance-profile"
  role = aws_iam_role.cloudshield_role.name
}

# ==============================================================================
# 4. MULTI-PROXY ACTIVE-ACTIVE NGINX INSTANCES (AZ-A & AZ-B)
# ==============================================================================

resource "aws_instance" "nginx_primary" {
  ami                  = data.aws_ami.ubuntu.id
  instance_type        = var.instance_type_nginx
  subnet_id            = aws_subnet.public[0].id
  vpc_security_group_ids = [aws_security_group.nginx_sg.id]
  iam_instance_profile = aws_iam_instance_profile.cloudshield_profile.name

  user_data = file("${path.module}/user_data/nginx.sh")

  tags = {
    Name = "cloudshield-nginx-primary"
    Role = "PrimaryProxy"
  }
}

resource "aws_instance" "nginx_secondary" {
  ami                  = data.aws_ami.ubuntu.id
  instance_type        = var.instance_type_nginx
  subnet_id            = aws_subnet.public[1].id
  vpc_security_group_ids = [aws_security_group.nginx_sg.id]
  iam_instance_profile = aws_iam_instance_profile.cloudshield_profile.name

  user_data = file("${path.module}/user_data/nginx.sh")

  tags = {
    Name = "cloudshield-nginx-secondary"
    Role = "SecondaryProxy"
  }
}

# ==============================================================================
# 5. APPLICATION SERVER POOL (LAUNCH TEMPLATE & AUTO SCALING GROUP)
# ==============================================================================

resource "aws_launch_template" "backend_template" {
  name_prefix   = "cloudshield-backend-"
  image_id      = data.aws_ami.ubuntu.id
  instance_type = var.instance_type_backend

  vpc_security_group_ids = [aws_security_group.backend_sg.id]
  iam_instance_profile {
    name = aws_iam_instance_profile.cloudshield_profile.name
  }

  user_data = base64encode(file("${path.module}/user_data/backend.sh"))

  tag_specifications {
    resource_type = "instance"
    tags = {
      Name = "cloudshield-backend-node"
      Role = "ApplicationPool"
    }
  }
}

resource "aws_autoscaling_group" "backend_asg" {
  name                = "cloudshield-backend-asg"
  vpc_zone_identifier = aws_subnet.private[*].id
  min_size            = var.asg_min_size
  max_size            = var.asg_max_size
  desired_capacity    = var.asg_desired_capacity

  launch_template {
    id      = aws_launch_template.backend_template.id
    version = "$Latest"
  }

  health_check_type         = "EC2"
  health_check_grace_period = 180

  tag {
    key                 = "Name"
    value               = "cloudshield-backend-asg"
    propagate_at_launch = true
  }
}

# ==============================================================================
# 6. ROUTE 53 HEALTH CHECK & FAILOVER ROUTING POLICY (LOW TTL: 30s)
# ==============================================================================

resource "aws_route53_zone" "primary_zone" {
  name = var.domain_name

  tags = {
    Name = "cloudshield-hosted-zone"
  }
}

# Health Check targeting Primary Proxy /nginx-health endpoint
resource "aws_route53_health_check" "primary_proxy_check" {
  ip_address        = aws_instance.nginx_primary.public_ip
  port              = 80
  type              = "HTTP"
  resource_path     = "/nginx-health"
  failure_threshold = 2
  request_interval  = 30

  tags = {
    Name = "cloudshield-primary-health-check"
  }
}

# Route53 PRIMARY Failover Record (Active)
resource "aws_route53_record" "primary" {
  zone_id = aws_route53_zone.primary_zone.zone_id
  name    = var.domain_name
  type    = "A"
  ttl     = 30

  failover_routing_policy {
    type = "PRIMARY"
  }

  set_identifier = "Primary-Proxy"
  records        = [aws_instance.nginx_primary.public_ip]
  health_check_id = aws_route53_health_check.primary_proxy_check.id
}

# Route53 SECONDARY Failover Record (Passive Standby / Failover Target)
resource "aws_route53_record" "secondary" {
  zone_id = aws_route53_zone.primary_zone.zone_id
  name    = var.domain_name
  type    = "A"
  ttl     = 30

  failover_routing_policy {
    type = "SECONDARY"
  }

  set_identifier = "Secondary-Proxy"
  records        = [aws_instance.nginx_secondary.public_ip]
}
