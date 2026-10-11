# CloudShield AWS Infrastructure & Deployment Guide

This guide details the AWS architecture and Terraform deployment for **CloudShield — Load-Balancing-Based DDoS Mitigation for Cloud Environments**.

---

## 1. Cloud Architecture Overview

CloudShield on AWS models a multi-tier defense across multiple Availability Zones:

```
                  [ Clients / Attacker / Flash Crowd ]
                                  │
                                  ▼
                [ AWS Route 53 (Low TTL = 30s) ]
                   │                         │
      (Primary Failover Route)     (Secondary Failover Route)
                   │                         │
                   ▼                         ▼
        [ Nginx Primary Proxy ]   [ Nginx Secondary Proxy ]
        (AZ-a, Public Subnet)     (AZ-b, Public Subnet)
        - Dynamic Blocklist       - Standby Failover Target
        - Tier 1 Rate Limiting    - Redundant Capacity
                   │                         │
                   └───────────┬─────────────┘
                               │ (Forward HTTP :8000)
                               ▼
            [ Backend EC2 Application Server Pool ]
              (Private Subnets, Multi-AZ)
              - Auto Scaling Group (min: 2, max: 8)
              - Tier 3 automated capacity scale-out
              - FastAPI + Shannon Entropy + Detection Engine
```

---

## 2. Infrastructure Components Provisioned by Terraform

1. **Virtual Private Cloud (VPC)**:
   - Dedicated CIDR: `10.0.0.0/16` with DNS hostnames and resolution enabled.
   - 2 Multi-AZ Public Subnets (`10.0.1.0/24`, `10.0.2.0/24`) for Nginx edge proxies.
   - 2 Multi-AZ Private Subnets (`10.0.11.0/24`, `10.0.12.0/24`) for backend application pool.
   - Internet Gateway + NAT Gateway for secure outbound backend connectivity.

2. **Least-Privilege Security Groups**:
   - `cloudshield-nginx-sg`: Inbound HTTP/HTTPS from `0.0.0.0/0`, restricted SSH for administration.
   - `cloudshield-backend-sg`: Inbound traffic strictly permitted from `cloudshield-nginx-sg` on port `8000`. Direct external access to backends is blocked.

3. **Active-Active Nginx Reverse Proxies**:
   - Primary Proxy in AZ-a and Secondary Proxy in AZ-b.
   - Automated bootstrap via `terraform/user_data/nginx.sh`.

4. **Elastic Backend Application Pool**:
   - EC2 Launch Template with systemd-managed FastAPI service (`terraform/user_data/backend.sh`).
   - Auto Scaling Group (`cloudshield-backend-asg`) automatically expanded by Tier 3 mitigation.

5. **Route 53 DNS Failover Routing**:
   - Health check targeting Primary Proxy `/nginx-health`.
   - Low TTL (30 seconds) on DNS records to minimize DNS caching latency during failover.
   - Primary record routes to Primary Proxy; Secondary record routes to Secondary Proxy upon Tier 4 trigger or proxy failure.

6. **IAM Security (Zero Hardcoded Secrets)**:
   - EC2 Instance Profile `cloudshield-instance-profile`.
   - IAM Policy allowing only `route53:ChangeResourceRecordSets` and `autoscaling:SetDesiredCapacity`.

---

## 3. How to Deploy to AWS

### Prerequisites
- [Terraform CLI](https://developer.hashicorp.com/terraform/downloads) (>= 1.5.0)
- AWS CLI configured with administrator permissions:
  ```bash
  aws configure
  ```

### Step 1: Initialize Terraform
```bash
cd terraform
terraform init
```

### Step 2: Configure Variables
Copy the template and adjust values:
```bash
cp terraform.tfvars.example terraform.tfvars
```
Set your desired domain name and administration IP in `terraform.tfvars`:
```hcl
aws_region  = "us-east-1"
domain_name = "cloudshield.yourdomain.com"
admin_cidr  = "YOUR_PUBLIC_IP/32"
```

### Step 3: Plan and Apply
```bash
terraform plan -out=tfplan
terraform apply tfplan
```

### Step 4: Verify Deployment Outputs
Terraform will output:
- `primary_proxy_public_ip`
- `secondary_proxy_public_ip`
- `route53_hosted_zone_id`
- `domain_name`

---

## 4. Manual Configuration & External Requirements

| Requirement | Description | Manual Action Required |
|-------------|-------------|-------------------------|
| **AWS Credentials** | Access key / Secret key or IAM role | Run `aws configure` or attach IAM role to workstation |
| **Domain Registrar** | NS Delegation for Route53 Zone | Point your domain's nameservers at your registrar to Route53 NS records |
| **AWS Account Quotas** | EC2 and Elastic IP limits | Ensure at least 4 EC2 instances and 1 EIP are available in your region |
