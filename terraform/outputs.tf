output "vpc_id" {
  description = "CloudShield VPC ID"
  value       = aws_vpc.main.id
}

output "primary_proxy_public_ip" {
  description = "Public IP of Primary Nginx Reverse Proxy"
  value       = aws_instance.nginx_primary.public_ip
}

output "secondary_proxy_public_ip" {
  description = "Public IP of Secondary (Failover) Nginx Reverse Proxy"
  value       = aws_instance.nginx_secondary.public_ip
}

output "route53_hosted_zone_id" {
  description = "Route53 Hosted Zone ID"
  value       = aws_route53_zone.primary_zone.zone_id
}

output "domain_name" {
  description = "Configured Domain Name with Failover Routing"
  value       = var.domain_name
}

output "backend_asg_name" {
  description = "Name of the Backend Auto Scaling Group"
  value       = aws_autoscaling_group.backend_asg.name
}

output "dns_failover_ttl" {
  description = "TTL configured for Route53 failover records (seconds)"
  value       = 30
}
