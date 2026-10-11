"""
backend/app/core/aws_client.py
AWS Cloud Integration for CloudShield:
- Route53 Automated DNS Failover (Tier 4 Mitigation)
- Route53 Health Check Status Inspection
- EC2 / Auto Scaling Pool Expansion (Tier 3 Mitigation)
- Safe fallback to local simulation mode when AWS credentials are not configured
"""

import os
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger("cloudshield.aws")

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
    BOTO3_AVAILABLE = True
except ImportError:
    BOTO3_AVAILABLE = False
    ClientError = Exception
    NoCredentialsError = Exception

class AWSIntegrationManager:
    """
    Manages AWS infrastructure operations for CloudShield.
    Supports Route53 DNS Failover and EC2 Auto-Scaling with graceful local fallback.
    """
    def __init__(self):
        self.region = os.getenv("AWS_REGION", "us-east-1")
        self.hosted_zone_id = os.getenv("AWS_ROUTE53_ZONE_ID", "")
        self.domain_name = os.getenv("AWS_DOMAIN_NAME", "cloudshield.example.com")
        self.primary_proxy_ip = os.getenv("AWS_PRIMARY_PROXY_IP", "203.0.113.10")
        self.secondary_proxy_ip = os.getenv("AWS_SECONDARY_PROXY_IP", "203.0.113.20")
        self.asg_name = os.getenv("AWS_ASG_NAME", "cloudshield-backend-asg")
        
        self.is_configured: bool = False
        self.route53_client = None
        self.ec2_client = None
        self.autoscaling_client = None

        # State tracking
        self.current_active_proxy: str = "PRIMARY"  # "PRIMARY" or "SECONDARY"
        self.dns_failover_history: list = []

        self._initialize_clients()

    def _initialize_clients(self):
        """Initializes boto3 clients if credentials and library exist."""
        if not BOTO3_AVAILABLE:
            logger.info("boto3 is not installed; AWS integration running in SIMULATION mode.")
            return

        has_creds = bool(
            os.getenv("AWS_ACCESS_KEY_ID") and os.getenv("AWS_SECRET_ACCESS_KEY")
        ) or bool(os.getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI")) or bool(os.getenv("AWS_ROLE_ARN"))

        if has_creds:
            try:
                self.route53_client = boto3.client("route53", region_name=self.region)
                self.autoscaling_client = boto3.client("autoscaling", region_name=self.region)
                self.ec2_client = boto3.client("ec2", region_name=self.region)
                self.is_configured = True
                logger.info("AWS Boto3 clients successfully initialized with cloud credentials.")
            except Exception as e:
                logger.warning(f"AWS client initialization failed ({e}); falling back to SIMULATION mode.")
                self.is_configured = False
        else:
            logger.info("No AWS credentials detected in environment. Running in SIMULATION mode.")
            self.is_configured = False

    def trigger_route53_failover(self, reason: str = "Tier 4 proxy failover triggered") -> Dict[str, Any]:
        """
        Executes DNS Failover: switches the Route53 A-record from Primary Proxy to Secondary Proxy.
        Uses low TTL (30s-60s) routing policy.
        """
        target_proxy = "SECONDARY"
        target_ip = self.secondary_proxy_ip
        timestamp = os.getenv("SIMULATED_TIME", "2026-10-05 13:30:00 UTC")

        if self.is_configured and self.route53_client and self.hosted_zone_id:
            try:
                change_batch = {
                    "Comment": f"CloudShield Tier 4 Failover: {reason}",
                    "Changes": [
                        {
                            "Action": "UPSERT",
                            "ResourceRecordSet": {
                                "Name": self.domain_name,
                                "Type": "A",
                                "TTL": 30,
                                "ResourceRecords": [{"Value": target_ip}],
                            }
                        }
                    ]
                }
                response = self.route53_client.change_resource_record_sets(
                    HostedZoneId=self.hosted_zone_id,
                    ChangeBatch=change_batch
                )
                self.current_active_proxy = target_proxy
                event = {
                    "action": "ROUTE53_DNS_FAILOVER",
                    "mode": "AWS_LIVE",
                    "status": response.get("ChangeInfo", {}).get("Status", "PENDING"),
                    "target_proxy": target_proxy,
                    "target_ip": target_ip,
                    "reason": reason
                }
                self.dns_failover_history.append(event)
                logger.warning(f"[AWS LIVE] Route53 DNS Failover executed: {target_ip} ({reason})")
                return event
            except ClientError as e:
                logger.error(f"Route53 failover API error: {e}")

        # Local simulation fallback
        self.current_active_proxy = target_proxy
        event = {
            "action": "ROUTE53_DNS_FAILOVER",
            "mode": "SIMULATED_LOCAL",
            "status": "SUCCESS",
            "target_proxy": target_proxy,
            "target_ip": target_ip,
            "reason": reason,
            "dns_record": {
                "name": self.domain_name,
                "type": "A",
                "ttl": 30,
                "value": target_ip
            }
        }
        self.dns_failover_history.append(event)
        logger.warning(f"[SIMULATED] Route53 DNS Failover to Secondary Proxy ({target_ip}): {reason}")
        return event

    def restore_route53_primary(self, reason: str = "Traffic returned to normal") -> Dict[str, Any]:
        """
        Restores Route53 DNS record back to Primary Proxy.
        """
        target_proxy = "PRIMARY"
        target_ip = self.primary_proxy_ip

        if self.is_configured and self.route53_client and self.hosted_zone_id:
            try:
                change_batch = {
                    "Comment": f"CloudShield Hysteresis Recovery: {reason}",
                    "Changes": [
                        {
                            "Action": "UPSERT",
                            "ResourceRecordSet": {
                                "Name": self.domain_name,
                                "Type": "A",
                                "TTL": 30,
                                "ResourceRecords": [{"Value": target_ip}],
                            }
                        }
                    ]
                }
                response = self.route53_client.change_resource_record_sets(
                    HostedZoneId=self.hosted_zone_id,
                    ChangeBatch=change_batch
                )
                self.current_active_proxy = target_proxy
                event = {
                    "action": "ROUTE53_DNS_RESTORE",
                    "mode": "AWS_LIVE",
                    "status": response.get("ChangeInfo", {}).get("Status", "PENDING"),
                    "target_proxy": target_proxy,
                    "target_ip": target_ip,
                    "reason": reason
                }
                self.dns_failover_history.append(event)
                logger.info(f"[AWS LIVE] Route53 restored to Primary Proxy: {target_ip}")
                return event
            except ClientError as e:
                logger.error(f"Route53 restore API error: {e}")

        self.current_active_proxy = target_proxy
        event = {
            "action": "ROUTE53_DNS_RESTORE",
            "mode": "SIMULATED_LOCAL",
            "status": "SUCCESS",
            "target_proxy": target_proxy,
            "target_ip": target_ip,
            "reason": reason,
            "dns_record": {
                "name": self.domain_name,
                "type": "A",
                "ttl": 30,
                "value": target_ip
            }
        }
        self.dns_failover_history.append(event)
        logger.info(f"[SIMULATED] Route53 restored to Primary Proxy ({target_ip})")
        return event

    def scale_out_backend_pool(self, desired_capacity: int = 4) -> Dict[str, Any]:
        """
        Scales out the backend EC2 Auto-Scaling Group (Tier 3 Mitigation).
        """
        if self.is_configured and self.autoscaling_client and self.asg_name:
            try:
                self.autoscaling_client.set_desired_capacity(
                    AutoScalingGroupName=self.asg_name,
                    DesiredCapacity=desired_capacity,
                    HonorCooldown=False
                )
                event = {
                    "action": "EC2_SCALE_OUT",
                    "mode": "AWS_LIVE",
                    "asg_name": self.asg_name,
                    "desired_capacity": desired_capacity,
                    "status": "APPLIED"
                }
                logger.warning(f"[AWS LIVE] ASG capacity scaled out to {desired_capacity} instances")
                return event
            except ClientError as e:
                logger.error(f"AWS AutoScaling error: {e}")

        event = {
            "action": "EC2_SCALE_OUT",
            "mode": "SIMULATED_LOCAL",
            "asg_name": self.asg_name,
            "desired_capacity": desired_capacity,
            "status": "APPLIED",
            "active_backends_simulated": desired_capacity
        }
        logger.warning(f"[SIMULATED] Backend pool scaled out to {desired_capacity} instances (Tier 3)")
        return event

    def get_status(self) -> Dict[str, Any]:
        """Returns the current AWS integration status."""
        return {
            "is_configured": self.is_configured,
            "mode": "AWS_LIVE" if self.is_configured else "SIMULATION_MODE",
            "region": self.region,
            "domain_name": self.domain_name,
            "current_active_proxy": self.current_active_proxy,
            "primary_proxy_ip": self.primary_proxy_ip,
            "secondary_proxy_ip": self.secondary_proxy_ip,
            "hosted_zone_id": self.hosted_zone_id if self.hosted_zone_id else "simulated-zone-id",
            "asg_name": self.asg_name,
            "failover_history": self.dns_failover_history[-5:]
        }

# Global AWS integration instance
aws_manager = AWSIntegrationManager()
