#!/usr/bin/env bash
set -e

# Update and install Python 3.11 and dependencies
apt-get update -y
apt-get install -y python3 python3-pip python3-venv git curl

# Create application user and directory
mkdir -p /opt/cloudshield
cd /opt/cloudshield

# Set up Python virtual environment
python3 -m venv /opt/cloudshield/venv
/opt/cloudshield/venv/bin/pip install --upgrade pip
/opt/cloudshield/venv/bin/pip install fastapi uvicorn[standard] sqlalchemy pydantic prometheus-client httpx boto3

# Create systemd service for CloudShield Backend
cat << 'EOF' > /etc/systemd/system/cloudshield-backend.service
[Unit]
Description=CloudShield Application Pool Backend Service
After=network.target

[Service]
User=root
WorkingDirectory=/opt/cloudshield
ExecStart=/opt/cloudshield/venv/bin/uvicorn app.main:app --host 0.0.0.0 --port 8000
Restart=always
RestartSec=3
Environment=ENVIRONMENT=production
Environment=SERVER_NAME=aws-backend-node

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable cloudshield-backend
