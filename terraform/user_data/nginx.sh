#!/usr/bin/env bash
set -e

# Update and install Nginx
apt-get update -y
apt-get install -y nginx curl

# Create directory for CloudShield dynamic blocklist
mkdir -p /etc/nginx/conf.d

# Write default blank blocklist
cat << 'EOF' > /etc/nginx/conf.d/blocklist.conf
# CloudShield Dynamic Blocklist Initialized
EOF

# Write CloudShield Nginx configuration
cat << 'EOF' > /etc/nginx/sites-available/default
limit_req_zone $binary_remote_addr zone=flood_limit:10m rate=50r/s;
limit_conn_zone $binary_remote_addr zone=conn_limit:10m;

upstream backend_pool {
    server 10.0.11.10:8000 max_fails=3 fail_timeout=5s;
    server 10.0.12.10:8000 max_fails=3 fail_timeout=5s;
}

server {
    listen 80 default_server;
    server_name _;

    include /etc/nginx/conf.d/blocklist.conf;

    limit_req zone=flood_limit burst=30 nodelay;
    limit_conn conn_limit 20;

    location /nginx-health {
        access_log off;
        default_type application/json;
        return 200 '{"status":"healthy","role":"nginx-proxy"}';
    }

    location = /robots.txt {
        default_type text/plain;
        return 200 "User-agent: *\nDisallow: /admin-backup/\nDisallow: /wp-login.php\n";
    }

    location / {
        proxy_pass http://backend_pool;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF

systemctl enable nginx
systemctl restart nginx
