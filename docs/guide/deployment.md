# Deployment Guide

This guide covers production deployment of the Reverse Proxy Manager.

## Production Deployment

The Reverse Proxy Manager is designed to run in production using Docker Compose.

### Prerequisites

- Docker Engine 20.10.0 or higher
- Docker Compose V2
- Server with sufficient resources (4GB RAM minimum, 8GB recommended)
- Domain name configured to point to your server
- SSL certificate or Let's Encrypt access

## Deployment Steps

### 1. Server Preparation

**Update System**
```bash
sudo apt update && sudo apt upgrade -y
```

**Install Docker**
```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
```

**Configure Firewall**
```bash
# Allow necessary ports
sudo ufw allow 22/tcp    # SSH
sudo ufw allow 80/tcp    # HTTP
sudo ufw allow 443/tcp   # HTTPS
sudo ufw allow 5002/tcp  # Application (or use reverse proxy)
sudo ufw enable
```

### 2. Clone and Configure

**Clone Repository**
```bash
git clone https://github.com/fabriziosalmi/reverse-proxy-manager.git
cd reverse-proxy-manager
```

**Create Production Environment File**
```bash
cp .env.example .env
```

**Edit `.env` with production settings:**
```env
FLASK_ENV=production
DEBUG=False
LOG_LEVEL=INFO

# Security - Generate strong random keys
SECRET_KEY=$(openssl rand -hex 32)
ADMIN_USERNAME=admin
ADMIN_EMAIL=admin@yourdomain.com
ADMIN_PASSWORD=YourStrongPassword123!

# Rate Limiting
RATELIMIT_STORAGE_URI=memcached://memcached:11211

# Node Discovery
AUTO_NODE_DISCOVERY=true
NODES_YAML_PATH=config/nodes.yaml
AUTO_ACTIVATE_DISCOVERED_NODES=true

# Proxy Configuration (if behind reverse proxy)
PROXY_FIX=True
```

### 3. Configure Nodes

**Create `config/nodes.yaml`:**
```yaml
- name: proxy-node-1
  ip_address: 192.168.1.10
  ssh_user: ubuntu
  ssh_port: 22
  ssh_key_path: /app/keys/node1.pem
  nginx_config_path: /etc/nginx/conf.d
  nginx_reload_command: sudo systemctl reload nginx

- name: proxy-node-2
  ip_address: 192.168.1.11
  ssh_user: ubuntu
  ssh_port: 22
  ssh_key_path: /app/keys/node2.pem
  nginx_config_path: /etc/nginx/conf.d
  nginx_reload_command: sudo systemctl reload nginx
```

**Store SSH Keys Securely**
```bash
mkdir -p keys
chmod 700 keys
# Copy your SSH keys to the keys/ directory
chmod 600 keys/*.pem
```

### 4. Start Production Service

**Build and Start**
```bash
docker compose up -d app-prod
```

**Verify Deployment**
```bash
docker compose ps
docker compose logs -f app-prod
```

**Initialize Database**
```bash
docker compose run --rm manage init-db
```

**Create Admin User**
```bash
docker compose run --rm manage create-admin
```

### 5. Configure SSL/TLS

**Option A: Use Let's Encrypt (Recommended)**

If exposing the application directly to the internet, configure Let's Encrypt in your reverse proxy.

**Option B: Behind Reverse Proxy**

Configure your reverse proxy (Nginx, Caddy, or Traefik) to handle SSL termination:

```nginx
# Example Nginx configuration
server {
    listen 443 ssl http2;
    server_name manager.yourdomain.com;

    ssl_certificate /etc/letsencrypt/live/manager.yourdomain.com/fullchain.pem;
    ssl_certificate_key /etc/letsencrypt/live/manager.yourdomain.com/privkey.pem;

    location / {
        proxy_pass http://localhost:5002;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

## Production Best Practices

### Security Hardening

**1. Strong Authentication**
- Use strong passwords (minimum 12 characters)
- Enable two-factor authentication if available
- Regularly rotate credentials

**2. Network Security**
- Use firewall rules to restrict access
- Implement fail2ban for SSH protection
- Consider VPN access for management interface

**3. Data Protection**
- Enable encryption at rest
- Use encrypted connections (SSL/TLS)
- Secure SSH keys with passphrases

### Performance Optimization

**1. Resource Allocation**
```yaml
# docker-compose.yml adjustments
services:
  app-prod:
    deploy:
      resources:
        limits:
          cpus: '2'
          memory: 4G
        reservations:
          cpus: '1'
          memory: 2G
```

**2. Database Optimization**
- Regular VACUUM operations for SQLite
- Consider PostgreSQL for larger deployments
- Implement connection pooling

**3. Caching Strategy**
- Configure memcached appropriately
- Use Redis for session storage (optional)
- Implement CDN for static assets

### Backup Strategy

**Automated Backups**

Create a backup script:
```bash
#!/bin/bash
# backup.sh

DATE=$(date +%Y%m%d_%H%M%S)
BACKUP_DIR="/backups/reverse-proxy-manager"

mkdir -p $BACKUP_DIR

# Backup database
docker compose run --rm manage backup-db > $BACKUP_DIR/db_$DATE.sql

# Backup configurations
tar -czf $BACKUP_DIR/config_$DATE.tar.gz config/

# Backup SSL certificates
tar -czf $BACKUP_DIR/certs_$DATE.tar.gz \
  $(docker volume inspect italiacdn-proxy_cert-data --format '{{ .Mountpoint }}')

# Cleanup old backups (keep last 30 days)
find $BACKUP_DIR -type f -mtime +30 -delete

echo "Backup completed: $DATE"
```

**Schedule with Cron**
```bash
# Add to crontab
0 2 * * * /path/to/backup.sh >> /var/log/rpm-backup.log 2>&1
```

**Backup Verification**
```bash
# Test restore periodically
docker compose run --rm manage restore-db --input=/backups/db_latest.sql
```

### Monitoring and Logging

**Application Logs**
```bash
# View logs
docker compose logs -f app-prod

# Export logs
docker compose logs app-prod > app-logs.txt
```

**System Monitoring**

Configure monitoring tools:
- **Prometheus**: For metrics collection
- **Grafana**: For visualization
- **Alertmanager**: For alerting

**Health Checks**

Set up automated health checks:
```bash
# Add to crontab
*/5 * * * * curl -f http://localhost:5002/health || echo "Health check failed" | mail -s "RPM Health Alert" admin@yourdomain.com
```

### Updates and Maintenance

**Update Procedure**

1. **Backup First**
   ```bash
   ./backup.sh
   ```

2. **Pull Latest Code**
   ```bash
   git pull
   ```

3. **Review Changes**
   ```bash
   git log -5
   ```

4. **Update Containers**
   ```bash
   docker compose down
   docker compose build --no-cache
   docker compose up -d app-prod
   ```

5. **Apply Migrations**
   ```bash
   docker compose run --rm manage db upgrade
   ```

6. **Verify**
   ```bash
   docker compose ps
   docker compose run --rm manage system-check
   ```

**Rollback Procedure**

If an update causes issues:
```bash
# Stop application
docker compose down

# Restore previous version
git checkout <previous-commit-hash>

# Restore database
docker compose run --rm manage restore-db --input=/backups/db_before_update.sql

# Restart
docker compose up -d app-prod
```

## High Availability Deployment

For mission-critical deployments:

### Load Balancing

**Option 1: Multiple Application Instances**
```yaml
# docker-compose.yml
services:
  app-prod-1:
    # ... configuration
  app-prod-2:
    # ... configuration
  
  nginx-lb:
    image: nginx:alpine
    volumes:
      - ./nginx-lb.conf:/etc/nginx/nginx.conf
    ports:
      - "80:80"
      - "443:443"
```

**Option 2: External Load Balancer**
- Use HAProxy, Nginx, or cloud load balancers
- Distribute traffic across multiple instances
- Implement health checks

### Database High Availability

**Option 1: PostgreSQL with Replication**
- Primary-replica setup
- Automatic failover with Patroni
- Point-in-time recovery

**Option 2: Managed Database**
- Use managed database services (AWS RDS, Google Cloud SQL)
- Automatic backups and failover
- Better for cloud deployments

### Container Orchestration

**Consider Kubernetes for Large Deployments**
```yaml
# kubernetes/deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: reverse-proxy-manager
spec:
  replicas: 3
  selector:
    matchLabels:
      app: rpm
  template:
    metadata:
      labels:
        app: rpm
    spec:
      containers:
      - name: rpm
        image: rpm:latest
        ports:
        - containerPort: 5000
```

## Disaster Recovery

### Recovery Plan

1. **Identify Issue**
   - Check monitoring alerts
   - Review logs
   - Assess impact

2. **Immediate Response**
   - Switch to backup system if available
   - Notify stakeholders
   - Begin recovery procedures

3. **Data Recovery**
   ```bash
   # Restore database
   docker compose run --rm manage restore-db --input=/backups/latest.sql
   
   # Restore configurations
   tar -xzf /backups/config_latest.tar.gz -C /
   ```

4. **Service Recovery**
   ```bash
   # Restart services
   docker compose down
   docker compose up -d app-prod
   
   # Verify
   docker compose run --rm manage system-check
   ```

5. **Post-Recovery**
   - Document incident
   - Review and improve procedures
   - Update disaster recovery plan

### Testing Recovery Procedures

Schedule regular disaster recovery drills:
```bash
# Monthly DR test
# 1. Create test backup
# 2. Spin up test environment
# 3. Restore backup
# 4. Verify functionality
# 5. Document results
```

## Production Checklist

Before going live, ensure:

- [ ] Environment variables configured for production
- [ ] Strong passwords and secret keys set
- [ ] SSL/TLS certificates configured
- [ ] Firewall rules in place
- [ ] Backup system configured and tested
- [ ] Monitoring and alerting set up
- [ ] Disaster recovery plan documented
- [ ] Health checks configured
- [ ] Log rotation configured
- [ ] Resource limits set appropriately
- [ ] Security hardening applied
- [ ] Documentation updated
- [ ] Team trained on operations

## Troubleshooting Production Issues

For common production issues, see the [Troubleshooting Guide](/guide/troubleshooting).

### Emergency Contacts

Maintain a list of emergency contacts:
- Infrastructure team
- Database administrator
- Security team
- On-call rotation

### Incident Response

Follow your incident response plan:
1. Detect and alert
2. Assess and escalate
3. Contain and recover
4. Learn and improve
