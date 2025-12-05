# Troubleshooting Guide

This guide helps you diagnose and resolve common issues with the Reverse Proxy Manager.

## General Troubleshooting Steps

When experiencing issues:

1. **Check the logs**
   ```bash
   docker compose logs -f app-dev
   # or
   docker compose logs -f app-prod
   ```

2. **Verify containers are running**
   ```bash
   docker compose ps
   ```

3. **Check system resources**
   ```bash
   docker stats
   ```

4. **Run system health check**
   ```bash
   docker compose run --rm manage system-check
   ```

## Installation Issues

### Docker Installation Problems

**Issue:** Docker command not found
```bash
# Solution: Install Docker
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
```

**Issue:** Permission denied when running docker
```bash
# Solution: Add user to docker group
sudo usermod -aG docker $USER
newgrp docker
```

**Issue:** Docker Compose version incompatible
```bash
# Check version
docker compose version

# Update to V2
sudo apt update
sudo apt install docker-compose-plugin
```

### Container Startup Issues

**Issue:** Container exits immediately after starting
```bash
# Check logs for error details
docker compose logs app-dev

# Common causes:
# - Missing environment variables
# - Database connection failure
# - Port already in use
```

**Issue:** Port already in use (5002)
```bash
# Find process using port
sudo lsof -i :5002
# or
sudo netstat -tulpn | grep 5002

# Change port in docker-compose.yml
ports:
  - "5003:5000"  # Use different port
```

**Issue:** Cannot connect to database
```bash
# Verify database container is running
docker compose ps db

# Restart database
docker compose restart db

# Check database logs
docker compose logs db
```

## Application Issues

### Login Problems

**Issue:** Cannot login with admin credentials
```bash
# Reset admin password
docker compose run --rm manage create-admin

# Or check database
docker compose exec db sqlite3 /app/instance/app.db
# SELECT * FROM user WHERE username='admin';
```

**Issue:** "Invalid credentials" error
- Verify username and password are correct
- Check caps lock is off
- Ensure password meets requirements (uppercase, lowercase, digits)

**Issue:** Session expires immediately
- Check SECRET_KEY is set in .env
- Verify browser cookies are enabled
- Clear browser cache and cookies

### Site Deployment Issues

**Issue:** Site deployment fails
```bash
# Check deployment logs
docker compose logs app-dev | grep deployment

# Common causes:
# 1. SSH connection failure to node
# 2. Invalid configuration syntax
# 3. Insufficient permissions on node
```

**Issue:** SSH connection to node fails
```bash
# Test SSH manually
ssh -i /path/to/key user@node-ip

# Check:
# - SSH key has correct permissions (600)
# - SSH user exists on node
# - Firewall allows SSH (port 22)
# - IP address is correct
```

**Issue:** Nginx/proxy configuration invalid
```bash
# Test configuration on node
ssh user@node-ip
sudo nginx -t

# Common errors:
# - Syntax errors in custom configuration
# - Conflicting server blocks
# - Missing SSL certificates
```

### SSL Certificate Issues

**Issue:** SSL certificate provisioning fails

**HTTP-01 Challenge Failures:**
```bash
# Check:
# - Port 80 is accessible from internet
# - Domain points to correct IP
# - No firewall blocking port 80
# - /.well-known/acme-challenge/ is accessible
```

**DNS-01 Challenge Failures:**
```bash
# Check:
# - DNS provider credentials are correct
# - API token has required permissions
# - DNS propagation (may take time)
# - Domain is correctly configured
```

**Issue:** Certificate renewal fails
```bash
# Manually renew certificate
docker compose run --rm manage renew-certificates

# Check certificate expiry
openssl x509 -in /path/to/cert.pem -noout -dates

# Common causes:
# - Rate limiting by Let's Encrypt
# - DNS/HTTP validation failure
# - Certificate already renewed recently
```

### WAF Issues

**Issue:** Legitimate traffic blocked by WAF
```bash
# Check WAF logs on node
ssh user@node-ip
sudo tail -f /var/log/modsec_audit.log

# Solutions:
# 1. Lower WAF protection level (Strict → Medium → Basic)
# 2. Add custom WAF rules to whitelist traffic
# 3. Disable specific ModSecurity rules
```

**Issue:** WAF not blocking malicious traffic
- Increase WAF protection level
- Verify ModSecurity is running on node
- Check WAF rules are correctly deployed
- Review and update custom rules

### Caching Issues

**Issue:** Content not being cached
```bash
# Check cache headers
curl -I https://yourdomain.com

# Look for:
# X-Cache-Status: HIT or MISS
# Cache-Control headers

# Verify:
# - Caching is enabled for site
# - Cache duration is configured
# - Backend sends cacheable responses
```

**Issue:** Stale content served
```bash
# Clear cache on node
ssh user@node-ip
sudo nginx -s reload

# Or disable caching temporarily
# Edit site configuration, set cache_enabled=false
```

### GeoIP Blocking Issues

**Issue:** GeoIP blocking not working
```bash
# Verify GeoIP database on node
ssh user@node-ip
ls -l /usr/share/GeoIP/

# Install GeoIP database if missing
sudo apt install geoip-database geoip-database-extra

# Restart Nginx
sudo systemctl restart nginx
```

**Issue:** Wrong countries blocked
- Verify country codes are correct (ISO 3166-1 alpha-2)
- Check blacklist vs whitelist mode
- Test from different IPs

## Performance Issues

### Slow Response Times

**Issue:** Application slow to respond
```bash
# Check resource usage
docker stats

# Increase resources if needed
# Edit docker-compose.yml
deploy:
  resources:
    limits:
      memory: 4G
      cpus: '2'
```

**Issue:** Database queries slow
```bash
# Check database size
docker compose exec db du -sh /app/instance/

# Optimize database
docker compose run --rm manage db optimize

# Consider PostgreSQL for production
```

**Issue:** High memory usage
```bash
# Identify memory-intensive processes
docker stats

# Restart application
docker compose restart app-dev

# Check for memory leaks in logs
```

### Rate Limiting Issues

**Issue:** Legitimate users getting rate limited
```bash
# Increase rate limits in site configuration
# Or adjust in .env
RATELIMIT_STORAGE_URI=memcached://memcached:11211

# Verify memcached is running
docker compose ps memcached
```

**Issue:** Rate limiting not working
```bash
# Check memcached connection
docker compose logs memcached

# Restart memcached
docker compose restart memcached

# Verify RATELIMIT_STORAGE_URI is set
```

## Node Management Issues

### Node Discovery Issues

**Issue:** Nodes not discovered automatically
```bash
# Check nodes.yaml file exists
cat config/nodes.yaml

# Verify AUTO_NODE_DISCOVERY=true in .env

# Manually trigger discovery
docker compose run --rm manage discover-nodes

# Check logs
docker compose logs app-dev | grep discovery
```

**Issue:** Discovered nodes inactive
```bash
# Set AUTO_ACTIVATE_DISCOVERED_NODES=true in .env

# Or manually activate
docker compose run --rm manage list-nodes
# Note node ID, then activate via web UI
```

### Node Monitoring Issues

**Issue:** Node statistics not updating
```bash
# Check SSH connectivity to node
ssh user@node-ip

# Verify monitoring commands work
ssh user@node-ip "top -bn1 | head -n 5"

# Check application logs
docker compose logs app-dev | grep monitoring
```

**Issue:** Node shows offline when it's online
- Verify firewall allows SSH
- Check SSH credentials are current
- Test SSH connection manually
- Restart application

## Database Issues

### Migration Problems

**Issue:** Database migration fails
```bash
# Check migration status
docker compose run --rm manage db current

# Review pending migrations
docker compose run --rm manage db heads

# Apply migrations
docker compose run --rm manage db upgrade

# If stuck, rollback and retry
docker compose run --rm manage db downgrade
docker compose run --rm manage db upgrade
```

**Issue:** Database locked
```bash
# SQLite database locked
# Stop all connections
docker compose down
docker compose up -d app-dev

# Check for stale lock files
ls -la instance/app.db*
```

### Data Corruption

**Issue:** Database corruption detected
```bash
# Restore from backup
docker compose run --rm manage restore-db --input=/backups/latest.sql

# If no backup available, try repair
sqlite3 instance/app.db ".dump" | sqlite3 instance/app_fixed.db
mv instance/app.db instance/app.db.corrupt
mv instance/app_fixed.db instance/app.db
```

## Docker Issues

### Volume Issues

**Issue:** Data lost after container restart
```bash
# Verify volumes are configured
docker volume ls | grep rpm

# Check volume mounts
docker compose config

# Ensure volumes are defined in docker-compose.yml
volumes:
  db-data:
  nginx-configs:
  cert-data:
```

**Issue:** Volume permissions problems
```bash
# Check volume permissions
docker compose run --rm app-dev ls -la /app/instance

# Fix permissions
docker compose run --rm app-dev chown -R 1000:1000 /app/instance
```

### Network Issues

**Issue:** Containers cannot communicate
```bash
# Check network
docker network ls
docker network inspect rpm_default

# Recreate network
docker compose down
docker compose up -d
```

**Issue:** Cannot access application from host
```bash
# Verify port mapping
docker compose ps

# Check firewall
sudo ufw status

# Test locally
curl http://localhost:5002
```

## Production Issues

### High Load Issues

**Issue:** Application unresponsive under load
```bash
# Scale horizontally
# Use load balancer + multiple instances

# Optimize database queries
# Add indexes, use caching

# Increase worker processes
# Edit gunicorn config
workers = (2 * CPU_COUNT) + 1
```

**Issue:** Memory leaks
```bash
# Monitor memory over time
watch docker stats

# Restart application periodically
# Set up cron job for nightly restart

# Investigate with profiling tools
```

### Backup and Restore Issues

**Issue:** Backup fails
```bash
# Check disk space
df -h

# Verify backup directory writable
ls -la /backups

# Manual backup
docker compose run --rm manage backup-db > /backups/manual_backup.sql
```

**Issue:** Restore fails
```bash
# Check backup file integrity
file /backups/backup.sql

# Verify SQL syntax
head -100 /backups/backup.sql

# Try manual restore
docker compose exec db sqlite3 /app/instance/app.db < /backups/backup.sql
```

## Getting Help

If you cannot resolve your issue:

1. **Check Documentation**
   - Review relevant guide sections
   - Check API documentation

2. **Search Issues**
   - [GitHub Issues](https://github.com/fabriziosalmi/reverse-proxy-manager/issues)
   - Check for similar problems

3. **Collect Information**
   ```bash
   # System info
   docker --version
   docker compose version
   uname -a
   
   # Application info
   docker compose ps
   docker compose logs app-dev --tail=100
   
   # Configuration
   cat .env | grep -v PASSWORD
   ```

4. **Create Issue**
   - Describe the problem clearly
   - Include steps to reproduce
   - Attach relevant logs
   - Specify your environment

5. **Community Support**
   - GitHub Discussions
   - Stack Overflow (tag: reverse-proxy-manager)

## Debug Mode

Enable debug mode for more detailed logs:

```env
# .env
DEBUG=True
LOG_LEVEL=DEBUG
```

**Warning:** Do not use debug mode in production!

## Common Error Messages

### "Database is locked"
- Multiple processes accessing SQLite
- Use PostgreSQL for production
- Restart application

### "ModuleNotFoundError"
- Missing Python dependency
- Rebuild Docker image: `docker compose build --no-cache`

### "Connection refused"
- Service not running
- Wrong port or IP
- Firewall blocking connection

### "Permission denied"
- File permission issue
- SSH key permissions
- User lacks required privileges

### "Command not found"
- Binary not in PATH
- Package not installed
- Use full path to command

For additional help, consult the [Architecture Guide](/guide/architecture) to understand system components.
