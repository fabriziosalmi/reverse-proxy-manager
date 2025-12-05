# Configuration Guide

This guide covers all configuration options available in the Reverse Proxy Manager.

## Environment Configuration

All configuration is done through environment variables in the `.env` file.

### Basic Configuration

```env
# Application Environment
FLASK_ENV=development  # or production
DEBUG=False  # Set to False in production

# Security
SECRET_KEY=your_secure_random_key_here
ADMIN_USERNAME=admin
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=Admin123!  # Must contain uppercase, lowercase, and digits

# Logging
LOG_LEVEL=INFO  # DEBUG, INFO, WARNING, ERROR, CRITICAL
```

### Node Discovery Configuration

```env
# Automatic Node Discovery
AUTO_NODE_DISCOVERY=true
NODES_YAML_PATH=config/nodes.yaml
AUTO_ACTIVATE_DISCOVERED_NODES=true
```

### Rate Limiting Configuration

```env
# Rate Limiting (requires memcached)
RATELIMIT_STORAGE_URI=memcached://memcached:11211
```

### Proxy Configuration

```env
# If running behind a reverse proxy
PROXY_FIX=True
```

## Multi-Proxy System

The Reverse Proxy Manager supports three proxy types: Nginx, Caddy, and Traefik.

### Supported Proxy Types

**Nginx** (Default)
- Most feature-rich option
- Full WAF support
- Advanced caching
- Best for high-traffic production environments

**Caddy**
- Automatic HTTPS
- Simple configuration
- Good for quick deployments

**Traefik**
- Container-friendly
- Dynamic configuration
- Best for microservices

### Feature Comparison

| Feature | Nginx | Caddy | Traefik |
|---------|-------|-------|---------|
| Auto HTTPS | Manual | Automatic | Automatic |
| WAF | Full | Limited | Plugin-based |
| Caching | Full control | Basic | Plugin-based |
| Rate Limiting | Built-in | Plugin | Plugin |
| Performance | Excellent | Good | Good |

## Web Application Firewall (WAF)

Configure WAF protection for your sites.

### Protection Levels

**Basic Protection**
- Essential protection against common web attacks
- Minimal false positives
- Recommended for most sites

**Medium Protection**
- Enhanced protection with stricter rules
- Paranoia level 3
- Good balance of security and compatibility

**Strict Protection**
- Maximum security
- Paranoia level 4
- May require rule tuning to reduce false positives

### WAF Configuration Options

```
Request Size Limits: 1-100 MB
Request Timeouts: 10-300 seconds
Tor Exit Node Blocking: Enabled/Disabled
Rate Limiting:
  - Requests per minute: 10-10000
  - Burst size: 10-20000
```

### Custom WAF Rules

Add custom ModSecurity directives:

```
# Block specific user agent
SecRule REQUEST_HEADERS:User-Agent "badbot" "id:1000,phase:1,deny,status:403,log,msg:'Blocked Bad Bot'"

# Block specific IP range
SecRule REMOTE_ADDR "@ipMatch 192.168.1.0/24" "id:1001,phase:1,deny,status:403,log,msg:'Blocked IP Range'"

# Block specific URI path
SecRule REQUEST_URI "@contains /admin/backup" "id:1002,phase:1,deny,status:403,log,msg:'Blocked sensitive URI'"
```

## SSL Certificate Management

Automated SSL certificate provisioning and renewal using Let's Encrypt.

### Certificate Types

**Let's Encrypt Certificates**
- Free automatic certificates
- 90-day validity
- Automatic renewal

**Self-signed Certificates**
- For testing or internal use
- Not trusted by browsers

### Validation Methods

**HTTP-01 Challenge**
- Standard validation through `/.well-known/acme-challenge/`
- Requires port 80 accessible
- Cannot be used for wildcard certificates

**DNS-01 Challenge**
- Required for wildcard certificates
- Works behind firewalls
- Requires DNS provider API access

### Supported DNS Providers

**CloudFlare**
- API Token with Zone:DNS:Edit permissions
- Recommended for most users

**Amazon Route53**
- IAM user credentials with Route53 permissions
- Good for AWS infrastructure

**DigitalOcean**
- API token with read/write access
- Simple configuration

**GoDaddy**
- API credentials
- Supports most common use cases

### SSL Best Practices

The following are automatically configured:
- TLSv1.2 and TLSv1.3 protocols only
- Strong cipher suites
- OCSP stapling
- HSTS headers
- Automatic HTTP to HTTPS redirection

## Geographic Access Control (GeoIP)

Control access based on visitor's country of origin.

### Nginx Level GeoIP (Per Site)

Configure in site settings:

**Blacklist Mode**
- Block specific countries
- Allow all others

**Whitelist Mode**
- Allow only specific countries
- Block all others

**Country Codes**
- Use ISO 3166-1 alpha-2 codes (e.g., US, CA, UK, DE, FR, IT, ES)

### IP Tables Level GeoIP (Node-wide)

- Admin-only feature
- Affects all sites on the node
- Higher performance than Nginx-level filtering
- Configure through node's country blocking interface

## Caching Configuration

Fine-grained control over content caching.

### Cache Settings

**Enable/Disable Caching**
- Toggle caching per site

**Content Cache Duration**
- Default: 3600 seconds (1 hour)
- Cache time for dynamic content

**Static Assets Cache Duration**
- Default: 86400 seconds (1 day)
- Longer cache for CSS, JS, images

**Browser Cache Duration**
- Default: 3600 seconds
- Client-side cache-control headers

### Custom Cache Rules

Add advanced Nginx cache directives:

```nginx
# Bypass cache for specific paths
proxy_cache_bypass $cookie_nocache $arg_nocache;

# Cache based on response headers
proxy_cache_valid 200 302 10m;
proxy_cache_valid 404 1m;

# Cache based on content type
location ~* \.(jpg|jpeg|png|gif|ico|css|js)$ {
    expires 1y;
    add_header Cache-Control "public, immutable";
}
```

### Cache Implementation

- Uses Nginx's proxy_cache system
- Implements cache bypass for certain request types
- Configures stale cache usage during backend errors
- Optimized for performance

## Custom Nginx Configuration

Add specialized directives per site.

### Per-Site Custom Configuration

Example custom configurations:

```nginx
# Custom headers
add_header X-Frame-Options "SAMEORIGIN" always;
add_header X-Content-Type-Options "nosniff" always;

# Custom access control
location /api/ {
    limit_except GET POST {
        deny all;
    }
}

# Custom proxy settings
proxy_read_timeout 300s;
proxy_connect_timeout 75s;
```

### Location-based Rules

```nginx
# Serve static files directly
location /static/ {
    alias /var/www/static/;
    expires 30d;
}

# WebSocket support
location /ws/ {
    proxy_http_version 1.1;
    proxy_set_header Upgrade $http_upgrade;
    proxy_set_header Connection "upgrade";
}
```

## Node Configuration

Configure individual proxy nodes.

### Node Properties

- **Name**: Unique identifier for the node
- **IP Address**: IPv4 or IPv6 address
- **SSH User**: Username for SSH access
- **SSH Port**: SSH port (default: 22)
- **SSH Authentication**: Key-based or password
- **Nginx Config Path**: Path to Nginx config directory
- **Nginx Reload Command**: Command to reload Nginx

### Node Discovery YAML

```yaml
- name: production-node-1
  ip_address: 203.0.113.10
  ssh_user: ubuntu
  ssh_port: 22
  ssh_key_path: /keys/prod-node-1.pem
  nginx_config_path: /etc/nginx/conf.d
  nginx_reload_command: sudo systemctl reload nginx

- name: production-node-2
  ip_address: 203.0.113.11
  ssh_user: ubuntu
  ssh_port: 22
  ssh_key_path: /keys/prod-node-2.pem
  nginx_config_path: /etc/nginx/conf.d
  nginx_reload_command: sudo systemctl reload nginx
```

## Site Configuration

Configure individual proxy sites.

### Basic Site Settings

- **Domain Name**: Primary domain for the site
- **Backend IP**: IP address of the backend server
- **Backend Port**: Port of the backend service
- **Protocol**: HTTP or HTTPS

### Advanced Site Settings

- **SSL Configuration**: Certificate type and validation method
- **WAF Protection**: Protection level and custom rules
- **Cache Settings**: Cache durations and custom rules
- **GeoIP Settings**: Country allowlist/blocklist
- **Rate Limiting**: Requests per minute and burst size
- **Custom Configuration**: Additional Nginx directives

## Security Best Practices

### Password Requirements

- Minimum 8 characters
- At least one uppercase letter
- At least one lowercase letter
- At least one digit
- Special characters recommended

### SSH Key Management

- Use SSH keys instead of passwords when possible
- Store SSH keys securely
- Rotate keys periodically
- Use different keys for different environments

### API Token Security

- Use minimal required permissions
- Rotate tokens regularly
- Never commit tokens to version control
- Use environment variables for tokens

### Database Security

- Regular backups
- Secure backup storage
- Test restore procedures
- Monitor for unauthorized access

## Monitoring Configuration

### Real-time Node Monitoring

Monitor the following metrics:
- CPU usage
- Memory usage
- Disk usage
- Active connections
- Network traffic

### Deployment Logging

Track all deployments:
- Configuration changes
- Deployment timestamps
- Success/failure status
- Error messages

### System Health Checks

Run periodic health checks:
```bash
docker compose run --rm manage system-check
```

## Production Configuration

Recommended production settings:

```env
# Production Environment
FLASK_ENV=production
DEBUG=False
LOG_LEVEL=INFO

# Security
SECRET_KEY=long_random_secure_key_here
PROXY_FIX=True

# Performance
RATELIMIT_STORAGE_URI=memcached://memcached:11211

# Monitoring
ENABLE_METRICS=True
```

### Production Checklist

- [ ] Set `FLASK_ENV=production`
- [ ] Disable debug mode (`DEBUG=False`)
- [ ] Use strong `SECRET_KEY`
- [ ] Configure SSL for all sites
- [ ] Enable WAF protection
- [ ] Set up rate limiting
- [ ] Configure automatic backups
- [ ] Enable monitoring
- [ ] Review security settings
- [ ] Test disaster recovery

For deployment instructions, see the [Deployment Guide](/guide/deployment).
