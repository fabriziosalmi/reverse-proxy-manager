# Reverse Proxy Manager

A centralized proxy management system for distributed proxy nodes, providing robust management of content delivery infrastructure.

![Version](https://img.shields.io/badge/version-0.0.1-blue)
![Python](https://img.shields.io/badge/python-3.12+-green)
![Flask](https://img.shields.io/badge/flask-2.3+-green)
![License](https://img.shields.io/badge/license-MIT-yellow)
![Docker](https://img.shields.io/badge/docker-required-blue)

> **⚠️ DOCKER REQUIRED**: This application must be run using Docker and Docker Compose. Running the application outside of Docker is not supported and will lead to unexpected behavior.

## Screenshots

![screenshot1](https://github.com/fabriziosalmi/reverse-proxy-manager/blob/main/screenshot_1.png?raw=true)
![screenshot3](https://github.com/fabriziosalmi/reverse-proxy-manager/blob/main/screenshot_3.png?raw=true)


## Overview

Reverse Proxy Manager is a comprehensive solution for managing multiple proxy nodes from a centralized interface. It simplifies deployment, configuration, and monitoring of proxy infrastructure at scale, making it ideal for content delivery networks, load balancing, and distributed web hosting environments.

The system supports multiple reverse proxy types (Nginx, Caddy, and Traefik), allowing you to choose the right tool for each use case while managing everything from a single dashboard. This multi-proxy capability gives you flexibility to optimize for different requirements across your infrastructure.

## Features

- **Centralized Management**: Control multiple proxy nodes from a single dashboard
- **Multi-Proxy Support**: Mix and match Nginx, Caddy, and Traefik nodes in your infrastructure
- **SSL Management**: Automated SSL certificate provisioning and renewal
- **DNS Provider Integration**: Support for multiple DNS providers (CloudFlare, Route53, DigitalOcean, GoDaddy)  
- **Web Application Firewall**: Built-in WAF for enhanced security with advanced configuration options
- **Geographic Access Control**: Block or allow traffic based on country of origin (GeoIP)
- **Cache Configuration**: Fine-grained control over caching policies
- **Version Control**: Track and roll back configuration changes
- **Site Blocking**: Temporarily block sites across all nodes
- **User Management**: Role-based access control (admin/client)
- **Theme Support**: Built-in light/dark theme
- **Real-time Monitoring**: Live statistics for nodes including CPU, memory, connections
- **Deployment Tracking**: Comprehensive logs for all deployments
- **Automatic Node Discovery**: Add and manage nodes via YAML configuration
- **Rate Limiting**: Configurable request rate limiting with memcached storage

## Screenshots

*Coming soon*

## Docker Setup

The application **must** be run using Docker Compose in both development and production environments.

### Prerequisites

- Docker Engine (version 20.10.0 or higher)
- Docker Compose (V2 compatible)
- Git (for cloning the repository)

### Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/fabriziosalmi/reverse-proxy-manager.git
   cd reverse-proxy-manager
   ```

2. Create a `.env` file with your configuration (use the example as a template):
   ```bash
   cp .env.example .env
   # Edit .env with your preferred settings
   ```

3. Start the application in development mode:
   ```bash
   docker compose up app-dev
   ```

   Or in production mode:
   ```bash
   docker compose up -d app-prod
   ```

   Note: If you're using an older version of Docker Compose (v1), use `docker-compose` instead of `docker compose`.

4. Access the application at http://localhost:5002

### Environment Configuration

Configure the application by setting environment variables in the `.env` file, which will be used by Docker Compose:

Example `.env` file:
```
FLASK_ENV=development
ADMIN_USERNAME=admin
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=Admin123!  # Must contain uppercase, lowercase, and digits
SECRET_KEY=your_secure_secret_key
AUTO_NODE_DISCOVERY=true
NODES_YAML_PATH=/path/to/custom/nodes.yaml
AUTO_ACTIVATE_DISCOVERED_NODES=true
RATELIMIT_STORAGE_URI=memcached://memcached:11211
```

### Docker Management Commands

The application includes various management commands that must be run within Docker:

```bash
# Database Management
docker compose run --rm manage init-db              # Initialize the database
docker compose run --rm manage backup-db            # Backup the database
docker compose run --rm manage restore-db --input=backup.sql  # Restore from backup

# User Management
docker compose run --rm manage create-admin         # Create an admin user
docker compose run --rm manage list-users           # List all users

# Node Management
docker compose run --rm manage list-nodes           # List all nodes
docker compose run --rm manage discover-nodes       # Discover nodes from YAML

# Site Management
docker compose run --rm manage list-sites           # List all sites

# System Management
docker compose run --rm manage system-check         # Run a system health check
```

### Docker Volumes

The application uses Docker volumes to persist data:
- `db-data`: Database files
- `nginx-configs`: Generated Nginx configuration files
- `cert-data`: SSL certificates and related files

You can inspect these volumes with:
```bash
docker volume ls | grep italiacdn-proxy
```

## Automatic Node Discovery

Reverse Proxy Manager supports automatic discovery of proxy nodes from a YAML configuration file, enabling seamless management of infrastructure at scale.

### How It Works

1. Nodes are defined in a YAML file (`config/nodes.yaml` by default)
2. When the application starts with auto-discovery enabled, it reads this file and adds/updates nodes
3. Discovered nodes are marked with the `is_discovered` flag in the database
4. Nodes can be auto-activated upon discovery (configurable)

### Enabling Auto-Discovery

Set the following environment variables:

```
AUTO_NODE_DISCOVERY=true
NODES_YAML_PATH=/path/to/custom/nodes.yaml  # Optional, defaults to config/nodes.yaml
AUTO_ACTIVATE_DISCOVERED_NODES=true  # Optional, defaults to true
```

### YAML File Format

The nodes.yaml file should contain a list of node objects with the following properties:

```yaml
- name: cdn-node-1             # Required: Unique name to identify the node
  ip_address: 192.168.1.10     # Required: IPv4 or IPv6 address
  ssh_user: ubuntu             # Required: SSH username
  ssh_port: 22                 # Optional: SSH port (default: 22)
  ssh_key_path: /path/to/key   # Optional: Path to SSH private key
  ssh_password: password123    # Optional: SSH password (if not using key)
  nginx_config_path: /etc/nginx/conf.d  # Optional: Nginx config path
  nginx_reload_command: sudo systemctl reload nginx  # Optional: Command to reload Nginx
```

### Running Node Discovery Manually

You can trigger node discovery manually using the CLI command:

```bash
# Using default nodes.yaml location
./manage.py discover-nodes

# Specifying a custom YAML file
./manage.py discover-nodes --yaml-path=/path/to/nodes.yaml

# Disable auto-activation of discovered nodes
./manage.py discover-nodes --no-activate
```

### Migration for Existing Installations

If you're upgrading from a previous version, run the migration to add the `is_discovered` field:

```bash
./manage.py create-migration-is-discovered
flask db upgrade
```

## Web Application Firewall (WAF)

The Reverse Proxy Manager includes a comprehensive Web Application Firewall (WAF) system based on ModSecurity to protect your sites from common web vulnerabilities.

### WAF Protection Levels

Three protection levels are available:

- **Basic**: Essential protection against common web attacks with minimal false positives
- **Medium**: Enhanced protection with stricter rules (paranoia level 3)
- **Strict**: Maximum security with comprehensive rule sets (paranoia level 4)

### WAF Configuration Options

- **Request Size Limits**: Set maximum allowed size for client requests (1-100 MB)
- **Request Timeouts**: Configure timeouts for processing requests (10-300 seconds)
- **Tor Exit Node Blocking**: Option to block requests from known Tor exit nodes
- **Rate Limiting**: Restrict the number of requests per IP address with configurable:
  - Requests per minute (10-10000)
  - Burst size (10-20000)
- **Custom Rules**: Add custom ModSecurity compatible directives

### Sample Custom WAF Rules

```
# Block specific user agent
SecRule REQUEST_HEADERS:User-Agent "badbot" "id:1000,phase:1,deny,status:403,log,msg:'Blocked Bad Bot'"

# Block specific IP range
SecRule REMOTE_ADDR "@ipMatch 192.168.1.0/24" "id:1001,phase:1,deny,status:403,log,msg:'Blocked IP Range'"

# Block specific URI path
SecRule REQUEST_URI "@contains /admin/backup" "id:1002,phase:1,deny,status:403,log,msg:'Blocked sensitive URI'"
```

## Geographic Access Control (GeoIP)

The application offers country-based access control at two levels:

### Nginx Level GeoIP (Per Site)

- Configure per site in the site settings
- Two operation modes:
  - **Blacklist**: Block specific countries
  - **Whitelist**: Allow only specific countries
- Uses ISO 3166-1 alpha-2 country codes (e.g., US, CA, UK, DE)

### IP Tables Level GeoIP (Node-wide)

- Admin-only feature configured at the node level
- Affects all sites on the node
- Higher performance than Nginx-level filtering
- Managed through the node's country blocking interface

## Multi-Proxy System

The Reverse Proxy Manager supports multiple reverse proxy types, giving you flexibility to choose the right tool for each scenario while managing everything from a single interface.

### Supported Proxy Types

Currently, the system supports three proxy types:

1. **Nginx** - The default and most feature-rich option
2. **Caddy** - A modern, automatic HTTPS web server
3. **Traefik** - A dynamic, container-friendly reverse proxy and load balancer

### Feature Comparison

| Feature                   | Nginx                    | Caddy                    | Traefik                  |
|---------------------------|--------------------------|--------------------------|--------------------------|
| **Configuration Format**  | Text-based               | Text-based               | YAML/TOML                |
| **Auto HTTPS**            | Manual (Let's Encrypt)   | Automatic                | With Let's Encrypt       |
| **WAF Integration**       | ModSecurity              | Limited                  | Plugin-based             |
| **Cache Control**         | Full control             | Basic                    | Plugin-based             |
| **Rate Limiting**         | Built-in                 | Plugin                   | Plugin                   |
| **GeoIP Filtering**       | Built-in                 | Built-in                 | Plugin                   |
| **Websocket Support**     | Excellent                | Excellent                | Excellent                |
| **Container Integration** | Manual                   | Basic                    | Excellent                |
| **Dynamic Config**        | Reload required          | Automatic                | Automatic                |
| **Memory Usage**          | Low                      | Moderate                 | Moderate                 |
| **Community Support**     | Extensive                | Growing                  | Growing                  |
| **Performance**           | Excellent                | Good                     | Good                     |

### When to Use Each Proxy Type

- **Nginx**: High-traffic production environments, complex routing requirements, when advanced WAF features are needed
- **Caddy**: Quick deployments, environments where automatic HTTPS is valuable, when simplicity is preferred over fine-grained control
- **Traefik**: Container orchestration environments, microservices architectures, dynamic cloud environments

### Mixed Proxy Deployment Considerations

When deploying sites to multiple node types:

1. Some features may not be available across all proxy types
2. WAF configurations may differ in implementation
3. Caching behavior may vary
4. Custom configurations may need to be proxy-specific

The system attempts to translate configurations between proxy types when possible, but some advanced features may require proxy-specific configuration.

### Best Practices

1. Use the same proxy type for all nodes when possible
2. Test deployments when using multiple proxy types
3. Keep advanced features in separate configurations when using mixed proxy types
4. Consider which features are critical when selecting proxy types
5. Document any proxy-specific configurations for your sites

## Caching Configuration

Fine-grained control over content caching with multiple configuration options:

### Cache Settings

- **Enable/Disable Caching**: Toggle caching for each site
- **Content Cache Duration**: Set caching time for dynamic content (default: 3600 seconds / 1 hour)
- **Static Assets Cache Duration**: Configure longer cache times for static files like images, CSS, JS (default: 86400 seconds / 1 day)
- **Browser Cache Duration**: Set client-side cache-control headers (default: 3600 seconds)
- **Custom Cache Rules**: Add advanced Nginx cache directives for specialized requirements

### Cache Implementation

- Utilizes Nginx's proxy_cache system with optimized settings
- Implements cache bypass for certain request types
- Configures stale cache usage during backend errors or updates

## SSL Certificate Management

The platform supports automated SSL certificate provisioning and renewal using Let's Encrypt.

### Certificate Types

- **Let's Encrypt Certificates**: Free automatic certificates with 90-day validity
- **Self-signed Certificates**: For testing or internal use

### Validation Methods

- **HTTP-01 Challenge**: Standard validation through the /.well-known/acme-challenge/ path
- **DNS-01 Challenge**: Required for wildcard certificates, works behind firewalls

### Supported DNS Providers

For DNS-01 challenge verification, the following providers are supported:

- **CloudFlare**: Uses API tokens with Zone:DNS:Edit permissions
- **Route53 (AWS)**: Requires IAM user credentials with Route53 permissions
- **DigitalOcean**: Uses API tokens with read/write access
- **GoDaddy**: Uses API credentials for domain verification

### SSL Best Practices

- Strong SSL protocols (TLSv1.2, TLSv1.3) and ciphers
- OCSP stapling enabled for improved performance
- HTTP Strict Transport Security (HSTS) headers
- Automatic HTTP to HTTPS redirection
- Certificates renewed automatically at least 30 days before expiry

## Custom Nginx Configuration

Users can add custom Nginx directives to their site configurations:

- **Per-site Custom Configuration**: Add specialized Nginx directives for each site
- **Custom Cache Rules**: Define specific caching behavior for different content types
- **Location-based Rules**: Create custom location blocks for specialized handling

## Administrative Features

### Site Management

- **Add/Edit/Remove Sites**: Complete site lifecycle management
- **Site Blocking**: Temporarily block a site across all nodes
- **Bulk Operations**: Perform actions on multiple sites (activate, deactivate, block, unblock)
- **Configuration Testing**: Test configurations before deployment
- **Config Version History**: Track changes and roll back to previous versions

### Node Management

- **Node Statistics**: Real-time monitoring of CPU, memory, disk usage, and connections
- **Nginx Information**: View running configuration, virtual hosts, and SSL certificates
- **Country Blocking**: Implement IP tables level GeoIP filtering
- **Site Deployment**: Manage which sites are deployed to which nodes

### User Management

- **Role-based Access**: Admin and client roles with appropriate permissions
- **User CRUD Operations**: Create, view, edit, and delete users
- **Profile Management**: Users can update their profiles and passwords

## Client Features

### Dashboard

- **Site Statistics**: Overview of active and inactive sites
- **Quick Actions**: Shortcuts to common tasks

### Site Management

- **Site Creation**: Wizard for creating new proxy sites
- **Site Configuration**: Edit all aspects of site settings
- **SSL Management**: Request and manage SSL certificates
- **Deployment Status**: View deployment status across all nodes

## Development

### Docker Development (Recommended)

For development, the application code is mounted as a volume, so code changes are reflected immediately:

```bash
docker compose up app-dev
```

### Local Development Setup (Not Recommended)

While the application is designed to run via Docker Compose, you can set up a local development environment for testing specific components:

1. Create a virtual environment:
   ```bash
   python3 -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

2. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

3. Initialize the database:
   ```bash
   python manage.py init-db
   ```

4. Run the application:
   ```bash
   python run.py
   ```

5. Access the application at http://localhost:5000

Note: Some features that depend on Docker services (like memcached for rate limiting) may not work correctly in this setup.

## Production Deployment

For production deployment, use the production service with Docker Compose:

```bash
docker compose up -d app-prod
```

This starts the application with Gunicorn as the WSGI server for better performance and reliability.

### Production Configuration

Recommended production settings:

```
FLASK_ENV=production
DEBUG=False
LOG_LEVEL=INFO
PROXY_FIX=True  # If behind a reverse proxy
RATELIMIT_STORAGE_URI=memcached://memcached:11211
```

### Security Considerations

- Use strong passwords for admin accounts (must contain uppercase, lowercase, and digits)
- Store SSH keys securely
- Keep API tokens with minimal required permissions
- Regular updates and security patches
- Backup database periodically

## Updates and Migrations

When updating the application, follow these steps:

1. Pull the latest code:
   ```bash
   git pull
   ```

2. Rebuild and restart containers:
   ```bash
   docker compose down
   docker compose up -d --build
   ```

3. Apply any new database migrations (if needed):
   ```bash
   docker compose run --rm manage db upgrade
   ```

This process will update all Docker containers and apply the necessary database changes.

## Docker Troubleshooting

### Common Docker Issues

- **Container Startup Failures**: Check container logs with `docker compose logs app-dev` or `docker compose logs app-prod`
- **Database Connection Issues**: Ensure the database volume is properly mounted and has correct permissions
- **Networking Problems**: Verify ports are correctly mapped in `docker-compose.yml` and not blocked by firewalls
- **Memory Issues**: If containers crash or become unresponsive, increase Docker memory allocation in Docker Desktop settings
- **Volume Permission Issues**: Check file permissions in mounted volumes, especially for SSL certificates and config files

### Container Health Checks

You can check the health of containers with:
```bash
docker compose ps
```

If containers are constantly restarting, check logs:
```bash
docker compose logs --tail=100 app-dev
```

### Rebuilding Containers

If you encounter persistent issues, you may need to rebuild the containers completely:
```bash
docker compose down
docker compose build --no-cache
docker compose up -d
```

### Docker Network Inspection

To inspect the Docker network:
```bash
docker network ls
docker network inspect italiacdn-proxy_default
```

## Architecture

Reverse Proxy Manager follows a modular architecture with these key components:

- **Web Interface**: Flask-based admin and client panels
- **Node Connector**: Secure SSH-based deployment system
- **Configuration Generator**: Templating system for Nginx configs
- **Database**: SQLite for development, PostgreSQL recommended for production
- **Task Queue**: Background job processing for deployments and certificate renewals

## Roadmap

Future development plans include:

- **Cloud Integration**: Direct deployment to AWS, GCP, and Azure
- **Kubernetes Support**: Manage containerized Nginx instances
- **Advanced Analytics**: Extended metrics and reporting
- **Multi-factor Authentication**: Enhanced security for admin accounts
- **Extended API**: Comprehensive programmatic access
- **Custom Plugins**: Extensible plugin architecture

## Contributing

Contributions are welcome! To contribute:

1. Fork the repository
2. Create your feature branch: `git checkout -b feature/amazing-feature`
3. Commit your changes: `git commit -m 'Add some amazing feature'`
4. Push to the branch: `git push origin feature/amazing-feature`
5. Open a Pull Request

Please read [CONTRIBUTING.md](CONTRIBUTING.md) for details on our code of conduct and the submission process.

## Support

For support and questions:

- [GitHub Issues](https://github.com/fabriziosalmi/reverse-proxy-manager/issues)
- [Documentation](https://github.com/fabriziosalmi/reverse-proxy-manager/wiki)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgements

- [Nginx](https://nginx.org/) for the amazing web server
- [Flask](https://flask.palletsprojects.com/) for the web framework
- [Let's Encrypt](https://letsencrypt.org/) for free SSL certificates
- [ModSecurity](https://modsecurity.org/) for WAF capabilities
- [Memcached](https://memcached.org/) for rate limiting storage
- [Docker](https://www.docker.com/) for containerization
- [All contributors](https://github.com/fabriziosalmi/reverse-proxy-manager/graphs/contributors) who have helped with the project

## Important Note

This application is designed to be used exclusively via Docker Compose. Running the application outside of Docker Compose is not supported and will lead to unexpected behavior.
