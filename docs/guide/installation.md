# Installation Guide

This guide provides detailed installation instructions for the Reverse Proxy Manager.

## System Requirements

### Minimum Requirements

- **CPU**: 2 cores
- **RAM**: 4GB
- **Storage**: 10GB free space
- **Operating System**: Linux (Ubuntu 20.04+, Debian 11+, CentOS 8+) or macOS

### Required Software

- **Docker Engine**: 20.10.0 or higher
- **Docker Compose**: V2 compatible
- **Git**: Latest stable version

## Installation Methods

### Docker Installation (Recommended)

This is the recommended method for both development and production environments.

#### Step 1: Install Docker

**Ubuntu/Debian:**
```bash
curl -fsSL https://get.docker.com -o get-docker.sh
sudo sh get-docker.sh
sudo usermod -aG docker $USER
```

**macOS:**
Download and install [Docker Desktop for Mac](https://docs.docker.com/desktop/install/mac-install/)

#### Step 2: Verify Docker Installation

```bash
docker --version
docker compose version
```

#### Step 3: Clone the Repository

```bash
git clone https://github.com/fabriziosalmi/reverse-proxy-manager.git
cd reverse-proxy-manager
```

#### Step 4: Environment Configuration

Create and configure your `.env` file:

```bash
cp .env.example .env
```

Edit the `.env` file with your configuration. See [Configuration Guide](/guide/configuration) for details.

#### Step 5: Start the Application

**Development Mode:**
```bash
docker compose up app-dev
```

**Production Mode:**
```bash
docker compose up -d app-prod
```

## Docker Volumes

The application uses the following Docker volumes to persist data:

- `db-data`: Database files
- `nginx-configs`: Generated Nginx configuration files
- `cert-data`: SSL certificates and related files

To inspect volumes:
```bash
docker volume ls | grep italiacdn-proxy
```

## Environment Variables

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `ADMIN_USERNAME` | Administrator username | `admin` |
| `ADMIN_EMAIL` | Administrator email | `admin@example.com` |
| `ADMIN_PASSWORD` | Administrator password (must contain uppercase, lowercase, and digits) | `Admin123!` |
| `SECRET_KEY` | Flask secret key for session management | `your_secure_random_key` |

### Optional Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `FLASK_ENV` | Application environment | `development` |
| `DEBUG` | Enable debug mode | `True` |
| `LOG_LEVEL` | Logging level | `INFO` |
| `AUTO_NODE_DISCOVERY` | Enable automatic node discovery | `false` |
| `NODES_YAML_PATH` | Path to nodes YAML file | `config/nodes.yaml` |
| `AUTO_ACTIVATE_DISCOVERED_NODES` | Auto-activate discovered nodes | `true` |
| `RATELIMIT_STORAGE_URI` | Memcached URI for rate limiting | `memcached://memcached:11211` |

## Management Commands

### Database Management

```bash
# Initialize database
docker compose run --rm manage init-db

# Backup database
docker compose run --rm manage backup-db

# Restore database
docker compose run --rm manage restore-db --input=backup.sql
```

### User Management

```bash
# Create admin user
docker compose run --rm manage create-admin

# List all users
docker compose run --rm manage list-users
```

### Node Management

```bash
# List all nodes
docker compose run --rm manage list-nodes

# Discover nodes from YAML
docker compose run --rm manage discover-nodes
```

### Site Management

```bash
# List all sites
docker compose run --rm manage list-sites
```

### System Management

```bash
# Run system health check
docker compose run --rm manage system-check
```

## Automatic Node Discovery

The Reverse Proxy Manager supports automatic discovery of proxy nodes from a YAML configuration file.

### Enable Node Discovery

Set these environment variables in your `.env` file:

```env
AUTO_NODE_DISCOVERY=true
NODES_YAML_PATH=/path/to/custom/nodes.yaml  # Optional
AUTO_ACTIVATE_DISCOVERED_NODES=true  # Optional
```

### YAML File Format

Create a `config/nodes.yaml` file:

```yaml
- name: cdn-node-1
  ip_address: 192.168.1.10
  ssh_user: ubuntu
  ssh_port: 22
  ssh_key_path: /path/to/key
  nginx_config_path: /etc/nginx/conf.d
  nginx_reload_command: sudo systemctl reload nginx

- name: cdn-node-2
  ip_address: 192.168.1.11
  ssh_user: ubuntu
  ssh_password: password123  # Alternative to SSH key
  nginx_config_path: /etc/nginx/conf.d
  nginx_reload_command: sudo systemctl reload nginx
```

### Manual Node Discovery

Trigger node discovery manually:

```bash
# Using default nodes.yaml location
docker compose run --rm manage discover-nodes

# Specify custom YAML file
docker compose run --rm manage discover-nodes --yaml-path=/path/to/nodes.yaml

# Disable auto-activation
docker compose run --rm manage discover-nodes --no-activate
```

## Post-Installation

### Verify Installation

1. Check that containers are running:
   ```bash
   docker compose ps
   ```

2. Access the web interface:
   - Open http://localhost:5002
   - Log in with your admin credentials

3. Run system health check:
   ```bash
   docker compose run --rm manage system-check
   ```

### Next Steps

- Configure your first proxy node
- Add SSL certificates
- Create your first site
- Set up monitoring

See the [Configuration Guide](/guide/configuration) for detailed configuration options.

## Troubleshooting Installation

### Port Already in Use

If port 5002 is already in use, change the port mapping in `docker-compose.yml`:

```yaml
ports:
  - "5003:5000"  # Use port 5003 instead
```

### Permission Denied Errors

Add your user to the docker group:

```bash
sudo usermod -aG docker $USER
newgrp docker
```

### Container Build Failures

Clear Docker cache and rebuild:

```bash
docker compose down
docker compose build --no-cache
docker compose up -d
```

For more troubleshooting tips, see the [Troubleshooting Guide](/guide/troubleshooting).
