# Getting Started

This guide will help you set up and run the Reverse Proxy Manager using Docker.

## Prerequisites

Before you begin, ensure you have the following installed:

- **Docker Engine** (version 20.10.0 or higher)
- **Docker Compose** (V2 compatible)
- **Git** (for cloning the repository)

> **Important**: This application **must** be run using Docker Compose in both development and production environments. Running outside of Docker is not supported.

## Installation

### 1. Clone the Repository

```bash
git clone https://github.com/fabriziosalmi/reverse-proxy-manager.git
cd reverse-proxy-manager
```

### 2. Configure Environment Variables

Create a `.env` file with your configuration:

```bash
cp .env.example .env
```

Edit the `.env` file with your preferred settings:

```env
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

### 3. Start the Application

For development:

```bash
docker compose up app-dev
```

For production:

```bash
docker compose up -d app-prod
```

> **Note**: If you're using Docker Compose v1, use `docker-compose` instead of `docker compose`.

### 4. Access the Application

Open your browser and navigate to:
- Development: http://localhost:5002
- Production: http://localhost:5002

Log in with the credentials you specified in the `.env` file.

## Initial Setup

### Create Admin User

If you need to create an admin user manually:

```bash
docker compose run --rm manage create-admin
```

### Initialize Database

The database is automatically initialized on first run. To manually initialize:

```bash
docker compose run --rm manage init-db
```

### Discover Nodes

If you have configured automatic node discovery, nodes will be added on startup. To manually trigger discovery:

```bash
docker compose run --rm manage discover-nodes
```

## Next Steps

Now that you have the Reverse Proxy Manager running:

1. **Add Proxy Nodes**: Configure your proxy nodes (Nginx, Caddy, or Traefik)
2. **Create Sites**: Add your first proxy site configuration
3. **Configure SSL**: Set up SSL certificates for your sites
4. **Monitor**: Check the dashboard for node statistics and deployment status

For more detailed information, check out:
- [Installation Guide](/guide/installation) - Detailed installation options
- [Configuration Guide](/guide/configuration) - Configure advanced features
- [Deployment Guide](/guide/deployment) - Production deployment best practices

## Quick Reference

### Common Commands

```bash
# Start development server
docker compose up app-dev

# Start production server
docker compose up -d app-prod

# View logs
docker compose logs -f app-dev

# Stop the application
docker compose down

# Database backup
docker compose run --rm manage backup-db

# List all nodes
docker compose run --rm manage list-nodes

# List all sites
docker compose run --rm manage list-sites

# System health check
docker compose run --rm manage system-check
```

## Troubleshooting

If you encounter issues:

1. **Check container logs**: `docker compose logs app-dev`
2. **Verify containers are running**: `docker compose ps`
3. **Rebuild containers**: `docker compose down && docker compose build --no-cache && docker compose up -d`

For more troubleshooting tips, see the [Troubleshooting Guide](/guide/troubleshooting).
