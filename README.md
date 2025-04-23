# Italia CDN Proxy Manager

A centralized proxy management system for distributed CDN nodes.

## Features

- Manage multiple proxy nodes from a centralized dashboard
- Configure HTTP and HTTPS sites with automatic SSL certificate management
- Web Application Firewall (WAF) protection for sites
- User management with role-based access control
- Deployment tracking and logs
- Backup and restore functionality
- Automatic Node Discovery from YAML configuration

## Docker Setup

The application can be run using Docker in both development and production environments.

### Prerequisites

- Docker and Docker Compose installed on your system
- Git (for cloning the repository)

### Quick Start

1. Clone the repository:
   ```bash
   git clone https://github.com/yourusername/italiacdn-proxy.git
   cd italiacdn-proxy
   ```

2. Start the application in development mode:
   ```bash
   docker-compose up app-dev
   ```

3. Or start the application in production mode:
   ```bash
   docker-compose up app-prod
   ```

4. Access the application at http://localhost:5000

### Environment Configuration

You can configure the application by setting environment variables in the docker-compose.yml file or by creating a `.env` file.

Example `.env` file:
```
FLASK_ENV=development
ADMIN_USERNAME=admin
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=secure_password
SECRET_KEY=your_secure_secret_key
AUTO_NODE_DISCOVERY=true
NODES_YAML_PATH=/path/to/custom/nodes.yaml
```

### Management Commands

The application includes various management commands that can be run through the `manage.py` script:

```bash
# Initialize the database
docker-compose run --rm manage init-db

# Create an admin user
docker-compose run --rm manage create-admin

# List all users
docker-compose run --rm manage list-users

# List all nodes
docker-compose run --rm manage list-nodes

# List all sites
docker-compose run --rm manage list-sites

# Backup the database
docker-compose run --rm manage backup-db

# Restore the database from a backup
docker-compose run --rm manage restore-db --input=backup.sql

# Discover nodes from YAML configuration
docker-compose run --rm manage discover-nodes

# Create a migration for the Node model
docker-compose run --rm manage create-migration-is-discovered
```

## Automatic Node Discovery

Italia CDN Proxy now supports automatic discovery of proxy nodes from a YAML configuration file. This feature allows you to easily add and manage multiple nodes without manually configuring each one in the admin interface.

### How It Works

1. Nodes are defined in a YAML file (`config/nodes.yaml` by default)
2. When the application starts with auto-discovery enabled, it reads this file and adds/updates nodes in the database
3. Discovered nodes are marked as "discovered" in the database, so the system knows they're maintained via the YAML file
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

You can also trigger node discovery manually using the CLI command:

```bash
# Using default nodes.yaml location
./manage.py discover-nodes

# Specifying a custom YAML file
./manage.py discover-nodes --yaml-path=/path/to/nodes.yaml

# Disable auto-activation of discovered nodes
./manage.py discover-nodes --no-activate
```

### Migration for Existing Installations

If you're upgrading from a previous version, you'll need to run the migration to add the `is_discovered` field to your Node model:

```bash
./manage.py create-migration-is-discovered
flask db upgrade
```

## Development

### Local Development Setup

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
   ./manage.py init-db
   ```

4. Run the application:
   ```bash
   ./run.py
   ```

### Docker Development

For development with Docker, the application code is mounted as a volume, so changes to the code will be reflected immediately:

```bash
docker-compose up app-dev
```

## Production Deployment

For production deployment, use the production service:

```bash
docker-compose up -d app-prod
```

This will start the application with Gunicorn as the WSGI server.

## License

[Your License]