# API Reference

The Reverse Proxy Manager provides both a web interface and command-line management tools.

## Management CLI

The management CLI is accessed through Docker Compose using the `manage` service.

### Database Management

#### Initialize Database

Initialize a new database with required tables and default data.

```bash
docker compose run --rm manage init-db
```

**Options:** None

#### Backup Database

Create a backup of the database.

```bash
docker compose run --rm manage backup-db
```

**Output:** SQL dump to stdout (redirect to file)

**Example:**
```bash
docker compose run --rm manage backup-db > backup_$(date +%Y%m%d).sql
```

#### Restore Database

Restore database from a backup file.

```bash
docker compose run --rm manage restore-db --input=BACKUP_FILE
```

**Arguments:**
- `--input`: Path to backup SQL file

**Example:**
```bash
docker compose run --rm manage restore-db --input=/backups/backup_20231205.sql
```

### User Management

#### Create Admin User

Create a new administrator user interactively.

```bash
docker compose run --rm manage create-admin
```

**Prompts:**
- Username
- Email
- Password (must contain uppercase, lowercase, and digits)

#### List Users

Display all users in the system.

```bash
docker compose run --rm manage list-users
```

**Output:** Table with user ID, username, email, and role

### Node Management

#### List Nodes

Display all configured proxy nodes.

```bash
docker compose run --rm manage list-nodes
```

**Output:** Table with node ID, name, IP address, type, and status

#### Discover Nodes

Discover and register nodes from YAML configuration.

```bash
docker compose run --rm manage discover-nodes [OPTIONS]
```

**Options:**
- `--yaml-path`: Path to nodes YAML file (default: config/nodes.yaml)
- `--no-activate`: Don't automatically activate discovered nodes

**Examples:**
```bash
# Use default configuration
docker compose run --rm manage discover-nodes

# Use custom YAML file
docker compose run --rm manage discover-nodes --yaml-path=/custom/nodes.yaml

# Discover without activating
docker compose run --rm manage discover-nodes --no-activate
```

### Site Management

#### List Sites

Display all configured sites.

```bash
docker compose run --rm manage list-sites
```

**Output:** Table with site ID, domain, backend, and status

### System Management

#### System Health Check

Run a comprehensive system health check.

```bash
docker compose run --rm manage system-check
```

**Checks:**
- Database connectivity
- Required directories exist
- Services are accessible
- Configuration validity

**Output:** Status report with any issues found

## Node Configuration YAML Schema

Configuration file for automatic node discovery.

### Schema

```yaml
- name: string              # Required: Unique node identifier
  ip_address: string        # Required: IPv4 or IPv6 address
  ssh_user: string          # Required: SSH username
  ssh_port: integer         # Optional: SSH port (default: 22)
  ssh_key_path: string      # Optional: Path to SSH private key
  ssh_password: string      # Optional: SSH password (if not using key)
  proxy_type: string        # Optional: nginx, caddy, or traefik (default: nginx)
  nginx_config_path: string # Optional: Config directory path
  nginx_reload_command: string  # Optional: Command to reload service
```

### Example

```yaml
- name: production-nginx-1
  ip_address: 203.0.113.10
  ssh_user: ubuntu
  ssh_port: 22
  ssh_key_path: /app/keys/prod1.pem
  proxy_type: nginx
  nginx_config_path: /etc/nginx/conf.d
  nginx_reload_command: sudo systemctl reload nginx

- name: production-caddy-1
  ip_address: 203.0.113.20
  ssh_user: ubuntu
  ssh_port: 22
  ssh_key_path: /app/keys/prod2.pem
  proxy_type: caddy
  nginx_config_path: /etc/caddy/conf.d
  nginx_reload_command: sudo systemctl reload caddy

- name: staging-nginx-1
  ip_address: 192.168.1.10
  ssh_user: ubuntu
  ssh_password: SecurePass123!
  proxy_type: nginx
```

## Environment Variables Reference

### Required Variables

| Variable | Type | Description | Example |
|----------|------|-------------|---------|
| `ADMIN_USERNAME` | string | Default admin username | `admin` |
| `ADMIN_EMAIL` | string | Admin email address | `admin@example.com` |
| `ADMIN_PASSWORD` | string | Admin password | `Admin123!` |
| `SECRET_KEY` | string | Flask secret key | `random-secure-key` |

### Optional Variables

| Variable | Type | Default | Description |
|----------|------|---------|-------------|
| `FLASK_ENV` | string | `development` | Application environment |
| `DEBUG` | boolean | `True` | Enable debug mode |
| `LOG_LEVEL` | string | `INFO` | Logging level (DEBUG, INFO, WARNING, ERROR, CRITICAL) |
| `AUTO_NODE_DISCOVERY` | boolean | `false` | Enable automatic node discovery |
| `NODES_YAML_PATH` | string | `config/nodes.yaml` | Path to nodes YAML file |
| `AUTO_ACTIVATE_DISCOVERED_NODES` | boolean | `true` | Auto-activate discovered nodes |
| `RATELIMIT_STORAGE_URI` | string | None | Memcached URI for rate limiting |
| `PROXY_FIX` | boolean | `False` | Enable proxy fix middleware |

## Web Interface Endpoints

### Authentication

**Login**
- Path: `/login`
- Method: POST
- Body: `username`, `password`
- Response: Redirect to dashboard or error message

**Logout**
- Path: `/logout`
- Method: GET
- Response: Redirect to login page

### Admin Endpoints

**Dashboard**
- Path: `/admin/dashboard`
- Method: GET
- Auth: Required (Admin)
- Description: Admin overview with statistics

**Site Management**
- Path: `/admin/sites`
- Method: GET
- Auth: Required (Admin)
- Description: List all sites

**Add Site**
- Path: `/admin/sites/add`
- Method: GET, POST
- Auth: Required (Admin)
- Description: Create new site

**Edit Site**
- Path: `/admin/sites/<id>/edit`
- Method: GET, POST
- Auth: Required (Admin)
- Description: Modify existing site

**Delete Site**
- Path: `/admin/sites/<id>/delete`
- Method: POST
- Auth: Required (Admin)
- Description: Remove site

**Node Management**
- Path: `/admin/nodes`
- Method: GET
- Auth: Required (Admin)
- Description: List all nodes

**User Management**
- Path: `/admin/users`
- Method: GET
- Auth: Required (Admin)
- Description: List all users

### Client Endpoints

**Dashboard**
- Path: `/client/dashboard`
- Method: GET
- Auth: Required (Client)
- Description: Client overview

**My Sites**
- Path: `/client/sites`
- Method: GET
- Auth: Required (Client)
- Description: List user's sites

## Database Models

### User Model

```python
class User:
    id: Integer (Primary Key)
    username: String (Unique, Required)
    email: String (Unique, Required)
    password_hash: String (Required)
    role: String (admin/client)
    created_at: DateTime
    updated_at: DateTime
```

### Node Model

```python
class Node:
    id: Integer (Primary Key)
    name: String (Unique, Required)
    ip_address: String (Required)
    proxy_type: String (nginx/caddy/traefik)
    ssh_user: String (Required)
    ssh_port: Integer (Default: 22)
    ssh_key_path: String
    ssh_password: String (Encrypted)
    status: String (active/inactive)
    is_discovered: Boolean (Default: False)
    created_at: DateTime
    updated_at: DateTime
```

### Site Model

```python
class Site:
    id: Integer (Primary Key)
    user_id: Integer (Foreign Key)
    domain: String (Required)
    backend_ip: String (Required)
    backend_port: Integer (Required)
    ssl_enabled: Boolean
    waf_level: String (basic/medium/strict)
    cache_enabled: Boolean
    blocked: Boolean (Default: False)
    created_at: DateTime
    updated_at: DateTime
```

### Deployment Model

```python
class Deployment:
    id: Integer (Primary Key)
    site_id: Integer (Foreign Key)
    node_id: Integer (Foreign Key)
    status: String (pending/success/failed)
    config_version: String
    deployed_at: DateTime
    error_message: String
```

## Error Codes

### HTTP Status Codes

- `200 OK`: Request successful
- `201 Created`: Resource created successfully
- `400 Bad Request`: Invalid request data
- `401 Unauthorized`: Authentication required
- `403 Forbidden`: Insufficient permissions
- `404 Not Found`: Resource not found
- `500 Internal Server Error`: Server error

### Application Error Codes

- `AUTH_001`: Invalid credentials
- `AUTH_002`: Session expired
- `AUTH_003`: Insufficient permissions
- `SITE_001`: Invalid site configuration
- `SITE_002`: Domain already exists
- `NODE_001`: Cannot connect to node
- `NODE_002`: Invalid node configuration
- `SSL_001`: Certificate provisioning failed
- `SSL_002`: Certificate validation failed
- `DEPLOY_001`: Deployment failed
- `DEPLOY_002`: Configuration test failed

## Rate Limiting

Default rate limits are applied to prevent abuse:

- Login endpoint: 5 requests per minute
- API endpoints: 100 requests per minute
- Admin actions: 60 requests per minute

Configure rate limiting with `RATELIMIT_STORAGE_URI` environment variable.

## WebSocket Support

Currently not implemented. Future versions may include WebSocket support for real-time updates.

## Versioning

The API follows semantic versioning. Check the application version with:

```bash
docker compose run --rm manage --version
```

## Future API Development

Planned API enhancements:

- RESTful API endpoints
- API authentication tokens
- Webhook support
- GraphQL interface
- OpenAPI/Swagger documentation

For the latest API updates, check the [GitHub repository](https://github.com/fabriziosalmi/reverse-proxy-manager).

