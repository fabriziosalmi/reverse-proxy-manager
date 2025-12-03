# Configuration

## Environment Configuration

Configure the application by setting environment variables in the `.env` file, which will be used by Docker Compose.

### Example `.env` file

```bash
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

## Production Configuration

Recommended production settings:

```bash
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
