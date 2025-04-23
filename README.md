# Italia CDN Proxy Manager

A centralized proxy management system for distributed CDN nodes.

## Features

- Manage multiple proxy nodes from a centralized dashboard
- Configure HTTP and HTTPS sites with automatic SSL certificate management
- Web Application Firewall (WAF) protection for sites
- User management with role-based access control
- Deployment tracking and logs
- Backup and restore functionality

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