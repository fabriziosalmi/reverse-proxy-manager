# Getting Started

## Docker Setup

The application **must** be run using Docker Compose in both development and production environments.

### Prerequisites

- Docker Engine (version 20.10.0 or higher)
- Docker Compose (V2 compatible)
- Git (for cloning the repository)

## Quick Start

1. **Clone the repository:**
   \`\`\`bash
   git clone https://github.com/fabriziosalmi/reverse-proxy-manager.git
   cd reverse-proxy-manager
   \`\`\`

2. **Create a `.env` file:**
   \`\`\`bash
   cp .env.example .env
   # Edit .env with your preferred settings
   \`\`\`

3. **Start the application:**

   In development mode:
   \`\`\`bash
   docker compose up app-dev
   \`\`\`

   Or in production mode:
   \`\`\`bash
   docker compose up -d app-prod
   \`\`\`

   > Note: If you're using an older version of Docker Compose (v1), use `docker-compose` instead of `docker compose`.

4. **Access the application:**
   Open http://localhost:5002 in your browser.

## Docker Management Commands

The application includes various management commands that must be run within Docker:

\`\`\`bash
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
\`\`\`
