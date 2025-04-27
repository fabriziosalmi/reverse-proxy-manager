#!/bin/bash
set -e

# Wait for services to be ready
echo "Starting Italia CDN Proxy"

# Create database if it doesn't exist
if [ ! -f "instance/app.db" ]; then
    echo "Initializing database..."
    mkdir -p instance
    python manage.py init-db
    echo "Database initialized."
fi

# Check if any admin user exists
ADMIN_COUNT=$(python manage.py shell -c "from app.models.models import User; print(User.query.filter_by(role='admin').count())" 2>/dev/null || echo "0")

# Create default admin if no admin exists
if [ "$ADMIN_COUNT" = "0" ]; then
    echo "No admin user found. Creating default admin..."
    
    # Use environment variables if provided, otherwise use defaults
    ADMIN_USERNAME=${ADMIN_USERNAME:-admin}
    ADMIN_EMAIL=${ADMIN_EMAIL:-admin@italiacdn.local}
    ADMIN_PASSWORD=${ADMIN_PASSWORD:-Admin123!}
    
    echo "Creating admin user: $ADMIN_USERNAME ($ADMIN_EMAIL)"
    python manage.py create-admin --username "$ADMIN_USERNAME" --email "$ADMIN_EMAIL" --password "$ADMIN_PASSWORD"
    echo "Default admin created. Please change password immediately after first login."
fi

# Execute the command passed to docker
exec "$@"