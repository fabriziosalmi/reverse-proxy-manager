FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libffi-dev \
    libssl-dev \
    openssh-client \
    git \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for better caching
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application
COPY . .

# Make scripts executable
RUN chmod +x manage.py run.py scripts/docker-entrypoint.sh

# Create necessary directories
RUN mkdir -p backups instance

# Expose the port the app runs on
EXPOSE 5000

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1
ENV FLASK_APP=run.py

# Use the entrypoint script
ENTRYPOINT ["/app/scripts/docker-entrypoint.sh"]

# Remove the CMD instruction to prevent running the app directly from the Dockerfile
# Command to run the application with Gunicorn
# CMD ["gunicorn", "--bind", "0.0.0.0:5002", "--workers", "4", "run:app"]