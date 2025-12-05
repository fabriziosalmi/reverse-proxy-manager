# Reverse Proxy Manager

A centralized proxy management system for distributed proxy nodes, providing robust management of content delivery infrastructure.

![Version](https://img.shields.io/badge/version-0.0.1-blue)
![Python](https://img.shields.io/badge/python-3.12+-green)
![Flask](https://img.shields.io/badge/flask-2.3+-green)
![License](https://img.shields.io/badge/license-MIT-yellow)
![Docker](https://img.shields.io/badge/docker-required-blue)

> **⚠️ DOCKER REQUIRED**: This application must be run using Docker and Docker Compose. Running the application outside of Docker is not supported and will lead to unexpected behavior.

## Overview

Reverse Proxy Manager is a comprehensive solution for managing multiple proxy nodes from a centralized interface. It simplifies deployment, configuration, and monitoring of proxy infrastructure at scale, making it ideal for content delivery networks, load balancing, and distributed web hosting environments.

The system supports multiple reverse proxy types (Nginx, Caddy, and Traefik), allowing you to choose the right tool for each use case while managing everything from a single dashboard. This multi-proxy capability gives you flexibility to optimize for different requirements across your infrastructure.

## Features

### Core Management
- **Centralized Management**: Control multiple proxy nodes from a single dashboard
- **Multi-Proxy Support**: Mix and match Nginx, Caddy, and Traefik nodes in your infrastructure
- **Automatic Node Discovery**: Add and manage nodes via YAML configuration
- **Real-time Monitoring**: Live statistics for nodes including CPU, memory, connections
- **Deployment Tracking**: Comprehensive logs for all deployments

### Security Features
- **SSL Management**: Automated SSL certificate provisioning and renewal
- **DNS Provider Integration**: Support for multiple DNS providers (CloudFlare, Route53, DigitalOcean, GoDaddy)
- **Web Application Firewall**: Built-in WAF for enhanced security with advanced configuration options
- **Geographic Access Control**: Block or allow traffic based on country of origin (GeoIP)
- **Rate Limiting**: Configurable request rate limiting with memcached storage

### Performance & Configuration
- **Cache Configuration**: Fine-grained control over caching policies
- **Version Control**: Track and roll back configuration changes
- **Site Blocking**: Temporarily block sites across all nodes
- **Custom Nginx Configuration**: Add specialized directives for each site

### User Management
- **User Management**: Role-based access control (admin/client)
- **Theme Support**: Built-in light/dark theme

## Quick Start

Get started with Reverse Proxy Manager in just a few steps:

1. **Prerequisites**: Docker Engine and Docker Compose
2. **Clone**: `git clone https://github.com/fabriziosalmi/reverse-proxy-manager.git`
3. **Configure**: Copy `.env.example` to `.env` and customize
4. **Run**: `docker compose up app-dev`
5. **Access**: Open http://localhost:5002

For detailed instructions, see the [Getting Started Guide](/guide/getting-started).

## Documentation

- [Getting Started](/guide/getting-started) - Installation and basic setup
- [Installation](/guide/installation) - Detailed installation guide
- [Configuration](/guide/configuration) - Configure WAF, SSL, caching, and more
- [Deployment](/guide/deployment) - Production deployment guide
- [Architecture](/guide/architecture) - System architecture overview
- [Troubleshooting](/guide/troubleshooting) - Common issues and solutions
- [API Reference](/api-reference) - API documentation

## Support

For support and questions:
- [GitHub Issues](https://github.com/fabriziosalmi/reverse-proxy-manager/issues)
- [Documentation](https://fabriziosalmi.github.io/reverse-proxy-manager/)

## License

This project is licensed under the MIT License.
