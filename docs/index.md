# Reverse Proxy Manager

A centralized proxy management system for distributed proxy nodes, providing robust management of content delivery infrastructure.

> **⚠️ DOCKER REQUIRED**: This application must be run using Docker and Docker Compose. Running the application outside of Docker is not supported and will lead to unexpected behavior.

## Overview

Reverse Proxy Manager is a comprehensive solution for managing multiple proxy nodes from a centralized interface. It simplifies deployment, configuration, and monitoring of proxy infrastructure at scale, making it ideal for content delivery networks, load balancing, and distributed web hosting environments.

The system supports multiple reverse proxy types (Nginx, Caddy, and Traefik), allowing you to choose the right tool for each use case while managing everything from a single dashboard. This multi-proxy capability gives you flexibility to optimize for different requirements across your infrastructure.

## Features

- **Centralized Management**: Control multiple proxy nodes from a single dashboard
- **Multi-Proxy Support**: Mix and match Nginx, Caddy, and Traefik nodes in your infrastructure
- **SSL Management**: Automated SSL certificate provisioning and renewal
- **DNS Provider Integration**: Support for multiple DNS providers (CloudFlare, Route53, DigitalOcean, GoDaddy)
- **Web Application Firewall**: Built-in WAF for enhanced security with advanced configuration options
- **Geographic Access Control**: Block or allow traffic based on country of origin (GeoIP)
- **Cache Configuration**: Fine-grained control over caching policies
- **Version Control**: Track and roll back configuration changes
- **Site Blocking**: Temporarily block sites across all nodes
- **User Management**: Role-based access control (admin/client)
- **Theme Support**: Built-in light/dark theme
- **Real-time Monitoring**: Live statistics for nodes including CPU, memory, connections
- **Deployment Tracking**: Comprehensive logs for all deployments
- **Automatic Node Discovery**: Add and manage nodes via YAML configuration
- **Rate Limiting**: Configurable request rate limiting with memcached storage

## Getting Started

Check out the [Getting Started Guide](/guide/getting-started) to learn how to set up and use the Reverse Proxy Manager.
