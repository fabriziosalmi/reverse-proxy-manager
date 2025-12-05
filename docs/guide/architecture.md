# Architecture

This document describes the architecture of the Reverse Proxy Manager.

## System Overview

The Reverse Proxy Manager is a centralized management system for distributed proxy nodes. It provides a web interface for configuring, deploying, and monitoring multiple reverse proxy servers.

```
┌─────────────────────────────────────────────────────────┐
│                    Web Interface                         │
│              (Flask + Bootstrap + jQuery)                │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────┴────────────────────────────────────┐
│              Application Layer (Flask)                   │
│  ┌──────────────┬──────────────┬──────────────────────┐ │
│  │   Admin      │   Client     │   API Endpoints      │ │
│  │   Panel      │   Panel      │                      │ │
│  └──────────────┴──────────────┴──────────────────────┘ │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────┴────────────────────────────────────┐
│                  Business Logic                          │
│  ┌─────────────┬──────────────┬─────────────────────┐  │
│  │  Site       │  Node        │  Deployment         │  │
│  │  Manager    │  Manager     │  Engine             │  │
│  └─────────────┴──────────────┴─────────────────────┘  │
│  ┌─────────────┬──────────────┬─────────────────────┐  │
│  │  SSL/TLS    │  WAF         │  Cache              │  │
│  │  Manager    │  Manager     │  Manager            │  │
│  └─────────────┴──────────────┴─────────────────────┘  │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────┴────────────────────────────────────┐
│                 Data Layer (SQLAlchemy)                  │
│  ┌──────────────────────────────────────────────────┐  │
│  │              SQLite/PostgreSQL                    │  │
│  │  (Sites, Nodes, Users, Deployments, Configs)     │  │
│  └──────────────────────────────────────────────────┘  │
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────┴────────────────────────────────────┐
│            Infrastructure Services                       │
│  ┌──────────────┬──────────────┬──────────────────────┐│
│  │  Memcached   │  Docker      │  SSH Connector       ││
│  │  (Rate Limit)│  Containers  │                      ││
│  └──────────────┴──────────────┴──────────────────────┘│
└────────────────────┬────────────────────────────────────┘
                     │
┌────────────────────┴────────────────────────────────────┐
│                  Proxy Nodes (Remote)                    │
│  ┌──────────────┬──────────────┬──────────────────────┐│
│  │  Nginx       │  Caddy       │  Traefik             ││
│  │  Nodes       │  Nodes       │  Nodes               ││
│  └──────────────┴──────────────┴──────────────────────┘│
└─────────────────────────────────────────────────────────┘
```

## Core Components

### 1. Web Interface Layer

**Technology Stack:**
- Flask (Python web framework)
- Bootstrap (UI framework)
- jQuery (JavaScript library)
- Jinja2 (Template engine)

**Responsibilities:**
- User authentication and authorization
- Admin and client dashboards
- Form handling and validation
- AJAX requests for dynamic updates

**Key Features:**
- Role-based access control (Admin/Client)
- Responsive design
- Dark/light theme support
- Real-time updates

### 2. Application Layer

**Flask Application Structure:**
```
app/
├── __init__.py          # Application factory
├── models/              # Database models
│   ├── user.py
│   ├── node.py
│   ├── site.py
│   └── deployment.py
├── routes/              # Route handlers
│   ├── admin/           # Admin routes
│   ├── client/          # Client routes
│   └── api/             # API endpoints
├── services/            # Business logic
│   ├── node_service.py
│   ├── site_service.py
│   ├── ssl_service.py
│   └── deployment_service.py
├── templates/           # Jinja2 templates
└── static/              # CSS, JS, images
```

**Core Services:**

**Node Service**
- Node registration and management
- Node health monitoring
- SSH connectivity
- Command execution on remote nodes

**Site Service**
- Site configuration management
- Multi-site deployment
- Configuration versioning
- Site blocking/unblocking

**SSL Service**
- Certificate provisioning (Let's Encrypt)
- Certificate renewal
- DNS challenge validation
- Self-signed certificate generation

**Deployment Service**
- Configuration generation
- Remote deployment via SSH
- Deployment validation
- Rollback capabilities

### 3. Configuration Generation

**Template System:**
```
nginx_templates/
├── server_block.conf.j2      # Main server configuration
├── ssl_config.conf.j2        # SSL/TLS configuration
├── waf_config.conf.j2        # WAF rules
├── cache_config.conf.j2      # Caching configuration
└── geoip_config.conf.j2      # Geographic restrictions
```

**Configuration Pipeline:**
1. User inputs configuration through web UI
2. Data validated and stored in database
3. Template engine renders Nginx/Caddy/Traefik config
4. Configuration tested for syntax errors
5. Deployed to remote nodes via SSH
6. Service reloaded on remote nodes

### 4. Data Layer

**Database Schema:**

**Users Table**
- id, username, email, password_hash
- role (admin/client)
- created_at, updated_at

**Nodes Table**
- id, name, ip_address, proxy_type
- ssh_user, ssh_port, ssh_key_path
- status (active/inactive)
- is_discovered, created_at

**Sites Table**
- id, user_id, domain, backend_ip, backend_port
- ssl_enabled, waf_level, cache_enabled
- blocked, created_at, updated_at

**Deployments Table**
- id, site_id, node_id, status
- config_version, deployed_at
- error_message

**SSL Certificates Table**
- id, site_id, provider, status
- expires_at, auto_renew

**ORM: SQLAlchemy**
- Database abstraction
- Migration support (Flask-Migrate/Alembic)
- Relationship management
- Query optimization

### 5. Background Tasks

**Task Processing:**
- SSL certificate renewal (scheduled)
- Node health checks (periodic)
- Configuration synchronization
- Deployment queue processing

**Implementation:**
- Synchronous for simple tasks
- Consider Celery for production at scale

### 6. SSH Connector

**Paramiko-based SSH Client:**
```python
class NodeConnector:
    def connect(node):
        # Establish SSH connection
    
    def deploy_config(node, config):
        # Upload configuration file
    
    def reload_service(node):
        # Reload proxy service
    
    def get_stats(node):
        # Retrieve node statistics
    
    def test_config(node, config):
        # Test configuration syntax
```

**Security:**
- SSH key-based authentication preferred
- Password authentication fallback
- Connection pooling for efficiency
- Timeout handling

## Data Flow

### Site Deployment Flow

```
1. User creates/updates site configuration
   ↓
2. Validation and database update
   ↓
3. Configuration template rendering
   ↓
4. Syntax validation
   ↓
5. For each target node:
   a. SSH connection established
   b. Configuration uploaded
   c. Syntax test on remote node
   d. Service reload
   e. Deployment record created
   ↓
6. User notification (success/failure)
```

### SSL Certificate Flow

```
1. User requests SSL certificate
   ↓
2. Select validation method (HTTP-01/DNS-01)
   ↓
3. Generate certificate request
   ↓
4. DNS provider API call (if DNS-01)
   ↓
5. Let's Encrypt validation
   ↓
6. Certificate retrieval and storage
   ↓
7. Deploy to all nodes
   ↓
8. Schedule automatic renewal
```

### Node Discovery Flow

```
1. Application startup or manual trigger
   ↓
2. Read nodes.yaml file
   ↓
3. For each node:
   a. Check if exists in database
   b. Create or update node record
   c. Mark as discovered
   d. Activate if configured
   ↓
4. Log discovery results
```

## Security Architecture

### Authentication & Authorization

**User Authentication:**
- Password hashing (Werkzeug security)
- Session management (Flask-Login)
- Password strength requirements
- Brute-force protection (rate limiting)

**Authorization:**
- Role-based access control
- Admin: Full access
- Client: Limited to own resources

### Communication Security

**Web Interface:**
- HTTPS recommended for production
- Secure session cookies
- CSRF protection
- XSS prevention

**SSH Communication:**
- Encrypted channels
- Key-based authentication
- Host key verification
- Connection timeout

### Data Security

**Sensitive Data:**
- Passwords hashed (not stored plaintext)
- SSH keys stored securely
- API tokens encrypted
- Database encryption at rest (optional)

**Input Validation:**
- Form validation on client and server
- SQL injection prevention (ORM)
- Command injection prevention
- Path traversal protection

## Scalability Considerations

### Horizontal Scaling

**Application Instances:**
- Stateless application design
- Load balancer in front
- Shared database
- Shared session storage (Redis)

**Database Scaling:**
- Read replicas for reports
- Connection pooling
- Query optimization
- Consider PostgreSQL for production

### Vertical Scaling

**Resource Optimization:**
- Efficient database queries
- Caching frequently accessed data
- Asynchronous task processing
- Connection reuse

### Performance Optimization

**Caching Strategy:**
- In-memory caching for node stats
- Template caching
- Database query caching
- Static asset CDN

**Background Processing:**
- Offload heavy tasks
- Queue-based processing
- Batch operations
- Scheduled jobs

## Monitoring & Observability

### Application Metrics

**Key Metrics:**
- Request count and latency
- Active users and sessions
- Deployment success rate
- Error rate

**Node Metrics:**
- CPU, memory, disk usage
- Active connections
- Proxy service status
- Certificate expiry dates

### Logging

**Log Levels:**
- DEBUG: Development debugging
- INFO: General information
- WARNING: Warning messages
- ERROR: Error conditions
- CRITICAL: Critical failures

**Log Storage:**
- Application logs (stdout/file)
- Deployment logs (database)
- Audit logs (database)
- Node logs (remote)

### Health Checks

**Application Health:**
```python
@app.route('/health')
def health_check():
    return {
        'status': 'healthy',
        'database': db_check(),
        'memcached': cache_check(),
        'version': app_version
    }
```

**Node Health:**
- SSH connectivity
- Service status
- Resource availability
- Certificate validity

## Deployment Architecture

### Development Environment

```
Docker Compose:
- app-dev (Flask development server)
- db (SQLite)
- memcached
```

### Production Environment

```
Docker Compose:
- app-prod (Gunicorn)
- db (PostgreSQL recommended)
- memcached
- nginx-lb (optional load balancer)
```

### High Availability Setup

```
Load Balancer (HAProxy/Nginx)
├── App Instance 1
├── App Instance 2
└── App Instance 3

Database Cluster
├── Primary (read/write)
└── Replicas (read-only)

Shared Storage
├── SSL Certificates
├── Configuration Files
└── SSH Keys
```

## Technology Stack Summary

| Component | Technology | Purpose |
|-----------|-----------|---------|
| Backend | Python 3.12+, Flask | Web application framework |
| Database | SQLite/PostgreSQL | Data persistence |
| ORM | SQLAlchemy | Database abstraction |
| Templates | Jinja2 | HTML rendering |
| Frontend | Bootstrap, jQuery | User interface |
| SSH | Paramiko | Remote node management |
| Caching | Memcached | Rate limiting, performance |
| Container | Docker | Application containerization |
| Proxy Support | Nginx, Caddy, Traefik | Reverse proxy engines |
| SSL | Let's Encrypt | Certificate management |
| WAF | ModSecurity | Security layer |

## Future Architecture Enhancements

### Planned Improvements

1. **Microservices Architecture**
   - Separate deployment service
   - Dedicated SSL service
   - Monitoring service

2. **Message Queue**
   - RabbitMQ/Redis for task distribution
   - Better async processing
   - Job retry mechanisms

3. **API Gateway**
   - RESTful API
   - GraphQL support
   - API versioning

4. **Container Orchestration**
   - Kubernetes support
   - Auto-scaling
   - Service mesh

5. **Enhanced Monitoring**
   - Prometheus integration
   - Grafana dashboards
   - Distributed tracing

For implementation details, see the codebase documentation and inline comments.
