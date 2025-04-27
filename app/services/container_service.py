import docker
import os
import time
import logging
from flask import current_app
from app.models.models import db, Node, Site, SiteNode, DeploymentLog
from app.services.logger_service import log_activity
from datetime import datetime
import paramiko
import tempfile
import shutil

class ContainerService:
    """Service for managing containerized Nginx instances"""
    
    @staticmethod
    def get_docker_client(node):
        """Get a Docker client for the node
        
        Args:
            node: Node object with container connection details
            
        Returns:
            docker.DockerClient or None if connection fails
        """
        try:
            if not node.is_container_node:
                log_activity('error', f"Node {node.name} is not configured for containers", 'node', node.id)
                return None
                
            # For local Docker socket
            if node.container_connection_type == 'socket':
                return docker.DockerClient(base_url='unix:///var/run/docker.sock')
                
            elif node.container_connection_type == 'tcp':
                # For TCP connection (with TLS if needed)
                if node.container_tls_enabled:
                    tls_config = docker.tls.TLSConfig(
                        client_cert=(node.container_cert_path, node.container_key_path),
                        ca_cert=node.container_ca_path,
                        verify=True
                    )
                    return docker.DockerClient(
                        base_url=f"tcp://{node.ip_address}:{node.container_api_port}", 
                        tls=tls_config
                    )
                else:
                    return docker.DockerClient(
                        base_url=f"tcp://{node.ip_address}:{node.container_api_port}"
                    )
                
            elif node.container_connection_type == 'ssh':
                # For SSH tunneling to Docker socket
                ssh_client = paramiko.SSHClient()
                ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                # Connect using key or password
                if node.ssh_key_path:
                    ssh_client.connect(
                        hostname=node.ip_address,
                        port=node.ssh_port or 22,
                        username=node.ssh_user,
                        key_filename=node.ssh_key_path,
                        timeout=10
                    )
                else:
                    ssh_client.connect(
                        hostname=node.ip_address,
                        port=node.ssh_port or 22,
                        username=node.ssh_user,
                        password=node.ssh_password,
                        timeout=10
                    )
                
                # Create a transport channel
                transport = ssh_client.get_transport()
                
                # Create tunnel from local port to remote Docker socket
                local_port = 2375
                remote_socket = '/var/run/docker.sock'
                transport.request_port_forward('', local_port)
                
                # Connect to Docker through the tunnel
                return docker.DockerClient(base_url=f'tcp://localhost:{local_port}')
            
            else:
                log_activity('error', f"Unknown container connection type: {node.container_connection_type}", 'node', node.id)
                return None
                
        except Exception as e:
            log_activity('error', f"Failed to connect to Docker on node {node.name}: {str(e)}")
            return None
    
    @staticmethod
    def check_container_status(node):
        """Check if Nginx container is running on the node
        
        Args:
            node: Node object with container details
            
        Returns:
            dict: Status information about the container
        """
        try:
            client = ContainerService.get_docker_client(node)
            if not client:
                return {
                    'status': 'error',
                    'message': 'Failed to connect to Docker daemon',
                    'container_running': False
                }
            
            # Try to get the container by name
            container_name = node.container_name or f"nginx-proxy-{node.id}"
            containers = client.containers.list(all=True, filters={"name": container_name})
            
            if not containers:
                return {
                    'status': 'not_found',
                    'message': f'Container {container_name} not found',
                    'container_running': False
                }
            
            container = containers[0]
            
            # Get container stats
            stats = container.stats(stream=False)
            
            # Calculate CPU usage percentage
            cpu_delta = stats.get('cpu_stats', {}).get('cpu_usage', {}).get('total_usage', 0) - \
                         stats.get('precpu_stats', {}).get('cpu_usage', {}).get('total_usage', 0)
            system_delta = stats.get('cpu_stats', {}).get('system_cpu_usage', 0) - \
                          stats.get('precpu_stats', {}).get('system_cpu_usage', 0)
            
            cpu_percentage = 0
            if system_delta > 0 and cpu_delta > 0:
                cpu_count = len(stats.get('cpu_stats', {}).get('cpu_usage', {}).get('percpu_usage', []))
                cpu_percentage = (cpu_delta / system_delta) * cpu_count * 100
            
            # Calculate memory usage
            memory_usage = stats.get('memory_stats', {}).get('usage', 0)
            memory_limit = stats.get('memory_stats', {}).get('limit', 0)
            memory_percentage = 0
            if memory_limit > 0:
                memory_percentage = (memory_usage / memory_limit) * 100
            
            # Convert to readable formats
            memory_usage_mb = memory_usage / (1024 * 1024)
            memory_limit_mb = memory_limit / (1024 * 1024)
            
            return {
                'status': 'success',
                'container_status': container.status,
                'container_running': container.status == 'running',
                'container_id': container.id,
                'container_name': container.name,
                'image': container.image.tags[0] if container.image.tags else container.image.id,
                'created': container.attrs.get('Created', ''),
                'cpu_usage': f"{cpu_percentage:.2f}%",
                'memory_usage': f"{memory_usage_mb:.2f}MB / {memory_limit_mb:.2f}MB ({memory_percentage:.2f}%)",
                'ports': container.ports,
                'restart_count': container.attrs.get('RestartCount', 0),
                'logs_tail': container.logs(tail=10).decode('utf-8')
            }
            
        except Exception as e:
            return {
                'status': 'error',
                'message': str(e),
                'container_running': False
            }
    
    @staticmethod
    def setup_container(node, user_id=None):
        """Set up a new Nginx container on the node
        
        Args:
            node: Node object with container details
            user_id: Optional ID of the user performing the setup
            
        Returns:
            dict: Result of the container setup
        """
        try:
            client = ContainerService.get_docker_client(node)
            if not client:
                return {
                    'success': False,
                    'message': 'Failed to connect to Docker daemon'
                }
            
            # Set the container name if not specified
            container_name = node.container_name or f"nginx-proxy-{node.id}"
            
            # Check if container with this name already exists
            existing = client.containers.list(all=True, filters={"name": container_name})
            if existing:
                # If it exists but not running, start it
                container = existing[0]
                if container.status != 'running':
                    container.start()
                    log_activity('info', f"Started existing container {container_name} on node {node.name}", 'node', node.id, None, user_id)
                
                return {
                    'success': True,
                    'message': f"Container {container_name} already exists and is running",
                    'container_id': container.id
                }
            
            # Create necessary volumes and directories
            volumes = {
                # Main Nginx configuration
                f"{node.container_config_path}": {'bind': '/etc/nginx/conf.d', 'mode': 'rw'},
                # Let's Encrypt certificates
                f"{node.container_certs_path}": {'bind': '/etc/letsencrypt', 'mode': 'rw'},
                # ACME challenge directory
                f"{node.container_webroot_path}": {'bind': '/var/www/letsencrypt', 'mode': 'rw'},
                # Cache directory
                f"{node.container_cache_path}": {'bind': '/var/cache/nginx', 'mode': 'rw'}
            }
            
            # Ensure local directories exist
            for path in volumes.keys():
                os.makedirs(path, exist_ok=True)
            
            # Set environment variables for the container
            environment = {
                "TZ": node.container_timezone or "UTC"
            }
            
            # Set up ports
            ports = {
                '80/tcp': node.container_http_port or 80,
                '443/tcp': node.container_https_port or 443
            }
            
            # Set up container labels
            labels = {
                'managed-by': 'reverse-proxy-manager',
                'node-id': str(node.id),
                'node-name': node.name
            }
            
            # Pull the latest Nginx image
            image_name = node.container_image or 'nginx:latest'
            try:
                client.images.pull(image_name)
                log_activity('info', f"Pulled image {image_name} for node {node.name}", 'node', node.id, None, user_id)
            except Exception as e:
                log_activity('warning', f"Failed to pull image {image_name}: {str(e)}", 'node', node.id, None, user_id)
            
            # Create the container
            container = client.containers.run(
                image=image_name,
                name=container_name,
                volumes=volumes,
                environment=environment,
                ports=ports,
                restart_policy={"Name": "always"},
                labels=labels,
                detach=True
            )
            
            # Wait for container to start
            time.sleep(2)
            
            # Update node record with container ID
            node.container_id = container.id
            db.session.commit()
            
            log_activity('info', f"Created and started container {container_name} on node {node.name}", 'node', node.id, None, user_id)
            
            return {
                'success': True,
                'message': f"Container {container_name} created and started successfully",
                'container_id': container.id
            }
            
        except Exception as e:
            log_activity('error', f"Failed to set up container on node {node.name}: {str(e)}", 'node', node.id, None, user_id)
            return {
                'success': False,
                'message': f"Failed to set up container: {str(e)}"
            }
    
    @staticmethod
    def deploy_to_container(site_id, node_id, nginx_config, test_only=False):
        """Deploy a site configuration to a container
        
        Args:
            site_id: ID of the site
            node_id: ID of the node to deploy to
            nginx_config: The Nginx configuration content
            test_only: If True, only test the configuration without deploying
            
        Returns:
            If test_only=True: tuple (is_valid, warnings)
            Otherwise: True on success or raises an exception
        """
        site = Site.query.get(site_id)
        node = Node.query.get(node_id)
        
        if not site or not node:
            raise ValueError("Site or node not found")
        
        if not node.is_container_node:
            raise ValueError("Node is not configured for container mode")
        
        warnings = []
        
        # Validate Nginx configuration
        from app.services.nginx_validation_service import NginxValidationService
        
        # Set up directories for the domain if they don't exist
        domain = site.domain
        
        try:
            client = ContainerService.get_docker_client(node)
            if not client:
                if test_only:
                    return False, ["Failed to connect to Docker daemon"]
                else:
                    raise ValueError("Failed to connect to Docker daemon")
            
            # Check if container is running
            container_name = node.container_name or f"nginx-proxy-{node.id}"
            containers = client.containers.list(filters={"name": container_name})
            
            if not containers:
                if test_only:
                    return False, [f"Container {container_name} not found or not running"]
                else:
                    raise ValueError(f"Container {container_name} not found or not running")
            
            container = containers[0]
            
            # For SSL sites, ensure certificate directories exist
            if site.protocol == 'https':
                ssl_dir = f"{node.container_certs_path}/live/{domain}"
                os.makedirs(ssl_dir, exist_ok=True)
                
                # Check if SSL certificates exist, if not create temporary ones
                cert_path = f"{ssl_dir}/fullchain.pem"
                key_path = f"{ssl_dir}/privkey.pem"
                chain_path = f"{ssl_dir}/chain.pem"
                
                if not (os.path.exists(cert_path) and os.path.exists(key_path)):
                    # Create a minimal self-signed certificate
                    from app.services.ssl_certificate_service import SSLCertificateService
                    ssl_result = SSLCertificateService.create_self_signed_cert(domain, ssl_dir)
                    
                    if not ssl_result.get('success', False):
                        warnings.append(f"Warning: Failed to create self-signed certificate: {ssl_result.get('message')}")
                    else:
                        warnings.append("Created temporary self-signed certificate. Remember to request a real certificate.")
            
            # Ensure ACME challenge directory exists
            acme_dir = f"{node.container_webroot_path}/.well-known/acme-challenge"
            os.makedirs(acme_dir, exist_ok=True)
            
            # Write configuration to a temporary file for testing
            import tempfile
            with tempfile.NamedTemporaryFile(suffix='.conf', delete=False) as tmp:
                tmp.write(nginx_config.encode('utf-8'))
                temp_config_path = tmp.name
            
            # For test-only mode, check if the config looks valid
            if test_only:
                # Basic syntax checking (simple search for common errors)
                basic_errors = []
                if 'server {' not in nginx_config:
                    basic_errors.append("Missing 'server' directive")
                if 'listen' not in nginx_config:
                    basic_errors.append("Missing 'listen' directive")
                if 'server_name' not in nginx_config:
                    basic_errors.append("Missing 'server_name' directive")
                
                if basic_errors:
                    os.unlink(temp_config_path)
                    return False, basic_errors
                
                # Copy to a test location in the container
                test_dest = f"/etc/nginx/conf.d/test_{domain}.conf"
                with open(temp_config_path, 'rb') as src_file:
                    cmd = f"cat > {test_dest} && nginx -t"
                    exit_code, output = container.exec_run(cmd, stdin=src_file)
                
                # Cleanup test config
                container.exec_run(f"rm -f {test_dest}")
                
                # Check the output
                is_valid = exit_code == 0
                if not is_valid:
                    warnings.append(f"Configuration test failed: {output.decode('utf-8')}")
                
                os.unlink(temp_config_path)
                return is_valid, warnings
            
            # Deploy the configuration
            config_path = f"{node.container_config_path}/{domain}.conf"
            
            # Copy the final config to the host path
            os.replace(temp_config_path, config_path)
            
            # Reload Nginx in the container
            exit_code, output = container.exec_run("nginx -s reload")
            
            if exit_code != 0:
                error_message = output.decode('utf-8')
                
                # Check if it's an SSL certificate error
                if "SSL" in error_message and "certificate" in error_message:
                    # Create a warning log
                    log = DeploymentLog(
                        site_id=site_id,
                        node_id=node_id,
                        action="deploy",
                        status="warning",
                        message=f"Deployment completed but Nginx reload had SSL certificate warnings: {error_message}"
                    )
                    db.session.add(log)
                    
                    # Update site node status
                    site_node = SiteNode.query.filter_by(site_id=site_id, node_id=node_id).first()
                    if site_node:
                        site_node.status = "warning"
                        site_node.updated_at = datetime.utcnow()
                    else:
                        site_node = SiteNode(
                            site_id=site_id,
                            node_id=node_id,
                            status="warning",
                            created_at=datetime.utcnow(),
                            updated_at=datetime.utcnow()
                        )
                        db.session.add(site_node)
                    
                    db.session.commit()
                    return True
                else:
                    # For other errors, log and raise exception
                    log = DeploymentLog(
                        site_id=site_id,
                        node_id=node_id,
                        action="deploy",
                        status="error",
                        message=f"Failed to reload nginx in container: {error_message}"
                    )
                    db.session.add(log)
                    db.session.commit()
                    raise ValueError(f"Failed to reload nginx in container: {error_message}")
            
            # Update or create the site_node relationship
            site_node = SiteNode.query.filter_by(site_id=site_id, node_id=node_id).first()
            if site_node:
                site_node.status = "deployed"
                site_node.updated_at = datetime.utcnow()
            else:
                site_node = SiteNode(
                    site_id=site_id,
                    node_id=node_id,
                    status="deployed",
                    created_at=datetime.utcnow(),
                    updated_at=datetime.utcnow()
                )
                db.session.add(site_node)
            
            # Log successful deployment
            log = DeploymentLog(
                site_id=site_id,
                node_id=node_id,
                action="deploy",
                status="success",
                message=f"Successfully deployed {site.domain} to container node {node.name}"
            )
            db.session.add(log)
            db.session.commit()
            
            # Version the configuration in git if configured
            from app.services.config_versioning_service import save_config_version
            try:
                from flask import session
                from flask_login import current_user
                username = current_user.username if current_user and current_user.is_authenticated else "system"
            except:
                username = "system"
            
            try:
                save_config_version(site, nginx_config, username)
            except Exception as e:
                # Log but don't fail deployment if versioning fails
                log_activity('warning', f"Failed to save config version for {site.domain}: {str(e)}")
            
            return True
            
        except Exception as e:
            # Log the error
            log = DeploymentLog(
                site_id=site_id,
                node_id=node_id,
                action="deploy",
                status="error",
                message=f"Container deployment error: {str(e)}"
            )
            db.session.add(log)
            db.session.commit()
            
            # Re-raise the exception
            raise

    @staticmethod
    def start_container(node, user_id=None):
        """
        Start an existing container for a node
        
        Args:
            node: Node object
            user_id: Optional user ID for activity logging
            
        Returns:
            dict: Result of container start operation
        """
        if not node.is_container_node:
            return {
                'success': False,
                'message': 'Not a container node'
            }
            
        docker_client = ContainerService.get_docker_client(node)
        
        if not docker_client:
            return {
                'success': False,
                'message': 'Failed to connect to Docker'
            }
            
        try:
            if isinstance(docker_client, dict) and docker_client.get('is_ssh_tunnel'):
                # Using SSH tunnel
                ssh_client = docker_client['ssh_client']
                
                # Check if container exists
                container_name = node.container_name
                stdin, stdout, stderr = ssh_client.exec_command(f"docker ps -a --filter name=^/{container_name}$ --format '{{{{.Status}}}}'")
                container_status = stdout.read().decode('utf-8').strip()
                
                if not container_status:
                    ssh_client.close()
                    return {
                        'success': False,
                        'message': 'Container does not exist'
                    }
                    
                # Start the container if it's not already running
                if not container_status.startswith('Up'):
                    stdin, stdout, stderr = ssh_client.exec_command(f"docker start {container_name}")
                    exit_code = stdout.channel.recv_exit_status()
                    
                    if exit_code != 0:
                        error_msg = stderr.read().decode('utf-8')
                        ssh_client.close()
                        return {
                            'success': False,
                            'message': f"Failed to start container: {error_msg}"
                        }
                    
                    # Log the container start
                    log_activity(
                        'info',
                        f"Started container for node {node.name}",
                        'node',
                        node.id,
                        user_id=user_id
                    )
                    
                ssh_client.close()
                
                return {
                    'success': True,
                    'message': 'Container started successfully'
                }
            else:
                # Direct Docker client connection
                try:
                    container = docker_client.containers.get(node.container_name)
                    
                    if container.status != 'running':
                        container.start()
                        
                        # Log the container start
                        log_activity(
                            'info',
                            f"Started container for node {node.name}",
                            'node',
                            node.id,
                            user_id=user_id
                        )
                    
                    return {
                        'success': True,
                        'message': 'Container started successfully'
                    }
                except docker.errors.NotFound:
                    return {
                        'success': False,
                        'message': 'Container does not exist'
                    }
                except Exception as e:
                    return {
                        'success': False,
                        'message': f"Error starting container: {str(e)}"
                    }
                    
        except Exception as e:
            if isinstance(docker_client, dict) and docker_client.get('is_ssh_tunnel'):
                docker_client['ssh_client'].close()
                
            error_msg = f"Error starting container: {str(e)}"
            
            log_activity(
                'error',
                error_msg,
                'node',
                node.id,
                user_id=user_id
            )
            
            return {
                'success': False,
                'message': error_msg
            }
    
    @staticmethod
    def stop_container(node, user_id=None):
        """
        Stop a running container for a node
        
        Args:
            node: Node object
            user_id: Optional user ID for activity logging
            
        Returns:
            dict: Result of container stop operation
        """
        if not node.is_container_node:
            return {
                'success': False,
                'message': 'Not a container node'
            }
            
        docker_client = ContainerService.get_docker_client(node)
        
        if not docker_client:
            return {
                'success': False,
                'message': 'Failed to connect to Docker'
            }
            
        try:
            if isinstance(docker_client, dict) and docker_client.get('is_ssh_tunnel'):
                # Using SSH tunnel
                ssh_client = docker_client['ssh_client']
                
                # Check if container exists and is running
                container_name = node.container_name
                stdin, stdout, stderr = ssh_client.exec_command(f"docker ps --filter name=^/{container_name}$ --format '{{{{.Status}}}}'")
                container_status = stdout.read().decode('utf-8').strip()
                
                if not container_status:
                    ssh_client.close()
                    return {
                        'success': True,
                        'message': 'Container is not running'
                    }
                    
                # Stop the container
                stdin, stdout, stderr = ssh_client.exec_command(f"docker stop {container_name}")
                exit_code = stdout.channel.recv_exit_status()
                
                if exit_code != 0:
                    error_msg = stderr.read().decode('utf-8')
                    ssh_client.close()
                    return {
                        'success': False,
                        'message': f"Failed to stop container: {error_msg}"
                    }
                
                # Log the container stop
                log_activity(
                    'info',
                    f"Stopped container for node {node.name}",
                    'node',
                    node.id,
                    user_id=user_id
                )
                
                ssh_client.close()
                
                return {
                    'success': True,
                    'message': 'Container stopped successfully'
                }
            else:
                # Direct Docker client connection
                try:
                    container = docker_client.containers.get(node.container_name)
                    
                    if container.status == 'running':
                        container.stop()
                        
                        # Log the container stop
                        log_activity(
                            'info',
                            f"Stopped container for node {node.name}",
                            'node',
                            node.id,
                            user_id=user_id
                        )
                    
                    return {
                        'success': True,
                        'message': 'Container stopped successfully'
                    }
                except docker.errors.NotFound:
                    return {
                        'success': False,
                        'message': 'Container does not exist'
                    }
                except Exception as e:
                    return {
                        'success': False,
                        'message': f"Error stopping container: {str(e)}"
                    }
                    
        except Exception as e:
            if isinstance(docker_client, dict) and docker_client.get('is_ssh_tunnel'):
                docker_client['ssh_client'].close()
                
            error_msg = f"Error stopping container: {str(e)}"
            
            log_activity(
                'error',
                error_msg,
                'node',
                node.id,
                user_id=user_id
            )
            
            return {
                'success': False,
                'message': error_msg
            }
    
    @staticmethod
    def delete_container(node, user_id=None):
        """
        Delete a container for a node
        
        Args:
            node: Node object
            user_id: Optional user ID for activity logging
            
        Returns:
            dict: Result of container deletion
        """
        if not node.is_container_node:
            return {
                'success': False,
                'message': 'Not a container node'
            }
            
        docker_client = ContainerService.get_docker_client(node)
        
        if not docker_client:
            return {
                'success': False,
                'message': 'Failed to connect to Docker'
            }
            
        try:
            if isinstance(docker_client, dict) and docker_client.get('is_ssh_tunnel'):
                # Using SSH tunnel
                ssh_client = docker_client['ssh_client']
                
                # Stop the container if it's running
                container_name = node.container_name
                stdin, stdout, stderr = ssh_client.exec_command(f"docker stop {container_name} 2>/dev/null || true")
                stdout.channel.recv_exit_status()  # Wait for command to complete
                
                # Remove the container
                stdin, stdout, stderr = ssh_client.exec_command(f"docker rm {container_name} 2>/dev/null || true")
                exit_code = stdout.channel.recv_exit_status()
                
                # Reset container_id in database
                node.container_id = None
                db.session.commit()
                
                # Log the container deletion
                log_activity(
                    'info',
                    f"Deleted container for node {node.name}",
                    'node',
                    node.id,
                    user_id=user_id
                )
                
                ssh_client.close()
                
                return {
                    'success': True,
                    'message': 'Container deleted successfully'
                }
            else:
                # Direct Docker client connection
                try:
                    container = docker_client.containers.get(node.container_name)
                    
                    # Stop container if running
                    if container.status == 'running':
                        container.stop()
                        
                    # Remove the container
                    container.remove()
                    
                    # Reset container_id in database
                    node.container_id = None
                    db.session.commit()
                    
                    # Log the container deletion
                    log_activity(
                        'info',
                        f"Deleted container for node {node.name}",
                        'node',
                        node.id,
                        user_id=user_id
                    )
                    
                    return {
                        'success': True,
                        'message': 'Container deleted successfully'
                    }
                except docker.errors.NotFound:
                    # Reset container_id in database since container doesn't exist
                    node.container_id = None
                    db.session.commit()
                    
                    return {
                        'success': True,
                        'message': 'Container does not exist'
                    }
                except Exception as e:
                    return {
                        'success': False,
                        'message': f"Error deleting container: {str(e)}"
                    }
                    
        except Exception as e:
            if isinstance(docker_client, dict) and docker_client.get('is_ssh_tunnel'):
                docker_client['ssh_client'].close()
                
            error_msg = f"Error deleting container: {str(e)}"
            
            log_activity(
                'error',
                error_msg,
                'node',
                node.id,
                user_id=user_id
            )
            
            return {
                'success': False,
                'message': error_msg
            }
    
    @staticmethod
    def deploy_to_container(site_id, node_id, nginx_config, test_only=False):
        """
        Deploy a site configuration to a containerized node
        
        Args:
            site_id: ID of the site
            node_id: ID of the node
            nginx_config: Nginx configuration content
            test_only: Whether to just test the configuration without deploying
            
        Returns:
            If test_only=True: tuple (is_valid, warnings)
            Otherwise: True on success or raises an exception
        """
        from app.models.models import Site, Node
        
        site = Site.query.get(site_id)
        node = Node.query.get(node_id)
        
        if not site or not node:
            raise ValueError("Site or node not found")
            
        if not node.is_container_node:
            raise ValueError("Node is not a container node")
            
        # Check if container is running
        container_status = ContainerService.check_container_status(node)
        
        if not container_status.get('success', False):
            raise ValueError(f"Could not check container status: {container_status.get('message', 'Unknown error')}")
            
        if not container_status.get('running', False):
            # Try to start the container or set it up if it doesn't exist
            if container_status.get('exists', False):
                start_result = ContainerService.start_container(node)
                
                if not start_result.get('success', False):
                    raise ValueError(f"Failed to start container: {start_result.get('message', 'Unknown error')}")
            else:
                setup_result = ContainerService.setup_container(node)
                
                if not setup_result.get('success', False):
                    raise ValueError(f"Failed to set up container: {setup_result.get('message', 'Unknown error')}")
        
        # Create a backup of the existing configuration if not in test mode
        backup_config = None
        if not test_only:
            from app.services.config_rollback_service import ConfigRollbackService
            backup_config = ConfigRollbackService.create_backup_config(site_id, node_id)
        
        try:
            # Create a temporary file with the configuration content
            with tempfile.NamedTemporaryFile(mode='w', delete=False) as temp_file:
                temp_file.write(nginx_config)
                temp_file_path = temp_file.name
            
            docker_client = ContainerService.get_docker_client(node)
            
            if not docker_client:
                os.unlink(temp_file_path)
                raise ValueError("Failed to connect to Docker")
                
            try:
                if isinstance(docker_client, dict) and docker_client.get('is_ssh_tunnel'):
                    # Using SSH tunnel
                    ssh_client = docker_client['ssh_client']
                    sftp = ssh_client.open_sftp()
                    
                    # Define paths
                    config_file_path = f"{node.container_config_path}/{site.domain}.conf"
                    test_config_path = f"{node.container_config_path}/test.conf"
                    
                    # Upload the configuration for testing
                    sftp.put(temp_file_path, test_config_path)
                    
                    # Test the configuration
                    if test_only:
                        test_cmd = f"docker exec {node.container_name} nginx -t -c /etc/nginx/nginx.conf 2>&1"
                        stdin, stdout, stderr = ssh_client.exec_command(test_cmd)
                        output = stdout.read().decode('utf-8') + stderr.read().decode('utf-8')
                        exit_code = stdout.channel.recv_exit_status()
                        
                        # Clean up the test file
                        sftp.remove(test_config_path)
                        sftp.close()
                        ssh_client.close()
                        os.unlink(temp_file_path)
                        
                        warnings = []
                        if 'warning' in output.lower():
                            warnings = [line for line in output.split('\n') if 'warning' in line.lower()]
                        
                        return exit_code == 0, warnings
                    
                    # Upload the configuration to its final location
                    sftp.put(temp_file_path, config_file_path)
                    
                    # Reload Nginx in the container
                    reload_cmd = f"docker exec {node.container_name} nginx -s reload"
                    stdin, stdout, stderr = ssh_client.exec_command(reload_cmd)
                    exit_code = stdout.channel.recv_exit_status()
                    
                    if exit_code != 0:
                        error_msg = stderr.read().decode('utf-8')
                        sftp.close()
                        ssh_client.close()
                        os.unlink(temp_file_path)
                        
                        # Attempt to restore from backup if available
                        if backup_config:
                            # Try to restore the backup config
                            from app.services.config_rollback_service import ConfigRollbackService
                            ConfigRollbackService.restore_config(site_id, node_id, backup_config)
                        
                        raise ValueError(f"Failed to reload Nginx in container: {error_msg}")
                    
                    # Update site node status
                    site_node = SiteNode.query.filter_by(site_id=site_id, node_id=node_id).first()
                    if site_node:
                        site_node.status = 'deployed'
                        site_node.deployed_at = time.strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        site_node = SiteNode(
                            site_id=site_id,
                            node_id=node_id,
                            status='deployed',
                            deployed_at=time.strftime('%Y-%m-%d %H:%M:%S')
                        )
                        db.session.add(site_node)
                        
                    db.session.commit()
                    
                    # Log the successful deployment
                    log = DeploymentLog(
                        site_id=site_id,
                        node_id=node_id,
                        action="deploy_container",
                        status="success",
                        message=f"Successfully deployed {site.domain} to containerized node {node.name}"
                    )
                    db.session.add(log)
                    db.session.commit()
                    
                    # Clean up
                    sftp.close()
                    ssh_client.close()
                    os.unlink(temp_file_path)
                    
                    return True
                else:
                    # Direct Docker client connection
                    # TODO: Implement this branch
                    # For now, we'll just raise an error
                    os.unlink(temp_file_path)
                    raise ValueError("Direct Docker connection not implemented yet")
                    
            except Exception as e:
                if isinstance(docker_client, dict) and docker_client.get('is_ssh_tunnel'):
                    try:
                        docker_client['ssh_client'].close()
                    except:
                        pass
                        
                os.unlink(temp_file_path)
                raise e
                
        except Exception as e:
            os.unlink(temp_file_path)
            
            # Log the error
            log = DeploymentLog(
                site_id=site_id,
                node_id=node_id,
                action="deploy_container",
                status="error",
                message=f"Failed to deploy to container: {str(e)}"
            )
            db.session.add(log)
            db.session.commit()
            
            # Try to restore from backup if available
            if backup_config:
                try:
                    from app.services.config_rollback_service import ConfigRollbackService
                    ConfigRollbackService.restore_config(site_id, node_id, backup_config)
                except Exception as restore_error:
                    # Just log the restore error, but raise the original error
                    log_activity(
                        'error',
                        f"Failed to restore config after deployment error: {str(restore_error)}",
                        'site',
                        site_id
                    )
            
            raise e