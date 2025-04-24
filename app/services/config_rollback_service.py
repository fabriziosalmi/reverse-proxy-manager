import os
import shutil
import tempfile
import git
from datetime import datetime
from flask import current_app
from app.models.models import db, Site, Node, SiteNode, DeploymentLog, ConfigVersion
from app.services.logger_service import log_activity

class ConfigRollbackService:
    """Service for handling configuration rollbacks"""
    
    @staticmethod
    def rollback_deployment(site_id, node_id, version_id=None, user_id=None):
        """
        Roll back a site configuration to a previous version
        
        Args:
            site_id: ID of the site to roll back
            node_id: ID of the node to roll back on
            version_id: Optional ID of the specific version to roll back to.
                        If None, rolls back to the previous successful deployment.
            user_id: Optional ID of the user performing the rollback
            
        Returns:
            dict: Result of the rollback operation
        """
        from app.services.nginx_service import deploy_to_node, generate_nginx_config
        
        site = Site.query.get(site_id)
        node = Node.query.get(node_id)
        
        if not site or not node:
            return {
                'success': False,
                'message': 'Site or node not found'
            }
        
        try:
            # Get the configuration to roll back to
            config_content = None
            rollback_version = None
            
            if version_id:
                # Roll back to a specific version
                rollback_version = ConfigVersion.query.get(version_id)
                if not rollback_version or rollback_version.site_id != site_id:
                    return {
                        'success': False,
                        'message': f'Version {version_id} not found for site {site.domain}'
                    }
                
                # Get the configuration content from Git
                repo_path = current_app.config['NGINX_CONFIG_GIT_REPO']
                file_path = os.path.join(repo_path, 'sites', f"{site.domain}.conf")
                
                if not os.path.exists(repo_path) or not os.path.isdir(os.path.join(repo_path, '.git')):
                    return {
                        'success': False,
                        'message': 'Git repository not found'
                    }
                
                repo = git.Repo(repo_path)
                
                # Check if the commit exists
                try:
                    commit = repo.commit(rollback_version.commit_hash)
                except git.exc.BadName:
                    return {
                        'success': False,
                        'message': f'Commit {rollback_version.commit_hash} not found in repository'
                    }
                
                # Get the file content at that commit
                try:
                    config_content = repo.git.show(f'{rollback_version.commit_hash}:{os.path.relpath(file_path, repo_path)}')
                except git.exc.GitCommandError:
                    # File might not exist at that commit
                    return {
                        'success': False,
                        'message': f'Configuration file not found in commit {rollback_version.commit_hash}'
                    }
            else:
                # Roll back to the last successful deployment
                # Get the most recent successful deployment log
                successful_deployment = DeploymentLog.query.filter_by(
                    site_id=site_id,
                    node_id=node_id,
                    status='success',
                    action='deploy'
                ).order_by(DeploymentLog.created_at.desc()).first()
                
                if not successful_deployment:
                    # If no successful deployment found, check for the most recent version in Git
                    repo_path = current_app.config['NGINX_CONFIG_GIT_REPO']
                    file_path = os.path.join(repo_path, 'sites', f"{site.domain}.conf")
                    
                    if not os.path.exists(repo_path) or not os.path.isdir(os.path.join(repo_path, '.git')):
                        # Generate a fresh configuration
                        config_content = generate_nginx_config(site)
                    else:
                        repo = git.Repo(repo_path)
                        # Get the file's commit history
                        try:
                            commits = list(repo.iter_commits(paths=os.path.relpath(file_path, repo_path), max_count=2))
                            if len(commits) >= 2:
                                # Use the second-most recent commit (previous version)
                                rollback_commit = commits[1]
                                config_content = repo.git.show(f'{rollback_commit.hexsha}:{os.path.relpath(file_path, repo_path)}')
                                
                                # Create a version record for this rollback if it doesn't exist
                                existing_version = ConfigVersion.query.filter_by(
                                    site_id=site_id,
                                    commit_hash=rollback_commit.hexsha
                                ).first()
                                
                                if not existing_version:
                                    rollback_version = ConfigVersion(
                                        site_id=site_id,
                                        commit_hash=rollback_commit.hexsha,
                                        message=rollback_commit.message,
                                        author=f"{rollback_commit.author.name} <{rollback_commit.author.email}>",
                                        created_at=datetime.fromtimestamp(rollback_commit.committed_date)
                                    )
                                    db.session.add(rollback_version)
                                    db.session.commit()
                                else:
                                    rollback_version = existing_version
                            else:
                                # No previous version found, generate a fresh configuration
                                config_content = generate_nginx_config(site)
                        except git.exc.GitCommandError:
                            # File might not have Git history
                            config_content = generate_nginx_config(site)
                else:
                    # Get the corresponding version from Git
                    versions_around_deployment = ConfigVersion.query.filter_by(
                        site_id=site_id
                    ).filter(
                        ConfigVersion.created_at <= successful_deployment.created_at
                    ).order_by(ConfigVersion.created_at.desc()).first()
                    
                    if versions_around_deployment:
                        rollback_version = versions_around_deployment
                        
                        # Get the configuration content from Git
                        repo_path = current_app.config['NGINX_CONFIG_GIT_REPO']
                        file_path = os.path.join(repo_path, 'sites', f"{site.domain}.conf")
                        
                        if os.path.exists(repo_path) and os.path.isdir(os.path.join(repo_path, '.git')):
                            repo = git.Repo(repo_path)
                            try:
                                config_content = repo.git.show(f'{rollback_version.commit_hash}:{os.path.relpath(file_path, repo_path)}')
                            except git.exc.GitCommandError:
                                # Fall back to generating a new configuration
                                config_content = generate_nginx_config(site)
                        else:
                            config_content = generate_nginx_config(site)
                    else:
                        # No version found, generate a fresh configuration
                        config_content = generate_nginx_config(site)
            
            # If no configuration could be retrieved, generate a new one
            if not config_content:
                config_content = generate_nginx_config(site)
            
            # Check if the node is a container node
            if node.is_container_node:
                # Use container service for deployment
                from app.services.container_service import ContainerService
                deployment_success = ContainerService.deploy_to_container(site_id, node_id, config_content)
            else:
                # Use standard SSH deployment
                deployment_success = deploy_to_node(site_id, node_id, config_content)
            
            if deployment_success:
                # Log the rollback
                log = DeploymentLog(
                    site_id=site_id,
                    node_id=node_id,
                    user_id=user_id,
                    action='rollback',
                    status='success',
                    message=f"Successfully rolled back {site.domain} on {node.name}" + 
                           (f" to version {rollback_version.commit_hash[:8]}" if rollback_version else "")
                )
                db.session.add(log)
                
                # Update site_node status
                site_node = SiteNode.query.filter_by(site_id=site_id, node_id=node_id).first()
                if site_node:
                    site_node.status = 'deployed'
                    site_node.updated_at = datetime.utcnow()
                
                db.session.commit()
                
                return {
                    'success': True,
                    'message': f"Successfully rolled back {site.domain} on {node.name}" +
                              (f" to version {rollback_version.commit_hash[:8]}" if rollback_version else "")
                }
            else:
                # Log the rollback failure
                log = DeploymentLog(
                    site_id=site_id,
                    node_id=node_id,
                    user_id=user_id,
                    action='rollback',
                    status='error',
                    message=f"Failed to roll back {site.domain} on {node.name}"
                )
                db.session.add(log)
                db.session.commit()
                
                return {
                    'success': False,
                    'message': f"Failed to roll back {site.domain} on {node.name}"
                }
                
        except Exception as e:
            # Log the error
            log_activity('error', f"Error during rollback of {site.domain} on {node.name}: {str(e)}", 'site', site_id, None, user_id)
            
            # Create a deployment log entry
            log = DeploymentLog(
                site_id=site_id,
                node_id=node_id,
                user_id=user_id,
                action='rollback',
                status='error',
                message=f"Error during rollback: {str(e)}"
            )
            db.session.add(log)
            db.session.commit()
            
            return {
                'success': False,
                'message': f"Error during rollback: {str(e)}"
            }
    
    @staticmethod
    def auto_rollback_on_failure(site_id, node_id, error_message, user_id=None):
        """
        Automatically roll back a failed deployment
        
        Args:
            site_id: ID of the site that failed deployment
            node_id: ID of the node where deployment failed
            error_message: Error message from the failed deployment
            user_id: Optional ID of the user who performed the failed deployment
            
        Returns:
            dict: Result of the auto-rollback operation
        """
        site = Site.query.get(site_id)
        node = Node.query.get(node_id)
        
        if not site or not node:
            return {
                'success': False,
                'message': 'Site or node not found'
            }
        
        # Log the auto-rollback attempt
        log_activity('info', f"Auto-rollback triggered for {site.domain} on {node.name} due to deployment failure", 'site', site_id, error_message, user_id)
        
        # Perform the rollback
        result = ConfigRollbackService.rollback_deployment(site_id, node_id, None, user_id)
        
        # Add a system log entry for the auto-rollback
        from app.models.models import SystemLog
        system_log = SystemLog(
            user_id=user_id,
            category='system',
            action='auto_rollback',
            resource_type='site',
            resource_id=site_id,
            details=f"Auto-rollback triggered for {site.domain} on {node.name}. Result: {result['message']}"
        )
        db.session.add(system_log)
        db.session.commit()
        
        return result
    
    @staticmethod
    def create_backup_config(site_id, node_id):
        """
        Create a backup of the current configuration before deployment
        
        Args:
            site_id: ID of the site
            node_id: ID of the node
            
        Returns:
            str: Path to the backup file, or None if backup failed
        """
        site = Site.query.get(site_id)
        node = Node.query.get(node_id)
        
        if not site or not node:
            return None
        
        try:
            # Determine backup location
            backup_dir = os.path.join(current_app.config.get('BACKUP_DIR', '/tmp/nginx_backups'), str(site_id), str(node_id))
            os.makedirs(backup_dir, exist_ok=True)
            
            # Generate a backup filename with timestamp
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_path = os.path.join(backup_dir, f"{site.domain}_{timestamp}.conf")
            
            if node.is_container_node:
                # For container nodes, read from local volume
                config_path = os.path.join(node.container_config_path, f"{site.domain}.conf")
                if os.path.exists(config_path):
                    shutil.copy2(config_path, backup_path)
                    return backup_path
            else:
                # For traditional nodes, use SSH to get the config
                import paramiko
                
                ssh_client = paramiko.SSHClient()
                ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                
                # Connect using key or password
                if node.ssh_key_path:
                    ssh_client.connect(
                        hostname=node.ip_address,
                        port=node.ssh_port,
                        username=node.ssh_user,
                        key_filename=node.ssh_key_path,
                        timeout=10
                    )
                else:
                    ssh_client.connect(
                        hostname=node.ip_address,
                        port=node.ssh_port,
                        username=node.ssh_user,
                        password=node.ssh_password,
                        timeout=10
                    )
                
                # Open SFTP connection
                sftp = ssh_client.open_sftp()
                
                # Get the config file path
                config_path = f"{node.nginx_config_path}/{site.domain}.conf"
                
                try:
                    # Try to retrieve the config file
                    with tempfile.NamedTemporaryFile(delete=False) as tmp:
                        tmp_path = tmp.name
                        try:
                            sftp.get(config_path, tmp_path)
                            # Copy to backup location
                            shutil.copy2(tmp_path, backup_path)
                        finally:
                            # Clean up temp file
                            if os.path.exists(tmp_path):
                                os.unlink(tmp_path)
                    
                    return backup_path
                except FileNotFoundError:
                    # Config doesn't exist yet, nothing to backup
                    return None
                finally:
                    sftp.close()
                    ssh_client.close()
            
            return None
        except Exception as e:
            log_activity('error', f"Failed to create backup for {site.domain} on {node.name}: {str(e)}", 'site', site_id)
            return None
    
    @staticmethod
    def restore_from_backup(backup_path, site_id, node_id, user_id=None):
        """
        Restore configuration from a backup file
        
        Args:
            backup_path: Path to the backup file
            site_id: ID of the site
            node_id: ID of the node
            user_id: Optional ID of the user performing the restore
            
        Returns:
            bool: True if restore was successful, False otherwise
        """
        if not backup_path or not os.path.exists(backup_path):
            return False
        
        site = Site.query.get(site_id)
        node = Node.query.get(node_id)
        
        if not site or not node:
            return False
        
        try:
            # Read the backup file
            with open(backup_path, 'r') as f:
                config_content = f.read()
            
            # Deploy the backup content
            from app.services.nginx_service import deploy_to_node
            
            if node.is_container_node:
                # Use container service for deployment
                from app.services.container_service import ContainerService
                return ContainerService.deploy_to_container(site_id, node_id, config_content)
            else:
                # Use standard SSH deployment
                return deploy_to_node(site_id, node_id, config_content)
                
        except Exception as e:
            log_activity('error', f"Failed to restore from backup for {site.domain} on {node.name}: {str(e)}", 'site', site_id, None, user_id)
            return False