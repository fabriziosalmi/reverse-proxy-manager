import os
import git
import shutil
import tempfile
from datetime import datetime
from flask import current_app
from app.models.models import db, Site, Node, SiteNode, DeploymentLog, ConfigVersion
from app.services.logger_service import log_activity
from app.services.nginx_service import generate_nginx_config, deploy_to_node

def get_git_repo():
    """
    Get or initialize Git repository for configuration versioning
    
    Returns:
        git.Repo: Git repository object
    """
    repo_path = current_app.config.get('NGINX_CONFIG_GIT_REPO', 
                                        os.path.join(current_app.root_path, '..', 'nginx_configs'))
    
    # Create repo if it doesn't exist
    if not os.path.exists(os.path.join(repo_path, '.git')):
        os.makedirs(repo_path, exist_ok=True)
        repo = git.Repo.init(repo_path)
        
        # Add .gitignore file
        with open(os.path.join(repo_path, '.gitignore'), 'w') as f:
            f.write("*.tmp\n")
            f.write("*.bak\n")
        
        # Initial commit
        repo.git.add('.gitignore')
        if not repo.head.is_valid() or len(repo.index.diff("HEAD")) > 0:
            repo.git.commit('-m', 'Initial commit')
    else:
        repo = git.Repo(repo_path)
    
    return repo

def save_config_version(site, config_content, message=None, author=None):
    """
    Save a new version of a site configuration
    
    Args:
        site: Site object
        config_content: Nginx configuration content
        message: Optional commit message
        author: Optional author name for the commit
        
    Returns:
        ConfigVersion: Created config version object
    """
    # Get Git repository
    repo = get_git_repo()
    repo_path = repo.working_dir
    
    # Create site directory if it doesn't exist
    site_dir = os.path.join(repo_path, 'sites')
    os.makedirs(site_dir, exist_ok=True)
    
    # Ensure we have the latest changes
    try:
        # Only pull if there's a remote configured
        if len(repo.remotes) > 0:
            # Stash any local changes before pulling
            repo.git.stash('save', 'Auto-stash before pull')
            repo.git.pull('--rebase')
            # Try to apply stashed changes
            try:
                repo.git.stash('pop')
            except git.GitCommandError:
                # If there are conflicts, just keep the stashed changes
                log_activity('warning', f"Conflicts during git stash pop in save_config_version for {site.domain}")
    except git.GitCommandError as e:
        # Log but continue, we'll work with the local copy
        log_activity('warning', f"Failed to pull latest changes: {str(e)}")
    
    # Write config file - use atomic write to avoid corruption
    file_path = os.path.join(site_dir, f"{site.domain}.conf")
    temp_file_path = f"{file_path}.{datetime.now().timestamp()}.tmp"
    
    try:
        # Write to temporary file first
        with open(temp_file_path, 'w') as f:
            f.write(config_content)
        
        # Use atomic rename to replace the original file
        os.replace(temp_file_path, file_path)
    except Exception as e:
        # Clean up temp file if there was an error
        if os.path.exists(temp_file_path):
            try:
                os.remove(temp_file_path)
            except:
                pass
        log_activity('error', f"Failed to write config file: {str(e)}")
        raise
    
    # Add to Git with error handling
    try:
        repo.git.add(file_path)
        
        # Check if there are actual changes
        if not repo.is_dirty():
            log_activity('info', f"No changes detected for {site.domain}, skipping version creation")
            return None
        
        # Commit message
        if not message:
            message = f"Updated configuration for {site.domain}"
        
        # Set up environment for the commit
        my_env = os.environ.copy()
        
        if author:
            # Format author information
            if '@' not in author:
                author_email = f"{author.lower().replace(' ', '.')}@italiacdn-proxy.local"
            else:
                author_email = author
                author = author.split('@')[0]
            
            # Set author environment variables
            my_env['GIT_AUTHOR_NAME'] = author
            my_env['GIT_AUTHOR_EMAIL'] = author_email
            my_env['GIT_COMMITTER_NAME'] = author
            my_env['GIT_COMMITTER_EMAIL'] = author_email
            
            # Make the commit with author info
            repo.git.commit('-m', message, env=my_env)
        else:
            # Use system defaults
            repo.git.commit('-m', message)
        
        # Get commit details
        commit = repo.head.commit
        commit_hash = commit.hexsha
        commit_date = datetime.fromtimestamp(commit.committed_date)
        commit_message = commit.message
        commit_author = commit.author.name
        
        # Try to push if a remote is configured
        if len(repo.remotes) > 0:
            try:
                repo.git.push()
            except git.GitCommandError as e:
                # Log but don't fail if push fails
                log_activity('warning', f"Failed to push config changes: {str(e)}")
        
        # Save version to database
        config_version = ConfigVersion(
            site_id=site.id,
            commit_hash=commit_hash,
            message=commit_message,
            author=commit_author,
            created_at=commit_date
        )
        db.session.add(config_version)
        db.session.commit()
        
        log_activity('info', f"Saved new configuration version for {site.domain}: {commit_hash[:8]}")
        
        return config_version
        
    except git.GitCommandError as e:
        log_activity('error', f"Git error in save_config_version for {site.domain}: {str(e)}")
        db.session.rollback()
        raise
    except Exception as e:
        log_activity('error', f"Error in save_config_version for {site.domain}: {str(e)}")
        db.session.rollback()
        raise

def get_config_versions(site):
    """
    Get all configuration versions for a site
    
    Args:
        site: Site object
        
    Returns:
        list: List of version dictionaries with commit info
    """
    # Get Git repository
    repo = get_git_repo()
    
    # Get file path
    file_path = os.path.join(repo.working_dir, 'sites', f"{site.domain}.conf")
    if not os.path.exists(file_path):
        return []
    
    # Get commits for this file
    versions = []
    
    try:
        # Use git log to get commit history for the file
        for commit in repo.iter_commits(paths=file_path):
            versions.append({
                'commit_hash': commit.hexsha,
                'short_hash': commit.hexsha[:8],
                'author': commit.author.name,
                'date': datetime.fromtimestamp(commit.committed_date),
                'message': commit.message
            })
    except git.exc.GitCommandError:
        # File might not be in git yet
        pass
    
    return versions

def get_config_content(site, commit_hash=None):
    """
    Get configuration content for a specific version
    
    Args:
        site: Site object
        commit_hash: Optional commit hash to retrieve (defaults to latest)
        
    Returns:
        str: Configuration content
    """
    # Get Git repository
    repo = get_git_repo()
    
    # Get file path
    file_path = os.path.join(repo.working_dir, 'sites', f"{site.domain}.conf")
    if not os.path.exists(file_path) and not commit_hash:
        # Generate new config
        return generate_nginx_config(site)
    
    if commit_hash:
        # Get specific version
        try:
            # Use git show to get file content at specific commit
            content = repo.git.show(f"{commit_hash}:{os.path.relpath(file_path, repo.working_dir)}")
            return content
        except git.exc.GitCommandError as e:
            log_activity('error', f"Error retrieving config version {commit_hash} for {site.domain}: {str(e)}")
            return None
    else:
        # Get latest version
        with open(file_path, 'r') as f:
            return f.read()

def rollback_config(site, commit_hash, deploy=False, user_id=None):
    """
    Rollback site configuration to a specific version
    
    Args:
        site: Site object
        commit_hash: Commit hash to rollback to
        deploy: Whether to deploy the changes to nodes
        user_id: Optional user ID performing the rollback
        
    Returns:
        bool: Success or failure
    """
    # Get config content for the version
    config_content = get_config_content(site, commit_hash)
    if not config_content:
        return False
    
    try:
        # Save as new version (creates a new commit with the old content)
        author = f"User {user_id}" if user_id else "System"
        message = f"Rollback to version {commit_hash[:8]}"
        
        config_version = save_config_version(site, config_content, message, author)
        
        # Deploy to nodes if requested
        if deploy:
            site_nodes = SiteNode.query.filter_by(site_id=site.id).all()
            for site_node in site_nodes:
                try:
                    deploy_to_node(site.id, site_node.node_id, config_content)
                    
                    # Log the rollback deployment
                    log = DeploymentLog(
                        site_id=site.id,
                        node_id=site_node.node_id,
                        action='rollback',
                        status='success',
                        message=f"Rolled back to version {commit_hash[:8]}",
                        user_id=user_id
                    )
                    db.session.add(log)
                except Exception as e:
                    log_activity('error', f"Error deploying rollback for {site.domain} to node {site_node.node_id}: {str(e)}")
                    
                    # Log the error
                    log = DeploymentLog(
                        site_id=site.id,
                        node_id=site_node.node_id,
                        action='rollback',
                        status='error',
                        message=f"Failed to deploy rollback: {str(e)}",
                        user_id=user_id
                    )
                    db.session.add(log)
        
        db.session.commit()
        return True
        
    except Exception as e:
        db.session.rollback()
        log_activity('error', f"Error rolling back configuration for {site.domain}: {str(e)}")
        return False

def compare_configs(site, commit_hash1, commit_hash2=None):
    """
    Compare two configuration versions
    
    Args:
        site: Site object
        commit_hash1: First commit hash
        commit_hash2: Second commit hash (defaults to current version)
        
    Returns:
        str: Diff output
    """
    # Get Git repository
    repo = get_git_repo()
    
    # Get file path
    file_path = os.path.relpath(
        os.path.join(repo.working_dir, 'sites', f"{site.domain}.conf"),
        repo.working_dir
    )
    
    try:
        if commit_hash2:
            # Compare two specific versions
            diff = repo.git.diff(commit_hash1, commit_hash2, '--', file_path)
        else:
            # Compare with current version
            diff = repo.git.diff(commit_hash1, '--', file_path)
        
        return diff
    except git.exc.GitCommandError as e:
        log_activity('error', f"Error comparing configs for {site.domain}: {str(e)}")
        return None