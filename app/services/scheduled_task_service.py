import threading
import time
import logging
import schedule
from datetime import datetime
import inspect
from app.services.node_discovery_service import NodeDiscoveryService
from app.services.ssl_certificate_service import SSLCertificateService
from app.services.logger_service import log_activity
from app import db

logger = logging.getLogger(__name__)

class ScheduledTaskService:
    """Service for managing scheduled tasks in the application"""
    
    _running = False
    _thread = None
    _tasks = {}
    # Initialize lock for thread safety
    _scheduler_lock = threading.Lock()
    
    @classmethod
    def initialize(cls):
        """Initialize the scheduled task service and register default tasks"""
        with cls._scheduler_lock:
            if cls._running:
                return False
                
            # Register default tasks
            cls.register_task(
                'node_heartbeat', 
                NodeDiscoveryService.run_heartbeat_check,
                '*/5 * * * *'  # Every 5 minutes
            )
            
            cls.register_task(
                'ssl_certificates_check',
                SSLCertificateService.certificate_health_check,
                '0 */6 * * *'  # Every 6 hours
            )
            
            # Auto-replace self-signed certificates with real ones if available
            cls.register_task(
                'replace_self_signed_certificates',
                SSLCertificateService.auto_replace_self_signed_certificates,
                '0 */12 * * *'  # Every 12 hours
            )
            
            # Start the scheduler
            cls.start()
            return True
    
    @classmethod
    def register_task(cls, name, func, schedule_str, description=None):
        """
        Register a scheduled task
        
        Args:
            name (str): Unique name for the task
            func (callable): Function to execute
            schedule_str (str): Schedule string in cron format or one of:
                               - 'hourly', 'daily', 'weekly', 'monthly'
                               - 'every X minutes/hours/days'
            description (str, optional): Description of the task
            
        Returns:
            bool: True if registered successfully, False otherwise
        """
        if name in cls._tasks:
            logger.warning(f"Task '{name}' already registered. Replacing.")
            
        if not callable(func):
            logger.error(f"Task '{name}' function is not callable")
            return False
            
        # Parse schedule string
        try:
            job = cls._parse_schedule(schedule_str, func)
            if not job:
                logger.error(f"Failed to parse schedule '{schedule_str}' for task '{name}'")
                return False
                
            # Add task to registry
            cls._tasks[name] = {
                'name': name,
                'function': func,
                'schedule': schedule_str,
                'description': description or inspect.getdoc(func) or "No description",
                'job': job,
                'last_run': None,
                'last_status': None,
                'last_result': None,
                'registered_at': datetime.utcnow()
            }
            
            logger.info(f"Registered task '{name}' with schedule '{schedule_str}'")
            return True
            
        except Exception as e:
            logger.error(f"Error registering task '{name}': {str(e)}")
            return False
    
    @classmethod
    def _parse_schedule(cls, schedule_str, func):
        """Parse a schedule string and return the corresponding job"""
        schedule_str = schedule_str.strip().lower()
        
        # Handle named schedules
        if schedule_str == 'hourly':
            return schedule.every().hour.do(cls._execute_task_wrapper, func)
        elif schedule_str == 'daily':
            return schedule.every().day.at("00:00").do(cls._execute_task_wrapper, func)
        elif schedule_str == 'weekly':
            return schedule.every().week.do(cls._execute_task_wrapper, func)
        elif schedule_str == 'monthly':
            # Schedule library doesn't have monthly, so we'll use a custom approach
            return schedule.every().day.at("00:00").do(cls._monthly_check, func)
            
        # Handle 'every X minutes/hours/days' format
        if schedule_str.startswith('every '):
            parts = schedule_str.split()
            if len(parts) >= 3:
                try:
                    interval = int(parts[1])
                    unit = parts[2].rstrip('s')  # Remove trailing s if present
                    
                    if unit == 'minute':
                        return schedule.every(interval).minutes.do(cls._execute_task_wrapper, func)
                    elif unit == 'hour':
                        return schedule.every(interval).hours.do(cls._execute_task_wrapper, func)
                    elif unit == 'day':
                        return schedule.every(interval).days.do(cls._execute_task_wrapper, func)
                    
                except (ValueError, IndexError):
                    logger.error(f"Invalid schedule format: {schedule_str}")
                    
        # Handle cron-style format (simple implementation)
        if cls._is_cron_format(schedule_str):
            # We'll use a custom handler for cron format
            return schedule.every(1).minutes.do(cls._cron_check, schedule_str, func)
            
        logger.error(f"Unsupported schedule format: {schedule_str}")
        return None
    
    @staticmethod
    def _is_cron_format(schedule_str):
        """Check if a string is in cron format"""
        parts = schedule_str.split()
        # A valid cron format should have exactly 5 parts
        return len(parts) == 5
    
    @staticmethod
    def _cron_check(cron_str, func):
        """Check if a cron schedule should run at the current time"""
        # Very basic cron implementation - just enough for our use case
        current_time = datetime.now()
        cron_parts = cron_str.split()
        
        if len(cron_parts) != 5:
            # Invalid cron format
            logger.error(f"Invalid cron format: {cron_str}")
            return
        
        # Parse minute, hour, day, month, day of week
        minute_spec, hour_spec, day_spec, month_spec, dow_spec = cron_parts
        
        # Check minute
        if minute_spec != '*':
            if minute_spec.startswith('*/'):
                # */5 format (every 5 minutes, etc.)
                try:
                    interval = int(minute_spec[2:])
                    if current_time.minute % interval != 0:
                        return
                except (ValueError, IndexError):
                    logger.error(f"Invalid minute interval in cron: {minute_spec}")
                    return
            else:
                try:
                    minute_values = [int(x) for x in minute_spec.split(',')]
                    if current_time.minute not in minute_values:
                        return
                except (ValueError, IndexError):
                    logger.error(f"Invalid minute values in cron: {minute_spec}")
                    return
        
        # Check hour
        if hour_spec != '*':
            if hour_spec.startswith('*/'):
                # */2 format (every 2 hours, etc.)
                try:
                    interval = int(hour_spec[2:])
                    if current_time.hour % interval != 0:
                        return
                except (ValueError, IndexError):
                    logger.error(f"Invalid hour interval in cron: {hour_spec}")
                    return
            else:
                try:
                    hour_values = [int(x) for x in hour_spec.split(',')]
                    if current_time.hour not in hour_values:
                        return
                except (ValueError, IndexError):
                    logger.error(f"Invalid hour values in cron: {hour_spec}")
                    return
        
        # Check day of month
        if day_spec != '*':
            try:
                day_values = [int(x) for x in day_spec.split(',')]
                if current_time.day not in day_values:
                    return
            except (ValueError, IndexError):
                logger.error(f"Invalid day values in cron: {day_spec}")
                return
        
        # Check month
        if month_spec != '*':
            try:
                month_values = [int(x) for x in month_spec.split(',')]
                if current_time.month not in month_values:
                    return
            except (ValueError, IndexError):
                logger.error(f"Invalid month values in cron: {month_spec}")
                return
        
        # Check day of week (0 = Monday in datetime, but 0 = Sunday in cron)
        if dow_spec != '*':
            # Convert python's day of week (0 = Monday) to cron's (0 = Sunday)
            python_dow = current_time.weekday()
            cron_dow = (python_dow + 1) % 7
            try:
                dow_values = [int(x) for x in dow_spec.split(',')]
                if cron_dow not in dow_values:
                    return
            except (ValueError, IndexError):
                logger.error(f"Invalid day of week values in cron: {dow_spec}")
                return
        
        # If we get here, the cron schedule matches the current time
        ScheduledTaskService._execute_task_wrapper(func)
    
    @staticmethod
    def _monthly_check(func):
        """Check if a monthly schedule should run at the current time"""
        current_time = datetime.now()
        if current_time.day == 1:
            ScheduledTaskService._execute_task_wrapper(func)
            
    @staticmethod
    def _execute_task_wrapper(func):
        """Wrapper around task execution to handle errors and database sessions"""
        task_name = func.__name__ if hasattr(func, '__name__') else 'unnamed_task'
        log_activity('info', f"Executing scheduled task: {task_name}")
        
        start_time = time.time()
        result = None
        status = 'failed'
        error = None
        
        try:
            # Execute the task
            result = func()
            status = 'success'
            return result
            
        except Exception as e:
            error = str(e)
            logger.error(f"Error executing task '{task_name}': {error}")
            
        finally:
            duration = time.time() - start_time
            
            # Record task execution
            task_info = {
                'name': task_name,
                'status': status,
                'duration_ms': int(duration * 1000),
                'executed_at': datetime.utcnow()
            }
            
            if error:
                task_info['error'] = error
                
            if result:
                # Only store simple result types
                if isinstance(result, (dict, list, str, int, float, bool)):
                    task_info['result'] = result
                    
            # Find the task in our registry and update its status
            for task in ScheduledTaskService._tasks.values():
                if task['function'] == func:
                    task['last_run'] = datetime.utcnow()
                    task['last_status'] = status
                    task['last_result'] = result
                    
            log_activity('info', f"Task '{task_name}' completed with status '{status}' in {duration:.2f}s")
    
    @classmethod
    def start(cls):
        """Start the scheduler in a background thread"""
        if cls._running:
            logger.warning("Scheduler is already running")
            return False
            
        cls._running = True
        cls._thread = threading.Thread(target=cls._scheduler_loop, daemon=True)
        cls._thread.start()
        
        logger.info(f"Scheduler started with {len(cls._tasks)} tasks")
        return True
        
    @classmethod
    def stop(cls):
        """Stop the scheduler"""
        if not cls._running:
            return False
            
        cls._running = False
        
        if cls._thread and cls._thread.is_alive():
            cls._thread.join(timeout=5)
            
        logger.info("Scheduler stopped")
        return True
        
    @classmethod
    def _scheduler_loop(cls):
        """Main loop for the scheduler"""
        logger.info("Scheduler loop starting")
        
        while cls._running:
            try:
                schedule.run_pending()
                time.sleep(1)
            except Exception as e:
                logger.error(f"Error in scheduler loop: {str(e)}")
                time.sleep(5)  # Longer delay after an error
                
        logger.info("Scheduler loop exited")
        
    @classmethod
    def get_tasks(cls):
        """Get a list of all registered tasks and their status"""
        tasks = []
        
        for task_id, task in cls._tasks.items():
            task_info = {
                'id': task_id,
                'name': task['name'],
                'schedule': task['schedule'],
                'description': task['description'],
                'last_run': task['last_run'],
                'last_status': task['last_status'],
                'registered_at': task['registered_at']
            }
            
            # Include simplified result if present
            if task['last_result'] and isinstance(task['last_result'], (dict, list, str, int, float, bool)):
                # For large results, include a summary
                if isinstance(task['last_result'], dict):
                    # Only include top-level keys for dictionary results
                    task_info['last_result_summary'] = {
                        k: (f"{len(v)} items" if isinstance(v, (list, dict)) and len(v) > 5 else v)
                        for k, v in task['last_result'].items()
                    }
                elif isinstance(task['last_result'], list) and len(task['last_result']) > 5:
                    task_info['last_result_summary'] = f"{len(task['last_result'])} items"
                else:
                    task_info['last_result_summary'] = task['last_result']
                    
            tasks.append(task_info)
            
        return tasks
        
    @classmethod
    def run_task_now(cls, task_id):
        """
        Run a specific task immediately
        
        Args:
            task_id (str): ID of the task to run
            
        Returns:
            dict: Result of the task execution
        """
        if task_id not in cls._tasks:
            return {
                'success': False,
                'error': f"Task '{task_id}' not found"
            }
            
        task = cls._tasks[task_id]
        
        try:
            # Run the task directly
            start_time = time.time()
            result = task['function']()
            duration = time.time() - start_time
            
            # Update task status
            task['last_run'] = datetime.utcnow()
            task['last_status'] = 'success'
            task['last_result'] = result
            
            return {
                'success': True,
                'task_id': task_id,
                'name': task['name'],
                'duration_ms': int(duration * 1000),
                'result': result
            }
            
        except Exception as e:
            # Update task status
            task['last_run'] = datetime.utcnow()
            task['last_status'] = 'failed'
            task['last_result'] = str(e)
            
            return {
                'success': False,
                'task_id': task_id,
                'name': task['name'],
                'error': str(e)
            }

"""
Scheduled Task Service

This module provides functionality for executing scheduled tasks
such as backups, certificate renewals, and log cleanup.
"""

import os
import datetime
import shutil
import tarfile
import tempfile
import logging
import json
import subprocess
from flask import current_app
from sqlalchemy import create_engine
from apscheduler.schedulers.background import BackgroundScheduler
from apscheduler.triggers.cron import CronTrigger
from app.models.models import db, SystemSetting, SSLCertificate, DeploymentLog, SystemLog, Site, User, Node
from app.services.logger_service import log_activity

# Create a dedicated logger for scheduled tasks
scheduler_logger = logging.getLogger('scheduler')
scheduler_logger.setLevel(logging.INFO)

# Initialize the scheduler
scheduler = BackgroundScheduler()

def init_scheduler(app):
    """
    Initialize and start the background scheduler with the Flask app context
    
    Args:
        app: Flask application instance
    """
    if scheduler.running:
        scheduler.shutdown()
    
    scheduler.start()
    
    # Schedule the regular tasks
    with app.app_context():
        # Schedule backups
        setup_backup_schedule()
        
        # Schedule certificate renewal checks
        schedule_ssl_renewal_checks()
        
        # Schedule log retention (cleanup)
        schedule_log_retention()
        
        # Schedule health checks
        schedule_node_health_checks()
    
    # Register shutdown function
    @app.teardown_appcontext
    def shutdown_scheduler(exception=None):
        if scheduler.running:
            scheduler.shutdown()

def setup_backup_schedule():
    """Configure and schedule automatic backups based on system settings"""
    # Get backup settings
    backup_enabled = SystemSetting.get('backup_backup_enabled', 'False').lower() == 'true'
    
    if not backup_enabled:
        # Remove any existing backup jobs if backups are disabled
        for job in scheduler.get_jobs():
            if job.id.startswith('backup_'):
                scheduler.remove_job(job.id)
        return
    
    # Get backup frequency
    frequency = SystemSetting.get('backup_backup_frequency', 'daily')
    
    # Set up the schedule based on frequency
    if frequency == 'hourly':
        trigger = CronTrigger(hour='*', minute=0)
    elif frequency == 'daily':
        trigger = CronTrigger(hour=2, minute=0)  # 2 AM
    elif frequency == 'weekly':
        trigger = CronTrigger(day_of_week=0, hour=2, minute=0)  # Sunday at 2 AM
    elif frequency == 'monthly':
        trigger = CronTrigger(day=1, hour=2, minute=0)  # 1st of the month at 2 AM
    else:
        # Default to daily
        trigger = CronTrigger(hour=2, minute=0)
    
    # Schedule the backup job
    scheduler.add_job(
        run_backup,
        trigger=trigger,
        id='backup_scheduled',
        replace_existing=True,
        args=[True]  # scheduled=True
    )
    
    # Schedule backup retention (cleanup of old backups)
    scheduler.add_job(
        cleanup_old_backups,
        trigger=CronTrigger(hour=3, minute=0),  # 3 AM
        id='backup_cleanup',
        replace_existing=True
    )
    
    scheduler_logger.info(f"Backup schedule configured: {frequency}")

def run_backup(scheduled=False):
    """
    Run a system backup
    
    Args:
        scheduled (bool): Whether this is a scheduled backup or manual
        
    Returns:
        tuple: (success, message)
    """
    # Get backup settings
    backup_destination = SystemSetting.get('backup_backup_destination', 'local')
    backup_path = SystemSetting.get('backup_backup_path', '/var/backups/proxy-manager')
    include_certs = SystemSetting.get('backup_include_certificates', 'True').lower() == 'true'
    include_logs = SystemSetting.get('backup_include_logs', 'False').lower() == 'true'
    
    # Create timestamp for the backup filename
    timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
    backup_filename = f"proxy_manager_backup_{timestamp}.tar.gz"
    
    # Create temporary directory for backup files
    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            # Step 1: Database backup
            db_file = os.path.join(temp_dir, 'database.sql')
            success, db_message = backup_database(db_file)
            
            if not success:
                log_activity(
                    category='error',
                    action='backup',
                    resource_type='database',
                    details=f"Database backup failed: {db_message}"
                )
                return False, f"Backup failed: {db_message}"
            
            # Step 2: Configuration backup
            config_dir = os.path.join(temp_dir, 'config')
            os.makedirs(config_dir, exist_ok=True)
            
            # Backup system settings
            settings = SystemSetting.query.all()
            settings_data = {setting.key: setting.value for setting in settings}
            with open(os.path.join(config_dir, 'settings.json'), 'w') as f:
                json.dump(settings_data, f, indent=2)
            
            # Backup nginx templates
            nginx_templates_dir = os.path.join(current_app.root_path, '..', 'nginx_templates')
            if os.path.exists(nginx_templates_dir):
                shutil.copytree(
                    nginx_templates_dir, 
                    os.path.join(config_dir, 'nginx_templates'),
                    dirs_exist_ok=True
                )
            
            # Backup nginx configs
            nginx_configs_dir = os.path.join(current_app.root_path, '..', 'nginx_configs')
            if os.path.exists(nginx_configs_dir):
                shutil.copytree(
                    nginx_configs_dir,
                    os.path.join(config_dir, 'nginx_configs'),
                    dirs_exist_ok=True
                )
            
            # Step 3: SSL certificates backup (if enabled)
            if include_certs:
                certs_dir = os.path.join(temp_dir, 'certificates')
                os.makedirs(certs_dir, exist_ok=True)
                
                # Get all certificate paths from the database
                certificates = SSLCertificate.query.all()
                
                for cert in certificates:
                    cert_data = {
                        'id': cert.id,
                        'site_id': cert.site_id,
                        'node_id': cert.node_id,
                        'domain': cert.domain,
                        'certificate_path': cert.certificate_path,
                        'private_key_path': cert.private_key_path,
                        'fullchain_path': cert.fullchain_path,
                        'is_self_signed': cert.is_self_signed
                    }
                    
                    # Create a directory for each domain
                    domain_dir = os.path.join(certs_dir, cert.domain.replace('*', 'wildcard'))
                    os.makedirs(domain_dir, exist_ok=True)
                    
                    # Save certificate metadata
                    with open(os.path.join(domain_dir, 'metadata.json'), 'w') as f:
                        json.dump(cert_data, f, indent=2)
                
                # Note: Actual certificate files are on the nodes and not backed up here
                # This is just metadata. We'd need to create a secure way to pull actual certs
                # which would be a separate feature.
            
            # Step 4: Logs backup (if enabled)
            if include_logs:
                logs_dir = os.path.join(temp_dir, 'logs')
                os.makedirs(logs_dir, exist_ok=True)
                
                # Export deployment logs to a JSON file
                deployment_logs = DeploymentLog.query.all()
                deployment_logs_data = [log.to_dict() for log in deployment_logs]
                with open(os.path.join(logs_dir, 'deployment_logs.json'), 'w') as f:
                    json.dump(deployment_logs_data, f, indent=2)
                
                # Export system logs to a JSON file
                system_logs = SystemLog.query.all()
                system_logs_data = [log.to_dict() for log in system_logs]
                with open(os.path.join(logs_dir, 'system_logs.json'), 'w') as f:
                    json.dump(system_logs_data, f, indent=2)
            
            # Step 5: Create the backup archive
            backup_file = os.path.join(temp_dir, backup_filename)
            with tarfile.open(backup_file, 'w:gz') as tar:
                # Add a README file with backup information
                readme_path = os.path.join(temp_dir, 'README.txt')
                with open(readme_path, 'w') as f:
                    f.write(f"Reverse Proxy Manager Backup\n")
                    f.write(f"Created: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write(f"Includes database: Yes\n")
                    f.write(f"Includes configs: Yes\n")
                    f.write(f"Includes certificates metadata: {include_certs}\n")
                    f.write(f"Includes logs: {include_logs}\n")
                
                tar.add(readme_path, arcname=os.path.basename(readme_path))
                
                # Add all other files from temp directory (database, configs, etc.)
                for root, dirs, files in os.walk(temp_dir):
                    if os.path.basename(root) == os.path.basename(temp_dir):
                        # Skip the top level directory itself
                        continue
                    for file in files:
                        file_path = os.path.join(root, file)
                        # Create a relative arcname by removing the temp_dir prefix
                        arcname = os.path.relpath(file_path, temp_dir)
                        tar.add(file_path, arcname=arcname)
            
            # Step 6: Upload/store the backup based on destination
            if backup_destination == 'local':
                # Ensure backup directory exists
                os.makedirs(backup_path, exist_ok=True)
                
                # Move the backup archive to the target location
                final_backup_path = os.path.join(backup_path, backup_filename)
                shutil.copy2(backup_file, final_backup_path)
                
                # Log successful backup
                log_activity(
                    category='system',
                    action='backup',
                    resource_type='system',
                    details=f"Backup completed successfully. File: {final_backup_path}"
                )
                
                return True, f"Backup completed successfully. File: {final_backup_path}"
                
            elif backup_destination == 's3':
                # S3 upload functionality would be implemented here
                # For now, we'll just store locally as a fallback
                s3_bucket = SystemSetting.get('backup_s3_bucket', '')
                s3_path = SystemSetting.get('backup_s3_path', '')
                aws_access_key = SystemSetting.get('backup_aws_access_key', '')
                aws_secret_key = SystemSetting.get('backup_aws_secret_key', '')
                
                if not s3_bucket or not aws_access_key or not aws_secret_key:
                    # Fall back to local storage if S3 settings are incomplete
                    os.makedirs(backup_path, exist_ok=True)
                    final_backup_path = os.path.join(backup_path, backup_filename)
                    shutil.copy2(backup_file, final_backup_path)
                    
                    log_activity(
                        category='warning',
                        action='backup',
                        resource_type='system',
                        details=f"S3 configuration incomplete. Backup saved locally: {final_backup_path}"
                    )
                    
                    return True, f"S3 configuration incomplete. Backup saved locally: {final_backup_path}"
                
                try:
                    # Using boto3 for S3 upload
                    import boto3
                    from botocore.exceptions import ClientError
                    
                    s3_client = boto3.client(
                        's3',
                        aws_access_key_id=aws_access_key,
                        aws_secret_access_key=aws_secret_key
                    )
                    
                    # Prepare S3 path
                    if s3_path and not s3_path.endswith('/'):
                        s3_path += '/'
                    s3_key = f"{s3_path}{backup_filename}"
                    
                    # Upload the file
                    s3_client.upload_file(
                        backup_file,
                        s3_bucket,
                        s3_key
                    )
                    
                    # Log successful S3 upload
                    log_activity(
                        category='system',
                        action='backup',
                        resource_type='system',
                        details=f"Backup uploaded to S3 successfully. Bucket: {s3_bucket}, Key: {s3_key}"
                    )
                    
                    return True, f"Backup uploaded to S3 successfully. Bucket: {s3_bucket}, Key: {s3_key}"
                    
                except ImportError:
                    # boto3 package not installed
                    log_activity(
                        category='error',
                        action='backup',
                        resource_type='system',
                        details="S3 upload failed: boto3 package not installed"
                    )
                    
                    # Fall back to local storage
                    os.makedirs(backup_path, exist_ok=True)
                    final_backup_path = os.path.join(backup_path, backup_filename)
                    shutil.copy2(backup_file, final_backup_path)
                    
                    return False, f"S3 upload failed: boto3 package not installed. Backup saved locally: {final_backup_path}"
                    
                except Exception as e:
                    # Other S3 upload errors
                    log_activity(
                        category='error',
                        action='backup',
                        resource_type='system',
                        details=f"S3 upload failed: {str(e)}"
                    )
                    
                    # Fall back to local storage
                    os.makedirs(backup_path, exist_ok=True)
                    final_backup_path = os.path.join(backup_path, backup_filename)
                    shutil.copy2(backup_file, final_backup_path)
                    
                    return False, f"S3 upload failed: {str(e)}. Backup saved locally: {final_backup_path}"
                    
            elif backup_destination == 'sftp':
                # SFTP upload functionality would be implemented here
                # For now, we'll just store locally as a fallback
                sftp_host = SystemSetting.get('backup_sftp_host', '')
                sftp_port = int(SystemSetting.get('backup_sftp_port', '22'))
                sftp_user = SystemSetting.get('backup_sftp_user', '')
                sftp_password = SystemSetting.get('backup_sftp_password', '')
                sftp_path = SystemSetting.get('backup_sftp_path', '')
                
                if not sftp_host or not sftp_user or (not sftp_password and not SystemSetting.get('backup_sftp_key_path')):
                    # Fall back to local storage if SFTP settings are incomplete
                    os.makedirs(backup_path, exist_ok=True)
                    final_backup_path = os.path.join(backup_path, backup_filename)
                    shutil.copy2(backup_file, final_backup_path)
                    
                    log_activity(
                        category='warning',
                        action='backup',
                        resource_type='system',
                        details=f"SFTP configuration incomplete. Backup saved locally: {final_backup_path}"
                    )
                    
                    return True, f"SFTP configuration incomplete. Backup saved locally: {final_backup_path}"
                
                try:
                    # Using paramiko for SFTP
                    import paramiko
                    
                    # Connect to SFTP server
                    transport = paramiko.Transport((sftp_host, sftp_port))
                    
                    if sftp_password:
                        transport.connect(username=sftp_user, password=sftp_password)
                    else:
                        sftp_key_path = SystemSetting.get('backup_sftp_key_path', '')
                        key = paramiko.RSAKey.from_private_key_file(sftp_key_path)
                        transport.connect(username=sftp_user, pkey=key)
                    
                    sftp = paramiko.SFTPClient.from_transport(transport)
                    
                    # Ensure remote path exists
                    if sftp_path:
                        try:
                            sftp.stat(sftp_path)
                        except FileNotFoundError:
                            # Create directory if it doesn't exist
                            sftp.mkdir(sftp_path)
                    
                    # Prepare SFTP path
                    if sftp_path and not sftp_path.endswith('/'):
                        sftp_path += '/'
                    remote_path = f"{sftp_path}{backup_filename}"
                    
                    # Upload the file
                    sftp.put(backup_file, remote_path)
                    
                    # Close the connection
                    sftp.close()
                    transport.close()
                    
                    # Log successful SFTP upload
                    log_activity(
                        category='system',
                        action='backup',
                        resource_type='system',
                        details=f"Backup uploaded to SFTP successfully. Server: {sftp_host}, Path: {remote_path}"
                    )
                    
                    return True, f"Backup uploaded to SFTP successfully. Server: {sftp_host}, Path: {remote_path}"
                    
                except ImportError:
                    # paramiko package not installed
                    log_activity(
                        category='error',
                        action='backup',
                        resource_type='system',
                        details="SFTP upload failed: paramiko package not installed"
                    )
                    
                    # Fall back to local storage
                    os.makedirs(backup_path, exist_ok=True)
                    final_backup_path = os.path.join(backup_path, backup_filename)
                    shutil.copy2(backup_file, final_backup_path)
                    
                    return False, f"SFTP upload failed: paramiko package not installed. Backup saved locally: {final_backup_path}"
                    
                except Exception as e:
                    # Other SFTP upload errors
                    log_activity(
                        category='error',
                        action='backup',
                        resource_type='system',
                        details=f"SFTP upload failed: {str(e)}"
                    )
                    
                    # Fall back to local storage
                    os.makedirs(backup_path, exist_ok=True)
                    final_backup_path = os.path.join(backup_path, backup_filename)
                    shutil.copy2(backup_file, final_backup_path)
                    
                    return False, f"SFTP upload failed: {str(e)}. Backup saved locally: {final_backup_path}"
                    
            else:
                # Unknown destination, fall back to local
                os.makedirs(backup_path, exist_ok=True)
                final_backup_path = os.path.join(backup_path, backup_filename)
                shutil.copy2(backup_file, final_backup_path)
                
                log_activity(
                    category='warning',
                    action='backup',
                    resource_type='system',
                    details=f"Unknown backup destination '{backup_destination}'. Backup saved locally: {final_backup_path}"
                )
                
                return True, f"Unknown backup destination '{backup_destination}'. Backup saved locally: {final_backup_path}"
            
        except Exception as e:
            # Log the error
            error_msg = f"Backup failed: {str(e)}"
            logging.error(error_msg)
            
            log_activity(
                category='error',
                action='backup',
                resource_type='system',
                details=error_msg
            )
            
            return False, error_msg

def backup_database(output_file):
    """
    Backup the SQLite database to a file
    
    Args:
        output_file (str): Path to the output SQL dump file
        
    Returns:
        tuple: (success, message)
    """
    try:
        # Get the database URI from the app config
        from flask import current_app
        db_uri = current_app.config.get('SQLALCHEMY_DATABASE_URI')
        
        if not db_uri or not db_uri.startswith('sqlite:///'):
            return False, "Only SQLite databases are supported for direct backup"
        
        # Extract the database path from the URI
        db_path = db_uri.replace('sqlite:///', '')
        
        # For relative paths, consider the application root
        if not os.path.isabs(db_path):
            db_path = os.path.join(current_app.root_path, '..', db_path)
        
        # Ensure the database file exists
        if not os.path.exists(db_path):
            return False, f"Database file not found: {db_path}"
        
        # For SQLite, we can simply copy the database file
        shutil.copy2(db_path, output_file)
        
        return True, "Database backed up successfully"
    
    except Exception as e:
        return False, f"Database backup failed: {str(e)}"

def cleanup_old_backups():
    """Delete old backups based on retention policy"""
    # Get backup settings
    backup_path = SystemSetting.get('backup_backup_path', '/var/backups/proxy-manager')
    backup_retention = int(SystemSetting.get('backup_backup_retention', '7'))
    backup_destination = SystemSetting.get('backup_backup_destination', 'local')
    
    # Only handle local backups for now
    if backup_destination != 'local':
        # For S3 and other destinations, we'd need specific cleanup logic
        return
    
    # Check if path exists
    if not os.path.exists(backup_path):
        return
    
    try:
        # Get list of backup files
        backup_files = []
        for file in os.listdir(backup_path):
            if file.startswith('proxy_manager_backup_') and file.endswith('.tar.gz'):
                file_path = os.path.join(backup_path, file)
                file_time = os.path.getmtime(file_path)
                backup_files.append((file_path, file_time))
        
        # Sort by time (oldest first)
        backup_files.sort(key=lambda x: x[1])
        
        # Keep only the newest X files based on retention
        files_to_keep = backup_files[-backup_retention:] if backup_retention > 0 else []
        files_to_delete = [f[0] for f in backup_files[:-backup_retention]] if backup_retention > 0 else [f[0] for f in backup_files]
        
        # Delete old files
        for file_path in files_to_delete:
            os.remove(file_path)
            
            log_activity(
                category='system',
                action='backup_cleanup',
                resource_type='system',
                details=f"Deleted old backup file: {os.path.basename(file_path)}"
            )
        
        if files_to_delete:
            scheduler_logger.info(f"Cleaned up {len(files_to_delete)} old backup files")
    
    except Exception as e:
        error_msg = f"Error cleaning up old backups: {str(e)}"
        scheduler_logger.error(error_msg)
        
        log_activity(
            category='error',
            action='backup_cleanup',
            resource_type='system',
            details=error_msg
        )

def schedule_ssl_renewal_checks():
    """Schedule regular checks for SSL certificates that need renewal"""
    # Schedule daily SSL certificate check
    scheduler.add_job(
        check_ssl_certificates,
        trigger=CronTrigger(hour=1, minute=0),  # 1 AM
        id='ssl_renewal_check',
        replace_existing=True
    )
    
    scheduler_logger.info("SSL renewal checks scheduled")

def check_ssl_certificates():
    """Check for SSL certificates that need renewal and notify admins"""
    try:
        # Get all certificates
        certificates = SSLCertificate.query.all()
        
        # Check for certificates expiring soon
        now = datetime.datetime.utcnow()
        expiring_soon = []
        
        for cert in certificates:
            if cert.valid_until and cert.valid_until > now:
                # Calculate days remaining
                days_remaining = (cert.valid_until - now).days
                
                # Update days_remaining in the database
                cert.days_remaining = days_remaining
                
                # Check if it's expiring soon (less than 30 days)
                if days_remaining <= 30:
                    if days_remaining <= 7:
                        cert.status = 'expiring_soon'
                    expiring_soon.append({
                        'id': cert.id,
                        'domain': cert.domain,
                        'days_remaining': days_remaining,
                        'site_id': cert.site_id,
                        'node_id': cert.node_id
                    })
            elif cert.valid_until and cert.valid_until <= now:
                # Certificate has expired
                cert.status = 'expired'
                cert.days_remaining = 0
                expiring_soon.append({
                    'id': cert.id,
                    'domain': cert.domain,
                    'days_remaining': 0,
                    'site_id': cert.site_id,
                    'node_id': cert.node_id,
                    'expired': True
                })
        
        # Save changes to the database
        db.session.commit()
        
        # Send notifications for expiring certificates
        if expiring_soon:
            # Log the expiring certificates
            log_activity(
                category='warning',
                action='ssl_expiry_check',
                resource_type='ssl',
                details=f"Found {len(expiring_soon)} certificates expiring soon or already expired"
            )
            
            # Notify admins if notifications are enabled
            enable_notifications = SystemSetting.get('email_enable_notifications', 'False').lower() == 'true'
            notification_events = SystemSetting.get('email_notification_events', '')
            
            if enable_notifications and 'certificate_expiry' in notification_events.split(','):
                from app.services.email_service import send_certificate_expiry_notification
                send_certificate_expiry_notification(expiring_soon)
    
    except Exception as e:
        error_msg = f"Error checking SSL certificates: {str(e)}"
        scheduler_logger.error(error_msg)
        
        log_activity(
            category='error',
            action='ssl_expiry_check',
            resource_type='ssl',
            details=error_msg
        )

def schedule_log_retention():
    """Schedule log retention/cleanup tasks"""
    # Schedule weekly log cleanup
    scheduler.add_job(
        cleanup_old_logs,
        trigger=CronTrigger(day_of_week=0, hour=4, minute=0),  # Sunday at 4 AM
        id='log_cleanup',
        replace_existing=True
    )
    
    scheduler_logger.info("Log retention scheduled")

def cleanup_old_logs():
    """Delete old logs based on retention policy"""
    try:
        # Get log retention setting (days)
        retention_days = int(SystemSetting.get('app_log_retention_days', '30'))
        
        # Calculate the cutoff date
        cutoff_date = datetime.datetime.utcnow() - datetime.timedelta(days=retention_days)
        
        # Delete old deployment logs
        old_deployment_logs = DeploymentLog.query.filter(DeploymentLog.created_at < cutoff_date).all()
        for log in old_deployment_logs:
            db.session.delete(log)
        
        # Delete old system logs
        old_system_logs = SystemLog.query.filter(SystemLog.created_at < cutoff_date).all()
        for log in old_system_logs:
            db.session.delete(log)
        
        # Commit the changes
        db.session.commit()
        
        log_activity(
            category='system',
            action='log_cleanup',
            resource_type='system',
            details=f"Cleaned up logs older than {retention_days} days"
        )
        
        scheduler_logger.info(f"Cleaned up logs older than {retention_days} days")
    
    except Exception as e:
        error_msg = f"Error cleaning up old logs: {str(e)}"
        scheduler_logger.error(error_msg)
        
        log_activity(
            category='error',
            action='log_cleanup',
            resource_type='system',
            details=error_msg
        )

def schedule_node_health_checks():
    """Schedule regular node health checks"""
    # Schedule hourly node health checks
    scheduler.add_job(
        check_node_health,
        trigger=CronTrigger(minute=15),  # Every hour at 15 minutes past
        id='node_health_check',
        replace_existing=True
    )
    
    scheduler_logger.info("Node health checks scheduled")

def check_node_health():
    """Check the health of all active nodes"""
    try:
        from app.services.node_inspection_service import check_node_connectivity, check_node_performance
        
        # Get all active nodes
        nodes = Node.query.filter_by(is_active=True).all()
        
        # Notification data
        nodes_down = []
        nodes_warning = []
        
        for node in nodes:
            # Check node connectivity
            is_reachable = check_node_connectivity(node)
            
            if not is_reachable:
                nodes_down.append({
                    'id': node.id,
                    'name': node.name,
                    'ip_address': node.ip_address,
                    'error': 'Node is unreachable'
                })
                
                # Log the node down event
                log_activity(
                    category='error',
                    action='node_health_check',
                    resource_type='node',
                    resource_id=node.id,
                    details=f"Node {node.name} is unreachable"
                )
                
                continue
            
            # Check node performance (CPU, memory, disk)
            try:
                performance = check_node_performance(node)
                
                # Check if any performance metric is in warning state
                if (performance.get('cpu_usage', 0) > 80 or 
                    performance.get('memory_usage', 0) > 80 or 
                    performance.get('disk_usage', 0) > 80):
                    
                    nodes_warning.append({
                        'id': node.id,
                        'name': node.name,
                        'ip_address': node.ip_address,
                        'cpu_usage': performance.get('cpu_usage', 0),
                        'memory_usage': performance.get('memory_usage', 0),
                        'disk_usage': performance.get('disk_usage', 0)
                    })
                    
                    # Log the warning event
                    log_activity(
                        category='warning',
                        action='node_health_check',
                        resource_type='node',
                        resource_id=node.id,
                        details=f"Node {node.name} has high resource usage: CPU {performance.get('cpu_usage', 0)}%, Memory {performance.get('memory_usage', 0)}%, Disk {performance.get('disk_usage', 0)}%"
                    )
            
            except Exception as e:
                # Log the performance check error
                log_activity(
                    category='error',
                    action='node_health_check',
                    resource_type='node',
                    resource_id=node.id,
                    details=f"Error checking node performance: {str(e)}"
                )
        
        # Send notifications for down or warning nodes
        if nodes_down or nodes_warning:
            # Notify admins if notifications are enabled
            enable_notifications = SystemSetting.get('email_enable_notifications', 'False').lower() == 'true'
            notification_events = SystemSetting.get('email_notification_events', '')
            
            if enable_notifications and 'node_offline' in notification_events.split(','):
                from app.services.email_service import send_node_health_notification
                send_node_health_notification(nodes_down, nodes_warning)
    
    except Exception as e:
        error_msg = f"Error checking node health: {str(e)}"
        scheduler_logger.error(error_msg)
        
        log_activity(
            category='error',
            action='node_health_check',
            resource_type='system',
            details=error_msg
        )

def restore_from_backup(backup_file):
    """
    Restore system from a backup file
    
    Args:
        backup_file (str): Path to the backup file
        
    Returns:
        tuple: (success, message)
    """
    # Create a temporary directory for extraction
    with tempfile.TemporaryDirectory() as temp_dir:
        try:
            # Extract the backup archive
            with tarfile.open(backup_file, 'r:gz') as tar:
                tar.extractall(path=temp_dir)
            
            # Check if this is a valid backup
            readme_path = os.path.join(temp_dir, 'README.txt')
            if not os.path.exists(readme_path):
                return False, "Invalid backup file: README.txt not found"
            
            # Read the readme to verify backup type
            with open(readme_path, 'r') as f:
                readme_content = f.read()
                if "Reverse Proxy Manager Backup" not in readme_content:
                    return False, "Invalid backup file: Not a Reverse Proxy Manager backup"
            
            # Check if database file exists
            db_file = os.path.join(temp_dir, 'database.sql')
            if not os.path.exists(db_file):
                return False, "Invalid backup file: database.sql not found"
            
            # Step 1: Restore database
            # This is tricky as we need to replace the current database
            # We'll need to get the database file path from the app config
            from flask import current_app
            db_uri = current_app.config.get('SQLALCHEMY_DATABASE_URI')
            
            if not db_uri or not db_uri.startswith('sqlite:///'):
                return False, "Only SQLite databases are supported for direct restore"
            
            # Extract the database path from the URI
            target_db_path = db_uri.replace('sqlite:///', '')
            
            # For relative paths, consider the application root
            if not os.path.isabs(target_db_path):
                target_db_path = os.path.join(current_app.root_path, '..', target_db_path)
            
            # Create a backup of the current database
            db_backup_path = f"{target_db_path}.bak"
            shutil.copy2(target_db_path, db_backup_path)
            
            # Close current database connections
            db.session.close()
            db.engine.dispose()
            
            # Replace the database file
            try:
                shutil.copy2(db_file, target_db_path)
            except Exception as e:
                # If anything goes wrong, restore the backup
                shutil.copy2(db_backup_path, target_db_path)
                return False, f"Error restoring database: {str(e)}"
            
            # Step 2: Restore configuration files
            config_dir = os.path.join(temp_dir, 'config')
            if os.path.exists(config_dir):
                # Restore nginx templates
                nginx_templates_src = os.path.join(config_dir, 'nginx_templates')
                if os.path.exists(nginx_templates_src):
                    nginx_templates_dest = os.path.join(current_app.root_path, '..', 'nginx_templates')
                    if os.path.exists(nginx_templates_dest):
                        # Backup existing templates
                        templates_backup_dir = f"{nginx_templates_dest}.bak"
                        if os.path.exists(templates_backup_dir):
                            shutil.rmtree(templates_backup_dir)
                        shutil.copytree(nginx_templates_dest, templates_backup_dir)
                        
                        # Remove existing and copy new
                        shutil.rmtree(nginx_templates_dest)
                    
                    # Copy restored templates
                    shutil.copytree(nginx_templates_src, nginx_templates_dest)
                
                # Restore nginx configs
                nginx_configs_src = os.path.join(config_dir, 'nginx_configs')
                if os.path.exists(nginx_configs_src):
                    nginx_configs_dest = os.path.join(current_app.root_path, '..', 'nginx_configs')
                    if os.path.exists(nginx_configs_dest):
                        # Backup existing configs
                        configs_backup_dir = f"{nginx_configs_dest}.bak"
                        if os.path.exists(configs_backup_dir):
                            shutil.rmtree(configs_backup_dir)
                        shutil.copytree(nginx_configs_dest, configs_backup_dir)
                        
                        # Remove existing and copy new
                        shutil.rmtree(nginx_configs_dest)
                    
                    # Copy restored configs
                    shutil.copytree(nginx_configs_src, nginx_configs_dest)
                
                # Restore system settings from settings.json
                settings_file = os.path.join(config_dir, 'settings.json')
                if os.path.exists(settings_file):
                    with open(settings_file, 'r') as f:
                        settings_data = json.load(f)
                    
                    # Save settings to database
                    # We need to reconnect to the new database first
                    db.session.remove()
                    
                    # Restore settings
                    for key, value in settings_data.items():
                        SystemSetting.set(key, value)
            
            # Log the successful restore
            log_activity(
                category='system',
                action='restore',
                resource_type='system',
                details=f"System restored from backup: {os.path.basename(backup_file)}"
            )
            
            return True, f"System restored successfully from backup: {os.path.basename(backup_file)}"
        
        except Exception as e:
            error_msg = f"Error restoring from backup: {str(e)}"
            logging.error(error_msg)
            
            log_activity(
                category='error',
                action='restore',
                resource_type='system',
                details=error_msg
            )
            
            return False, error_msg