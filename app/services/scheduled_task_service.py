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
    
    @classmethod
    def initialize(cls):
        """Initialize the scheduled task service and register default tasks"""
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
        return len(parts) == 5
    
    @staticmethod
    def _cron_check(cron_str, func):
        """Check if a cron schedule should run at the current time"""
        # Very basic cron implementation - just enough for our use case
        current_time = datetime.now()
        cron_parts = cron_str.split()
        
        # Parse minute, hour, day, month, day of week
        minute_spec, hour_spec, day_spec, month_spec, dow_spec = cron_parts
        
        if minute_spec != '*' and minute_spec.startswith('*/'):
            # */5 format (every 5 minutes, etc.)
            interval = int(minute_spec[2:])
            if current_time.minute % interval != 0:
                return
        elif minute_spec != '*' and current_time.minute not in [int(x) for x in minute_spec.split(',')]:
            return
            
        if hour_spec != '*' and hour_spec.startswith('*/'):
            # */2 format (every 2 hours, etc.)
            interval = int(hour_spec[2:])
            if current_time.hour % interval != 0:
                return
        elif hour_spec != '*' and current_time.hour not in [int(x) for x in hour_spec.split(',')]:
            return
            
        if day_spec != '*' and current_time.day not in [int(x) for x in day_spec.split(',')]:
            return
            
        if month_spec != '*' and current_time.month not in [int(x) for x in month_spec.split(',')]:
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