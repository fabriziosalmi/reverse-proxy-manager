"""
Deployment Notification Service
Handles notifications for deployment events
"""

from app.models.models import SystemSetting, DeploymentLog
from app.services.email_service import send_failed_deployment_notification
from flask import current_app
import logging

logger = logging.getLogger(__name__)

def notify_on_failed_deployment(deployment_log):
    """
    Notify users when a deployment fails
    
    Args:
        deployment_log (DeploymentLog): The deployment log record with failure
    
    Returns:
        bool: Whether the notification was sent successfully
    """
    try:
        # Check if notifications are enabled
        enable_notifications = SystemSetting.get('email_enable_notifications', 'False').lower() == 'true'
        notification_events = SystemSetting.get('email_notification_events', '')
        
        # Only proceed if notifications are enabled and the failed_deployment event is configured
        if enable_notifications and 'failed_deployment' in notification_events.split(','):
            # Send notification
            success, message = send_failed_deployment_notification(deployment_log)
            
            if success:
                logger.info(f"Sent failed deployment notification for {deployment_log.site_id} on node {deployment_log.node_id}: {message}")
                return True
            else:
                logger.error(f"Failed to send deployment notification: {message}")
                return False
        else:
            logger.debug("Failed deployment notification skipped: notifications disabled or event not configured")
            return False
    except Exception as e:
        logger.error(f"Error in deployment notification service: {str(e)}")
        return False
