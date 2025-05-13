"""
Simplified test script to verify the notification system for failed deployments
"""

from flask import Flask
from app import create_app
from app.models.models import DeploymentLog, SystemSetting, db
from app.services.email_service import send_failed_deployment_notification
import datetime

# Create the Flask app and application context
app = create_app()

with app.app_context():
    # Check current notification settings
    print("Current Notification Settings:")
    print("Email notifications enabled:", SystemSetting.get('email_enable_notifications', 'False'))
    print("Email notification events:", SystemSetting.get('email_notification_events', ''))
    
    # If notifications are not enabled, enable them for testing
    if SystemSetting.get('email_enable_notifications', 'False').lower() != 'true':
        print("\nEnabling email notifications for testing...")
        enable_setting = SystemSetting.query.filter_by(key='email_enable_notifications').first()
        if enable_setting:
            enable_setting.value = 'True'
        else:
            enable_setting = SystemSetting(key='email_enable_notifications', value='True')
            db.session.add(enable_setting)
    
    # Ensure failed_deployment is in the notification events
    events = SystemSetting.get('email_notification_events', '')
    events_list = events.split(',') if events else []
    
    if 'failed_deployment' not in events_list:
        print("\nAdding failed_deployment to notification events...")
        events_list.append('failed_deployment')
        events_setting = SystemSetting.query.filter_by(key='email_notification_events').first()
        if events_setting:
            events_setting.value = ','.join(events_list)
        else:
            events_setting = SystemSetting(key='email_notification_events', value=','.join(events_list))
            db.session.add(events_setting)
    
    # Configure required email settings if they don't exist
    required_email_settings = {
        'email_smtp_server': 'smtp.example.com',
        'email_smtp_port': '587',
        'email_smtp_user': 'test@example.com',
        'email_smtp_password': 'password123',
        'email_sender': 'notifications@example.com',
        'email_use_tls': 'True'
    }
    
    print("\nVerifying email settings...")
    for key, value in required_email_settings.items():
        setting = SystemSetting.query.filter_by(key=key).first()
        if not setting:
            print(f"Adding setting: {key}")
            setting = SystemSetting(key=key, value=value)
            db.session.add(setting)
    
    # Commit settings changes
    db.session.commit()
    
    # Create a mock deployment log object for testing
    class MockDeploymentLog:
        def __init__(self):
            self.id = 1
            self.site_id = 1
            self.node_id = 1
            self.action = "deploy"
            self.status = "error"
            self.message = "This is a test deployment error message"
            self.created_at = datetime.datetime.now()
            self.user_id = None
    
    # Create a mock site and node objects
    class MockSite:
        def __init__(self):
            self.id = 1
            self.domain = "test.example.com"
            self.user_id = None
    
    class MockNode:
        def __init__(self):
            self.id = 1
            self.name = "Test Node"
            self.ip_address = "192.168.1.100"
    
    # Monkeypatch the query methods to return our mocks
    def mock_site_get(site_id):
        return MockSite()
    
    def mock_node_get(node_id):
        return MockNode()
    
    import app.models.models
    original_site_get = app.models.models.Site.query.get
    original_node_get = app.models.models.Node.query.get
    
    app.models.models.Site.query.get = mock_site_get
    app.models.models.Node.query.get = mock_node_get
    
    mock_deployment = MockDeploymentLog()
    
    # Test sending notification
    print("\nTesting email_service.send_failed_deployment_notification...")
    try:
        success, message = send_failed_deployment_notification(mock_deployment)
        print(f"Send failed deployment notification result: {success}, {message}")
    except Exception as e:
        print(f"Error sending failed deployment notification: {str(e)}")
    
    # Restore original query methods
    app.models.models.Site.query.get = original_site_get
    app.models.models.Node.query.get = original_node_get
    
    # Test our deployment_notification_service
    print("\nTesting deployment_notification_service.notify_on_failed_deployment...")
    try:
        from app.services.deployment_notification_service import notify_on_failed_deployment
        result = notify_on_failed_deployment(mock_deployment)
        print("Notification service result:", result)
    except Exception as e:
        print(f"Error in notification service: {str(e)}")
    
    print("\nTest completed successfully!")
