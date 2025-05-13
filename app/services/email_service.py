def test_email_configuration(recipient_email=None):
    """
    Test the email configuration by sending a test email
    
    Args:
        recipient_email (str): Optional recipient email. If not provided, uses the configured admin email.
        
    Returns:
        tuple: (success, message)
    """
    from flask import current_app
    from app.models.models import SystemSetting, User
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    import smtplib
    
    try:
        # Get email settings from system settings
        smtp_server = SystemSetting.get('email_smtp_server')
        smtp_port = int(SystemSetting.get('email_smtp_port', 587))
        smtp_user = SystemSetting.get('email_smtp_user')
        smtp_password = SystemSetting.get('email_smtp_password')
        sender_email = SystemSetting.get('email_sender', smtp_user)
        use_tls = SystemSetting.get('email_use_tls', 'True') == 'True'
        
        # Use provided recipient or get admin email
        if not recipient_email:
            admin = User.query.filter_by(is_admin=True).first()
            recipient_email = admin.email if admin else current_app.config.get('ADMIN_EMAIL')
            
        if not recipient_email:
            return False, "No recipient email specified and no admin email found"
            
        # Prepare the email
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = recipient_email
        msg['Subject'] = "ItaliaProxy Email Configuration Test"
        
        body = "This is a test email from your ItaliaProxy system. If you're reading this, your email configuration is working correctly."
        msg.attach(MIMEText(body, 'plain'))
        
        # Connect to SMTP server and send email
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.ehlo()
        
        if use_tls:
            server.starttls()
            server.ehlo()
            
        if smtp_user and smtp_password:
            server.login(smtp_user, smtp_password)
            
        server.send_message(msg)
        server.quit()
        
        return True, f"Test email sent successfully to {recipient_email}"
        
    except Exception as e:
        return False, f"Failed to send test email: {str(e)}"


def send_certificate_expiry_notification(expiring_certificates):
    """
    Send an email notification about certificates that are expiring soon
    
    Args:
        expiring_certificates (list): List of certificate dictionaries with expiry info
        
    Returns:
        tuple: (success, message)
    """
    from flask import current_app
    from app.models.models import SystemSetting, User, SSLCertificate, Site
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    import smtplib
    from datetime import datetime
    
    try:
        # Get email settings from system settings
        smtp_server = SystemSetting.get('email_smtp_server')
        smtp_port = int(SystemSetting.get('email_smtp_port', 587))
        smtp_user = SystemSetting.get('email_smtp_user')
        smtp_password = SystemSetting.get('email_smtp_password')
        sender_email = SystemSetting.get('email_sender', smtp_user)
        use_tls = SystemSetting.get('email_use_tls', 'True') == 'True'
        
        # Get admin email
        admin = User.query.filter_by(is_admin=True).first()
        recipient_email = admin.email if admin else current_app.config.get('ADMIN_EMAIL')
        
        if not recipient_email:
            return False, "No admin email found to send notification"
            
        # Prepare the email
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = recipient_email
        msg['Subject'] = f"SSL Certificate Expiry Warning - {len(expiring_certificates)} Certificates"
        
        # Create the email body
        body = f"""
        <html>
        <head>
            <style>
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .expiring-soon {{ color: orange; }}
                .critical {{ color: red; font-weight: bold; }}
            </style>
        </head>
        <body>
            <h2>SSL Certificate Expiry Warning</h2>
            <p>The following SSL certificates are expiring soon and should be renewed:</p>
            <table>
                <tr>
                    <th>Domain</th>
                    <th>Expiry Date</th>
                    <th>Days Left</th>
                    <th>Certificate ID</th>
                </tr>
        """
        
        for cert in expiring_certificates:
            # Determine urgency class based on days left
            css_class = 'normal'
            if cert['days_left'] <= 7:
                css_class = 'critical'
            elif cert['days_left'] <= 14:
                css_class = 'expiring-soon'
                
            # Format the expiry date
            expiry_date = datetime.strptime(cert['expiry_date'], '%Y-%m-%d').strftime('%b %d, %Y')
            
            # Add row to table
            body += f"""
                <tr class="{css_class}">
                    <td>{cert['domain']}</td>
                    <td>{expiry_date}</td>
                    <td>{cert['days_left']}</td>
                    <td>{cert['cert_id']}</td>
                </tr>
            """
        
        body += """
            </table>
            <p>Please log in to the ItaliaProxy administration interface to renew these certificates.</p>
        </body>
        </html>
        """
        
        # Attach the HTML body
        msg.attach(MIMEText(body, 'html'))
        
        # Connect to SMTP server and send email
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.ehlo()
        
        if use_tls:
            server.starttls()
            server.ehlo()
            
        if smtp_user and smtp_password:
            server.login(smtp_user, smtp_password)
            
        server.send_message(msg)
        server.quit()
        
        return True, f"Certificate expiry notification sent successfully to {recipient_email}"
        
    except Exception as e:
        return False, f"Failed to send certificate expiry notification: {str(e)}"


def send_node_health_notification(nodes_down, nodes_warning):
    """
    Send an email notification about nodes that are down or have performance issues
    
    Args:
        nodes_down (list): List of node dictionaries that are unreachable
        nodes_warning (list): List of node dictionaries with high resource usage
        
    Returns:
        tuple: (success, message)
    """
    from flask import current_app
    from app.models.models import SystemSetting, User
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    import smtplib
    from datetime import datetime
    
    try:
        # Skip if no nodes to report
        if not nodes_down and not nodes_warning:
            return True, "No node issues to report"
            
        # Get email settings from system settings
        smtp_server = SystemSetting.get('email_smtp_server')
        smtp_port = int(SystemSetting.get('email_smtp_port', 587))
        smtp_user = SystemSetting.get('email_smtp_user')
        smtp_password = SystemSetting.get('email_smtp_password')
        sender_email = SystemSetting.get('email_sender', smtp_user)
        use_tls = SystemSetting.get('email_use_tls', 'True') == 'True'
        
        # Get admin email
        admin = User.query.filter_by(is_admin=True).first()
        recipient_email = admin.email if admin else current_app.config.get('ADMIN_EMAIL')
        
        if not recipient_email:
            return False, "No admin email found to send notification"
            
        # Prepare the email
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = recipient_email
        msg['Subject'] = f"Node Health Alert - {len(nodes_down)} Down, {len(nodes_warning)} Warning"
        
        # Create the email body
        body = f"""
        <html>
        <head>
            <style>
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .warning {{ color: orange; }}
                .critical {{ color: red; font-weight: bold; }}
            </style>
        </head>
        <body>
            <h2>Node Health Alert</h2>
        """
        
        # Add down nodes table if any
        if nodes_down:
            body += f"""
            <h3 class="critical">Unreachable Nodes ({len(nodes_down)})</h3>
            <table>
                <tr>
                    <th>Node Name</th>
                    <th>IP Address</th>
                    <th>Last Seen</th>
                </tr>
            """
            
            for node in nodes_down:
                last_seen = node.get('last_seen', 'Never')
                if isinstance(last_seen, datetime):
                    last_seen = last_seen.strftime('%Y-%m-%d %H:%M:%S')
                    
                body += f"""
                <tr class="critical">
                    <td>{node.get('name', 'Unknown')}</td>
                    <td>{node.get('ip_address', 'Unknown')}</td>
                    <td>{last_seen}</td>
                </tr>
                """
            
            body += "</table>"
        
        # Add warning nodes table if any
        if nodes_warning:
            body += f"""
            <h3 class="warning">Nodes with Performance Issues ({len(nodes_warning)})</h3>
            <table>
                <tr>
                    <th>Node Name</th>
                    <th>IP Address</th>
                    <th>CPU Usage</th>
                    <th>Memory Usage</th>
                    <th>Disk Usage</th>
                </tr>
            """
            
            for node in nodes_warning:
                body += f"""
                <tr class="warning">
                    <td>{node.get('name', 'Unknown')}</td>
                    <td>{node.get('ip_address', 'Unknown')}</td>
                    <td>{node.get('cpu_usage', 'Unknown')}</td>
                    <td>{node.get('memory_usage', 'Unknown')}</td>
                    <td>{node.get('disk_usage', 'Unknown')}</td>
                </tr>
                """
            
            body += "</table>"
        
        body += """
            <p>Please check the affected nodes as soon as possible.</p>
        </body>
        </html>
        """
        
        # Attach the HTML body
        msg.attach(MIMEText(body, 'html'))
        
        # Connect to SMTP server and send email
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.ehlo()
        
        if use_tls:
            server.starttls()
            server.ehlo()
            
        if smtp_user and smtp_password:
            server.login(smtp_user, smtp_password)
            
        server.send_message(msg)
        server.quit()
        
        return True, f"Node health notification sent successfully to {recipient_email}"
        
    except Exception as e:
        return False, f"Failed to send node health notification: {str(e)}"


def send_failed_deployment_notification(deployment):
    """
    Send an email notification about a failed deployment
    
    Args:
        deployment: DeploymentLog instance that failed
        
    Returns:
        tuple: (success, message)
    """
    from flask import current_app
    from app.models.models import SystemSetting, User, Site, Node
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    import smtplib
    from datetime import datetime
    
    try:
        # Get email settings from system settings
        smtp_server = SystemSetting.get('email_smtp_server')
        smtp_port = int(SystemSetting.get('email_smtp_port', 587))
        smtp_user = SystemSetting.get('email_smtp_user')
        smtp_password = SystemSetting.get('email_smtp_password')
        sender_email = SystemSetting.get('email_sender', smtp_user)
        use_tls = SystemSetting.get('email_use_tls', 'True') == 'True'
        
        # Get deployment details
        site = Site.query.get(deployment.site_id)
        node = Node.query.get(deployment.node_id)
        
        if not site or not node:
            return False, "Site or node information not available"
            
        # Get the appropriate recipient (site owner or admin)
        recipient_email = None
        
        # If deployment has a user_id, get that user's email
        if deployment.user_id:
            user = User.query.get(deployment.user_id)
            if user:
                recipient_email = user.email
                
        # If no user or user has no email, get site owner's email
        if not recipient_email and site.user_id:
            site_owner = User.query.get(site.user_id)
            if site_owner:
                recipient_email = site_owner.email
                
        # If still no recipient, use admin email
        if not recipient_email:
            admin = User.query.filter_by(is_admin=True).first()
            recipient_email = admin.email if admin else current_app.config.get('ADMIN_EMAIL')
            
        if not recipient_email:
            return False, "No recipient email found to send notification"
            
        # Prepare the email
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = recipient_email
        msg['Subject'] = f"Deployment Failed: {site.domain} on {node.name}"
        
        # Format the timestamp
        timestamp = deployment.created_at.strftime('%Y-%m-%d %H:%M:%S')
        
        # Create the email body
        body = f"""
        <html>
        <head>
            <style>
                .error {{ color: red; font-weight: bold; }}
                .details {{ background-color: #f9f9f9; padding: 10px; border: 1px solid #ddd; }}
            </style>
        </head>
        <body>
            <h2>Deployment Failed</h2>
            <p>A deployment has failed with the following details:</p>
            
            <h3>Deployment Information:</h3>
            <ul>
                <li><strong>Site:</strong> {site.domain}</li>
                <li><strong>Node:</strong> {node.name} ({node.ip_address})</li>
                <li><strong>Time:</strong> {timestamp}</li>
                <li><strong>Action:</strong> {deployment.action}</li>
            </ul>
            
            <h3 class="error">Error Message:</h3>
            <div class="details">
                <pre>{deployment.message}</pre>
            </div>
            
            <p>Please check the configuration and try the deployment again.</p>
            <p>If the problem persists, contact system support.</p>
        </body>
        </html>
        """
        
        # Attach the HTML body
        msg.attach(MIMEText(body, 'html'))
        
        # Connect to SMTP server and send email
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.ehlo()
        
        if use_tls:
            server.starttls()
            server.ehlo()
            
        if smtp_user and smtp_password:
            server.login(smtp_user, smtp_password)
            
        server.send_message(msg)
        server.quit()
        
        return True, f"Deployment failure notification sent successfully to {recipient_email}"
        
    except Exception as e:
        return False, f"Failed to send deployment failure notification: {str(e)}"


def send_security_alert_notification(alerts):
    """
    Send an email notification about security alerts detected in the system
    
    Args:
        alerts (list): List of security alert dictionaries with details
        
    Returns:
        tuple: (success, message)
    """
    from flask import current_app
    from app.models.models import SystemSetting, User
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    import smtplib
    from datetime import datetime
    
    try:
        # Skip if no alerts to report
        if not alerts:
            return True, "No security alerts to report"
            
        # Get email settings from system settings
        smtp_server = SystemSetting.get('email_smtp_server')
        smtp_port = int(SystemSetting.get('email_smtp_port', 587))
        smtp_user = SystemSetting.get('email_smtp_user')
        smtp_password = SystemSetting.get('email_smtp_password')
        sender_email = SystemSetting.get('email_sender', smtp_user)
        use_tls = SystemSetting.get('email_use_tls', 'True') == 'True'
        
        # Get admin email
        admin = User.query.filter_by(is_admin=True).first()
        recipient_email = admin.email if admin else current_app.config.get('ADMIN_EMAIL')
        
        if not recipient_email:
            return False, "No admin email found to send notification"
            
        # Prepare the email
        msg = MIMEMultipart()
        msg['From'] = sender_email
        msg['To'] = recipient_email
        msg['Subject'] = f"Security Alert - {len(alerts)} Potential Issues Detected"
        
        # Create the email body
        body = f"""
        <html>
        <head>
            <style>
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .high {{ color: red; font-weight: bold; }}
                .medium {{ color: orange; }}
                .low {{ color: #555; }}
            </style>
        </head>
        <body>
            <h2>Security Alerts</h2>
            <p>The following security alerts have been detected in your system:</p>
            <table>
                <tr>
                    <th>Severity</th>
                    <th>Type</th>
                    <th>Source</th>
                    <th>Description</th>
                    <th>Time</</th>
                </tr>
        """
        
        for alert in alerts:
            # Determine severity class
            severity = alert.get('severity', 'medium').lower()
            css_class = {
                'high': 'high',
                'medium': 'medium',
                'low': 'low'
            }.get(severity, 'medium')
            
            # Format timestamp
            timestamp = alert.get('timestamp')
            if isinstance(timestamp, datetime):
                timestamp = timestamp.strftime('%Y-%m-%d %H:%M:%S')
            else:
                timestamp = str(timestamp) if timestamp else 'Unknown'
                
            # Add row to table
            body += f"""
                <tr class="{css_class}">
                    <td>{severity.upper()}</td>
                    <td>{alert.get('type', 'Unknown')}</td>
                    <td>{alert.get('source', 'Unknown')}</td>
                    <td>{alert.get('description', 'No description provided')}</td>
                    <td>{timestamp}</td>
                </tr>
            """
        
        body += """
            </table>
            <p>Please review these security issues as soon as possible.</p>
            <p>If you believe these are false positives, you can adjust your security settings in the admin dashboard.</p>
        </body>
        </html>
        """
        
        # Attach the HTML body
        msg.attach(MIMEText(body, 'html'))
        
        # Connect to SMTP server and send email
        server = smtplib.SMTP(smtp_server, smtp_port)
        server.ehlo()
        
        if use_tls:
            server.starttls()
            server.ehlo()
            
        if smtp_user and smtp_password:
            server.login(smtp_user, smtp_password)
            
        server.send_message(msg)
        server.quit()
        
        return True, f"Security alert notification sent successfully to {recipient_email}"
        
    except Exception as e:
        return False, f"Failed to send security alert notification: {str(e)}"