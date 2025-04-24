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
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    
    try:
        # Get email settings from system settings
        smtp_server = SystemSetting.get('email_smtp_server')
        smtp_port = int(SystemSetting.get('email_smtp_port', '587'))
        smtp_username = SystemSetting.get('email_smtp_username')
        smtp_password = SystemSetting.get('email_smtp_password')
        from_address = SystemSetting.get('email_smtp_from_address')
        enable_ssl = SystemSetting.get('email_enable_ssl', 'False').lower() == 'true'
        
        # If no settings found, try to get them from app config
        if not smtp_server:
            smtp_server = current_app.config.get('MAIL_SERVER')
            smtp_port = current_app.config.get('MAIL_PORT', 587)
            smtp_username = current_app.config.get('MAIL_USERNAME')
            smtp_password = current_app.config.get('MAIL_PASSWORD')
            from_address = current_app.config.get('MAIL_DEFAULT_SENDER')
            enable_ssl = current_app.config.get('MAIL_USE_SSL', False)
        
        # If still no settings, return error
        if not smtp_server or not smtp_username or not smtp_password or not from_address:
            return False, "Email settings not configured. Please configure SMTP settings first."
        
        # If no recipient provided, use the first admin user's email
        if not recipient_email:
            admin_user = User.query.filter_by(role='admin').first()
            if admin_user:
                recipient_email = admin_user.email
            else:
                return False, "No recipient email provided and no admin users found."
        
        # Create the message
        msg = MIMEMultipart()
        msg['From'] = from_address
        msg['To'] = recipient_email
        msg['Subject'] = "Test Email from Reverse Proxy Manager"
        
        # Add body to the email
        body = """
        This is a test email from your Reverse Proxy Manager instance.
        
        If you received this email, your email configuration is working correctly.
        
        ---
        This is an automated test message. Please do not reply.
        """
        msg.attach(MIMEText(body, 'plain'))
        
        # Connect to the SMTP server
        if enable_ssl:
            server = smtplib.SMTP_SSL(smtp_server, smtp_port)
        else:
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.ehlo()
            server.starttls()
            server.ehlo()
        
        # Login to the server
        server.login(smtp_username, smtp_password)
        
        # Send the email
        server.sendmail(from_address, recipient_email, msg.as_string())
        
        # Close the connection
        server.quit()
        
        # Log the successful test
        from app.services.logger_service import log_activity
        log_activity(
            category='system',
            action='test_email',
            resource_type='email',
            details=f"Email test successful to {recipient_email}"
        )
        
        return True, f"Test email sent successfully to {recipient_email}"
        
    except Exception as e:
        # Log the error
        import logging
        logging.error(f"Error sending test email: {str(e)}")
        
        from app.services.logger_service import log_activity
        log_activity(
            category='error',
            action='test_email',
            resource_type='email',
            details=f"Error sending test email: {str(e)}"
        )
        
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
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    
    try:
        # Get email settings from system settings
        smtp_server = SystemSetting.get('email_smtp_server')
        smtp_port = int(SystemSetting.get('email_smtp_port', '587'))
        smtp_username = SystemSetting.get('email_smtp_username')
        smtp_password = SystemSetting.get('email_smtp_password')
        from_address = SystemSetting.get('email_smtp_from_address')
        enable_ssl = SystemSetting.get('email_enable_ssl', 'False').lower() == 'true'
        
        # If no settings found, try to get them from app config
        if not smtp_server:
            smtp_server = current_app.config.get('MAIL_SERVER')
            smtp_port = current_app.config.get('MAIL_PORT', 587)
            smtp_username = current_app.config.get('MAIL_USERNAME')
            smtp_password = current_app.config.get('MAIL_PASSWORD')
            from_address = current_app.config.get('MAIL_DEFAULT_SENDER')
            enable_ssl = current_app.config.get('MAIL_USE_SSL', False)
        
        # If still no settings, return error
        if not smtp_server or not smtp_username or not smtp_password or not from_address:
            return False, "Email settings not configured. Please configure SMTP settings first."
        
        # Get admin users' email addresses
        admin_users = User.query.filter_by(role='admin').all()
        if not admin_users:
            return False, "No admin users found to notify."
        
        recipient_emails = [user.email for user in admin_users]
        
        # Create the message
        msg = MIMEMultipart()
        msg['From'] = from_address
        msg['To'] = ", ".join(recipient_emails)
        msg['Subject'] = f"ALERT: {len(expiring_certificates)} SSL Certificates Expiring Soon"
        
        # Build the email body
        body = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .expired {{ color: red; font-weight: bold; }}
                .warning {{ color: orange; font-weight: bold; }}
            </style>
        </head>
        <body>
            <h2>SSL Certificate Expiration Alert</h2>
            <p>The following SSL certificates are expiring soon or have already expired:</p>
            
            <table>
                <tr>
                    <th>Domain</th>
                    <th>Status</th>
                    <th>Days Remaining</th>
                    <th>Site</th>
                </tr>
        """
        
        # Sort certificates by days remaining (ascending)
        sorted_certs = sorted(expiring_certificates, key=lambda x: x.get('days_remaining', 0))
        
        # Add certificate information to the email
        for cert in sorted_certs:
            # Get additional information
            certificate = SSLCertificate.query.get(cert['id'])
            site = Site.query.get(cert['site_id']) if cert['site_id'] else None
            site_name = site.name if site else "Unknown"
            
            # Determine status class
            status_class = "expired" if cert.get('expired', False) or cert.get('days_remaining', 0) == 0 else "warning"
            status_text = "Expired" if cert.get('expired', False) or cert.get('days_remaining', 0) == 0 else "Expiring Soon"
            
            body += f"""
                <tr>
                    <td>{cert['domain']}</td>
                    <td class="{status_class}">{status_text}</td>
                    <td class="{status_class}">{cert.get('days_remaining', 0)} days</td>
                    <td>{site_name}</td>
                </tr>
            """
        
        body += """
            </table>
            
            <p>Please renew these certificates as soon as possible to avoid service interruption.</p>
            
            <p>This is an automated notification from your Reverse Proxy Manager.</p>
        </body>
        </html>
        """
        
        # Attach the HTML content
        msg.attach(MIMEText(body, 'html'))
        
        # Connect to the SMTP server
        if enable_ssl:
            server = smtplib.SMTP_SSL(smtp_server, smtp_port)
        else:
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.ehlo()
            server.starttls()
            server.ehlo()
        
        # Login to the server
        server.login(smtp_username, smtp_password)
        
        # Send the email
        server.sendmail(from_address, recipient_emails, msg.as_string())
        
        # Close the connection
        server.quit()
        
        # Log the successful notification
        from app.services.logger_service import log_activity
        log_activity(
            category='system',
            action='send_email',
            resource_type='ssl',
            details=f"Certificate expiry notification sent to {len(recipient_emails)} admin users"
        )
        
        return True, f"Certificate expiry notification sent to {len(recipient_emails)} admin users"
        
    except Exception as e:
        # Log the error
        import logging
        logging.error(f"Error sending certificate expiry notification: {str(e)}")
        
        from app.services.logger_service import log_activity
        log_activity(
            category='error',
            action='send_email',
            resource_type='ssl',
            details=f"Error sending certificate expiry notification: {str(e)}"
        )
        
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
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    
    try:
        # Get email settings from system settings
        smtp_server = SystemSetting.get('email_smtp_server')
        smtp_port = int(SystemSetting.get('email_smtp_port', '587'))
        smtp_username = SystemSetting.get('email_smtp_username')
        smtp_password = SystemSetting.get('email_smtp_password')
        from_address = SystemSetting.get('email_smtp_from_address')
        enable_ssl = SystemSetting.get('email_enable_ssl', 'False').lower() == 'true'
        
        # If no settings found, try to get them from app config
        if not smtp_server:
            smtp_server = current_app.config.get('MAIL_SERVER')
            smtp_port = current_app.config.get('MAIL_PORT', 587)
            smtp_username = current_app.config.get('MAIL_USERNAME')
            smtp_password = current_app.config.get('MAIL_PASSWORD')
            from_address = current_app.config.get('MAIL_DEFAULT_SENDER')
            enable_ssl = current_app.config.get('MAIL_USE_SSL', False)
        
        # If still no settings, return error
        if not smtp_server or not smtp_username or not smtp_password or not from_address:
            return False, "Email settings not configured. Please configure SMTP settings first."
        
        # Get admin users' email addresses
        admin_users = User.query.filter_by(role='admin').all()
        if not admin_users:
            return False, "No admin users found to notify."
        
        recipient_emails = [user.email for user in admin_users]
        
        # Create the message
        msg = MIMEMultipart()
        msg['From'] = from_address
        msg['To'] = ", ".join(recipient_emails)
        
        # Determine subject based on severity
        if nodes_down:
            msg['Subject'] = f"CRITICAL ALERT: {len(nodes_down)} Nodes Unreachable"
        else:
            msg['Subject'] = f"WARNING: {len(nodes_warning)} Nodes Have Performance Issues"
        
        # Build the email body
        body = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                table {{ border-collapse: collapse; width: 100%; margin-bottom: 20px; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .critical {{ color: red; font-weight: bold; }}
                .warning {{ color: orange; font-weight: bold; }}
                .high {{ background-color: #ffdddd; }}
            </style>
        </head>
        <body>
            <h2>Node Health Status Alert</h2>
        """
        
        # Add information about down nodes
        if nodes_down:
            body += f"""
            <h3 class="critical">Critical: {len(nodes_down)} Nodes Unreachable</h3>
            <p>The following nodes are currently unreachable:</p>
            
            <table>
                <tr>
                    <th>Node Name</th>
                    <th>IP Address</th>
                    <th>Status</th>
                    <th>Error</th>
                </tr>
            """
            
            for node in nodes_down:
                body += f"""
                <tr>
                    <td class="critical">{node['name']}</td>
                    <td>{node['ip_address']}</td>
                    <td class="critical">Unreachable</td>
                    <td>{node.get('error', 'Unknown error')}</td>
                </tr>
                """
            
            body += """
            </table>
            <p>Please check these nodes immediately as they may be offline or experiencing connectivity issues.</p>
            """
        
        # Add information about nodes with performance issues
        if nodes_warning:
            body += f"""
            <h3 class="warning">Warning: {len(nodes_warning)} Nodes With High Resource Usage</h3>
            <p>The following nodes are experiencing high resource usage:</p>
            
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
                # Highlight high usage cells
                cpu_class = "high" if node.get('cpu_usage', 0) > 80 else ""
                mem_class = "high" if node.get('memory_usage', 0) > 80 else ""
                disk_class = "high" if node.get('disk_usage', 0) > 80 else ""
                
                body += f"""
                <tr>
                    <td class="warning">{node['name']}</td>
                    <td>{node['ip_address']}</td>
                    <td class="{cpu_class}">{node.get('cpu_usage', 'N/A')}%</td>
                    <td class="{mem_class}">{node.get('memory_usage', 'N/A')}%</td>
                    <td class="{disk_class}">{node.get('disk_usage', 'N/A')}%</td>
                </tr>
                """
            
            body += """
            </table>
            <p>Please monitor these nodes as high resource usage may lead to performance degradation or service outages.</p>
            """
        
        body += """
            <p>For more information, please check the system dashboard.</p>
            
            <p>This is an automated notification from your Reverse Proxy Manager.</p>
        </body>
        </html>
        """
        
        # Attach the HTML content
        msg.attach(MIMEText(body, 'html'))
        
        # Connect to the SMTP server
        if enable_ssl:
            server = smtplib.SMTP_SSL(smtp_server, smtp_port)
        else:
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.ehlo()
            server.starttls()
            server.ehlo()
        
        # Login to the server
        server.login(smtp_username, smtp_password)
        
        # Send the email
        server.sendmail(from_address, recipient_emails, msg.as_string())
        
        # Close the connection
        server.quit()
        
        # Log the successful notification
        from app.services.logger_service import log_activity
        log_activity(
            category='system',
            action='send_email',
            resource_type='node',
            details=f"Node health notification sent to {len(recipient_emails)} admin users"
        )
        
        return True, f"Node health notification sent to {len(recipient_emails)} admin users"
        
    except Exception as e:
        # Log the error
        import logging
        logging.error(f"Error sending node health notification: {str(e)}")
        
        from app.services.logger_service import log_activity
        log_activity(
            category='error',
            action='send_email',
            resource_type='node',
            details=f"Error sending node health notification: {str(e)}"
        )
        
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
    import smtplib
    from email.mime.text import MIMEText
    from email.mime.multipart import MIMEMultipart
    
    try:
        # Check if this type of notification is enabled
        enable_notifications = SystemSetting.get('email_enable_notifications', 'False').lower() == 'true'
        notification_events = SystemSetting.get('email_notification_events', '')
        
        if not enable_notifications or 'failed_deployment' not in notification_events.split(','):
            return False, "Failed deployment notifications are not enabled"
        
        # Get email settings from system settings
        smtp_server = SystemSetting.get('email_smtp_server')
        smtp_port = int(SystemSetting.get('email_smtp_port', '587'))
        smtp_username = SystemSetting.get('email_smtp_username')
        smtp_password = SystemSetting.get('email_smtp_password')
        from_address = SystemSetting.get('email_smtp_from_address')
        enable_ssl = SystemSetting.get('email_enable_ssl', 'False').lower() == 'true'
        
        # If no settings found, try to get them from app config
        if not smtp_server:
            smtp_server = current_app.config.get('MAIL_SERVER')
            smtp_port = current_app.config.get('MAIL_PORT', 587)
            smtp_username = current_app.config.get('MAIL_USERNAME')
            smtp_password = current_app.config.get('MAIL_PASSWORD')
            from_address = current_app.config.get('MAIL_DEFAULT_SENDER')
            enable_ssl = current_app.config.get('MAIL_USE_SSL', False)
        
        # If still no settings, return error
        if not smtp_server or not smtp_username or not smtp_password or not from_address:
            return False, "Email settings not configured. Please configure SMTP settings first."
        
        # Get admin users' email addresses
        admin_users = User.query.filter_by(role='admin').all()
        if not admin_users:
            return False, "No admin users found to notify."
        
        recipient_emails = [user.email for user in admin_users]
        
        # Get related site and node
        site = Site.query.get(deployment.site_id) if deployment.site_id else None
        node = Node.query.get(deployment.node_id) if deployment.node_id else None
        
        # Create the message
        msg = MIMEMultipart()
        msg['From'] = from_address
        msg['To'] = ", ".join(recipient_emails)
        msg['Subject'] = f"ERROR: Deployment Failed for {site.domain if site else 'Unknown Site'}"
        
        # Build the email body
        body = f"""
        <html>
        <head>
            <style>
                body {{ font-family: Arial, sans-serif; }}
                table {{ border-collapse: collapse; width: 100%; }}
                th, td {{ border: 1px solid #ddd; padding: 8px; text-align: left; }}
                th {{ background-color: #f2f2f2; }}
                .error {{ color: red; font-weight: bold; }}
                pre {{ background-color: #f5f5f5; padding: 10px; overflow-x: auto; }}
            </style>
        </head>
        <body>
            <h2>Deployment Failed</h2>
            
            <table>
                <tr>
                    <th>Site</th>
                    <td>{site.name if site else 'Unknown'} ({site.domain if site else 'Unknown Domain'})</td>
                </tr>
                <tr>
                    <th>Node</th>
                    <td>{node.name if node else 'Unknown'} ({node.ip_address if node else 'Unknown IP'})</td>
                </tr>
                <tr>
                    <th>Action</th>
                    <td>{deployment.action}</td>
                </tr>
                <tr>
                    <th>Status</th>
                    <td class="error">{deployment.status}</td>
                </tr>
                <tr>
                    <th>Time</th>
                    <td>{deployment.created_at.strftime('%Y-%m-%d %H:%M:%S')}</td>
                </tr>
                <tr>
                    <th>Executed By</th>
                    <td>{deployment.user.username if deployment.user else 'System'}</td>
                </tr>
            </table>
            
            <h3>Error Details</h3>
            <pre>{deployment.message}</pre>
            
            <p>Please check the system logs for more information.</p>
            
            <p>This is an automated notification from your Reverse Proxy Manager.</p>
        </body>
        </html>
        """
        
        # Attach the HTML content
        msg.attach(MIMEText(body, 'html'))
        
        # Connect to the SMTP server
        if enable_ssl:
            server = smtplib.SMTP_SSL(smtp_server, smtp_port)
        else:
            server = smtplib.SMTP(smtp_server, smtp_port)
            server.ehlo()
            server.starttls()
            server.ehlo()
        
        # Login to the server
        server.login(smtp_username, smtp_password)
        
        # Send the email
        server.sendmail(from_address, recipient_emails, msg.as_string())
        
        # Close the connection
        server.quit()
        
        # Log the successful notification
        from app.services.logger_service import log_activity
        log_activity(
            category='system',
            action='send_email',
            resource_type='deployment',
            resource_id=deployment.id,
            details=f"Deployment failure notification sent to {len(recipient_emails)} admin users"
        )
        
        return True, f"Deployment failure notification sent to {len(recipient_emails)} admin users"
        
    except Exception as e:
        # Log the error
        import logging
        logging.error(f"Error sending deployment failure notification: {str(e)}")
        
        from app.services.logger_service import log_activity
        log_activity(
            category='error',
            action='send_email',
            resource_type='deployment',
            resource_id=deployment.id if deployment else None,
            details=f"Error sending deployment failure notification: {str(e)}"
        )
        
        return False, f"Failed to send deployment failure notification: {str(e)}"