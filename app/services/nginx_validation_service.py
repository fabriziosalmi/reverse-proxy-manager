import os
import re
import tempfile
import paramiko
from app.models.models import db, Node, DeploymentLog
from app.services.logger_service import log_activity

class NginxValidationService:
    """Service for validating and testing Nginx configurations before deployment"""
    
    @staticmethod
    def validate_config_syntax(config_content):
        """
        Validate the Nginx configuration syntax locally
        
        Args:
            config_content: String containing the Nginx configuration
            
        Returns:
            tuple: (is_valid, error_message)
        """
        # Basic syntax validation
        errors = []
        
        # Check for unmatched brackets
        open_count = config_content.count('{')
        close_count = config_content.count('}')
        if open_count != close_count:
            errors.append(f"Unmatched brackets: {open_count} opening vs {close_count} closing")
        
        # Check for missing semicolons in non-comment, non-block lines
        lines = config_content.split('\n')
        for i, line in enumerate(lines):
            # Skip comments, empty lines, and lines with blocks
            line_stripped = line.strip()
            if not line_stripped or line_stripped.startswith('#') or '{' in line or '}' in line:
                continue
                
            # Check if the line is missing a semicolon
            if not line_stripped.endswith(';'):
                errors.append(f"Line {i+1} may be missing a semicolon: {line_stripped}")
        
        # Check for common directive issues
        location_pattern = re.compile(r'location\s+([^{]+)\s*{')
        for i, line in enumerate(lines):
            if 'location' in line and '{' in line:
                match = location_pattern.search(line)
                if match and '//' in match.group(1):
                    errors.append(f"Line {i+1} has potentially invalid location path: {line.strip()}")
        
        # Return validation results
        is_valid = len(errors) == 0
        error_message = "\n".join(errors) if errors else "Configuration appears valid"
        
        return is_valid, error_message
    
    @staticmethod
    def test_config_on_node(node_id, config_content, domain):
        """
        Test the configuration on a remote node using nginx -t
        
        Args:
            node_id: ID of the node to test on
            config_content: Nginx configuration content
            domain: Domain name for the configuration
            
        Returns:
            tuple: (is_valid, error_message)
        """
        node = Node.query.get(node_id)
        if not node:
            return False, "Node not found"
        
        try:
            # Connect to the node via SSH
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
            
            # Create a temporary file for testing - WRAP SERVER BLOCK IN HTTP CONTEXT
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp:
                # Wrap the server block in an http block to make it a valid standalone config
                wrapped_content = "http {\n" + config_content + "\n}"
                temp.write(wrapped_content)
                temp_path = temp.name
            
            # Upload the config to a temporary location on the remote server
            sftp = ssh_client.open_sftp()
            remote_temp_path = f"/tmp/{domain}_nginx_test.conf"
            sftp.put(temp_path, remote_temp_path)
            sftp.close()
            
            # Enhanced nginx executable discovery specifically for Ubuntu systems
            
            # First try standard environment PATH with a full env sourcing
            stdin, stdout, stderr = ssh_client.exec_command("bash -l -c 'which nginx' 2>/dev/null || echo 'not found'")
            result = stdout.read().decode('utf-8').strip()
            if result != 'not found' and 'nginx' in result:
                nginx_path = result
            else:
                # Try common Ubuntu/Debian installation paths
                nginx_paths = [
                    "/usr/sbin/nginx",            # Standard Debian/Ubuntu location
                    "/usr/bin/nginx",             # Alternative location
                    "/usr/local/nginx/sbin/nginx", # Manual install common location
                    "/usr/local/sbin/nginx",      # Some package managers
                    "/usr/share/nginx/sbin/nginx", # Some package managers
                    "/opt/nginx/sbin/nginx",      # Custom installs
                    "/snap/bin/nginx"             # Snap installation
                ]
                
                # Try to find working nginx path
                nginx_path = None
                for path in nginx_paths:
                    stdin, stdout, stderr = ssh_client.exec_command(f"test -x {path} && echo {path} || echo 'not found'")
                    result = stdout.read().decode('utf-8').strip()
                    if result != 'not found':
                        nginx_path = result
                        break
            
            # If nginx binary still not found, try active service detection
            if not nginx_path:
                # Check if nginx service is active and get its path
                stdin, stdout, stderr = ssh_client.exec_command("systemctl status nginx 2>/dev/null | grep 'Main PID' | awk '{print $3}' || echo 'not found'")
                result = stdout.read().decode('utf-8').strip()
                if result != 'not found' and result.isdigit():
                    # Get the executable path from the process
                    pid = result
                    stdin, stdout, stderr = ssh_client.exec_command(f"readlink -f /proc/{pid}/exe 2>/dev/null || echo 'not found'")
                    result = stdout.read().decode('utf-8').strip()
                    if result != 'not found' and 'nginx' in result:
                        nginx_path = result
            
            # If still not found, try a comprehensive file search
            if not nginx_path:
                # Try finding executable with dpkg (Debian/Ubuntu package manager)
                stdin, stdout, stderr = ssh_client.exec_command("dpkg -l | grep nginx | awk '{print $2}' | grep -v lib | head -1 || echo 'not found'")
                result = stdout.read().decode('utf-8').strip()
                if result != 'not found':
                    # If any package is found, try dpkg to find binary
                    package_name = result
                    stdin, stdout, stderr = ssh_client.exec_command(f"dpkg -L {package_name} | grep bin/nginx || echo 'not found'")
                    result = stdout.read().decode('utf-8').strip()
                    if result != 'not found' and 'nginx' in result:
                        # Take the first line as the binary path
                        nginx_path = result.split('\n')[0]
            
            # Last resort: deep file search
            if not nginx_path:
                # This might be slow but will find nginx in most cases
                stdin, stdout, stderr = ssh_client.exec_command("find /usr /etc /opt /snap -name nginx -type f -executable 2>/dev/null | head -1 || echo 'not found'")
                result = stdout.read().decode('utf-8').strip()
                if result != 'not found':
                    nginx_path = result
            
            # If nginx binary still not found, provide installation instructions
            if not nginx_path:
                # Try to determine the OS for better help message
                stdin, stdout, stderr = ssh_client.exec_command("lsb_release -ds 2>/dev/null || cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d '\"' -f 2 || echo 'Unknown'")
                os_info = stdout.read().decode('utf-8').strip()
                
                if "Ubuntu" in os_info or "Debian" in os_info:
                    return False, f"Could not find nginx executable on the server ({os_info}). Please install nginx using: sudo apt update && sudo apt install -y nginx"
                else:
                    return False, f"Could not find nginx executable on the server ({os_info}). Please check nginx installation."
            
            # Test the configuration
            test_command = f"{nginx_path} -t -c {remote_temp_path} 2>&1 || echo 'Test failed'"
            stdin, stdout, stderr = ssh_client.exec_command(test_command)
            test_output = stdout.read().decode('utf-8')
            
            # Remove temporary files
            ssh_client.exec_command(f"rm -f {remote_temp_path}")
            os.unlink(temp_path)
            
            # Check the test results
            is_valid = "test is successful" in test_output.lower() or "test failed" not in test_output.lower()
            
            # Log the test
            if not is_valid:
                log_activity('warning', f"Nginx config test failed for {domain} on node {node.name}: {test_output}")
            else:
                # If test succeeded, log the nginx path we found for future reference
                log_activity('info', f"Nginx config test successful using binary at {nginx_path}")
                
                # Store the detected nginx path in node properties for future use if it's different
                if hasattr(node, 'detected_nginx_path') and node.detected_nginx_path != nginx_path:
                    node.detected_nginx_path = nginx_path
                    db.session.commit()
            
            ssh_client.close()
            return is_valid, test_output.strip()
            
        except Exception as e:
            return False, f"Error testing config: {str(e)}"
    
    @staticmethod
    def validate_ssl_config(config_content):
        """
        Validate SSL configuration in the Nginx config
        
        Args:
            config_content: String containing the Nginx configuration
            
        Returns:
            tuple: (is_valid, warnings)
        """
        warnings = []
        
        # Check if we have SSL configuration
        if "ssl" in config_content:
            # Check for cipher configuration
            if "ssl_ciphers" not in config_content:
                warnings.append("SSL ciphers not explicitly set. Using Nginx defaults which may not be secure.")
            
            # Check for protocols
            if "ssl_protocols" not in config_content:
                warnings.append("SSL protocols not explicitly set. Older protocols like TLSv1.0 might be enabled.")
            elif "TLSv1 " in config_content or "SSLv3" in config_content:
                warnings.append("Insecure SSL/TLS protocols detected. Consider using only TLSv1.2 and TLSv1.3.")
            
            # Check for OCSP stapling
            if "ssl_stapling" not in config_content:
                warnings.append("OCSP stapling not enabled. Consider enabling for better SSL performance.")
            
            # Check for HSTS
            if "Strict-Transport-Security" not in config_content:
                warnings.append("HTTP Strict Transport Security (HSTS) header not set. Consider adding for better security.")
        
        is_valid = len(warnings) == 0
        return is_valid, warnings
    
    @staticmethod
    def validate_security_headers(config_content):
        """
        Validate security headers in the Nginx config
        
        Args:
            config_content: String containing the Nginx configuration
            
        Returns:
            tuple: (is_valid, warnings)
        """
        warnings = []
        important_headers = [
            ("X-Content-Type-Options", "Prevents MIME-sniffing"),
            ("X-Frame-Options", "Prevents clickjacking"),
            ("X-XSS-Protection", "Helps prevent XSS attacks"),
            ("Content-Security-Policy", "Restricts resource loading"),
        ]
        
        for header, description in important_headers:
            if header not in config_content:
                warnings.append(f"{header} header not set. {description}.")
        
        is_valid = len(warnings) == 0
        return is_valid, warnings