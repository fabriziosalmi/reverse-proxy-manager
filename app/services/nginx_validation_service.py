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
            
            # Create a temporary file for testing
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp:
                temp.write(config_content)
                temp_path = temp.name
            
            # Upload the config to a temporary location on the remote server
            sftp = ssh_client.open_sftp()
            remote_temp_path = f"/tmp/{domain}_nginx_test.conf"
            sftp.put(temp_path, remote_temp_path)
            sftp.close()
            
            # Find the nginx executable path - try various common locations
            nginx_paths = [
                "nginx",                      # If in PATH
                "/usr/sbin/nginx",            # Debian/Ubuntu common location
                "/usr/local/nginx/sbin/nginx", # Manual install common location
                "/usr/local/sbin/nginx",      # Some package managers
                "/opt/nginx/sbin/nginx"       # Custom installs
            ]
            
            # Try to find working nginx path
            nginx_path = None
            for path in nginx_paths:
                stdin, stdout, stderr = ssh_client.exec_command(f"which {path} 2>/dev/null || echo 'not found'")
                result = stdout.read().decode('utf-8').strip()
                if result != 'not found' and 'nginx' in result:
                    nginx_path = path
                    break
            
            if not nginx_path:
                # As a last resort, try to find it using find command
                stdin, stdout, stderr = ssh_client.exec_command("find /usr -name nginx -type f -executable 2>/dev/null | head -1")
                result = stdout.read().decode('utf-8').strip()
                if result:
                    nginx_path = result
            
            if not nginx_path:
                return False, "Could not find nginx executable on the server. Please check nginx installation."
            
            # Test the configuration
            test_command = f"{nginx_path} -t -c {remote_temp_path} 2>&1 || echo 'Test failed'"
            stdin, stdout, stderr = ssh_client.exec_command(test_command)
            test_output = stdout.read().decode('utf-8')
            
            # Remove temporary files
            ssh_client.exec_command(f"rm -f {remote_temp_path}")
            os.unlink(temp_path)
            ssh_client.close()
            
            # Check the test results
            is_valid = "test is successful" in test_output.lower() or "test failed" not in test_output.lower()
            
            # Log the test
            if not is_valid:
                log_activity('warning', f"Nginx config test failed for {domain} on node {node.name}: {test_output}")
            
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