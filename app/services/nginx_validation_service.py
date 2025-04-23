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
            
            # Check if we're testing an HTTPS config that might have SSL certificate paths
            is_https_config = "ssl_certificate" in config_content
            
            # For HTTPS configs, we'll need to modify the content to allow testing without certificates
            if is_https_config:
                # Create a modified version by commenting out SSL certificate directives
                modified_content = re.sub(
                    r'(\s*)(ssl_certificate|ssl_certificate_key|ssl_trusted_certificate)(.+?);',
                    r'\1# \2\3; # Commented for testing',
                    config_content
                )
                
                # Also add dummy SSL directives for test to pass
                dummy_ssl_config = """
    # Dummy SSL certificates for testing only
    ssl_certificate /etc/nginx/ssl/dummy.crt;
    ssl_certificate_key /etc/nginx/ssl/dummy.key;
"""
                # Check if there's a custom_config section to add these after
                if "# Custom configuration" in modified_content:
                    modified_content = modified_content.replace(
                        "# Custom configuration", 
                        "# Custom configuration\n" + dummy_ssl_config
                    )
                else:
                    # Otherwise add before the closing bracket of the server block
                    modified_content = modified_content.replace(
                        "}", 
                        dummy_ssl_config + "}", 
                        1  # Replace only first occurrence
                    )
                
                # Create the dummy SSL cert directory if needed
                ssh_client.exec_command("sudo mkdir -p /etc/nginx/ssl")
                
                # Create dummy SSL certificate if it doesn't exist
                ssh_client.exec_command("""
                if [ ! -f /etc/nginx/ssl/dummy.crt ]; then
                    sudo openssl req -x509 -nodes -days 365 -newkey rsa:2048 \
                    -keyout /etc/nginx/ssl/dummy.key -out /etc/nginx/ssl/dummy.crt \
                    -subj "/CN=localhost" 2>/dev/null
                fi
                """)
                
                # Use the modified content for testing
                test_content = modified_content
                log_activity('info', f"Testing HTTPS config for {domain} with dummy certificates")
            else:
                # For HTTP configs, use the original content
                test_content = config_content
            
            # Create a temporary file for testing
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp:
                # Wrap the server block in an http block to make it a valid standalone config
                wrapped_content = "http {\n" + test_content + "\n}"
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
            
            # Special handling for SSL certificate errors in the test output
            if "SSL:" in test_output and "No such file or directory" in test_output:
                # This is expected for HTTPS sites without certificates yet
                if is_https_config:
                    is_valid = True
                    test_output = "Configuration valid (SSL certificate paths ignored for testing)"
                    log_activity('info', f"HTTPS config test for {domain} passed with SSL certificate warnings ignored")
                else:
                    is_valid = "test is successful" in test_output.lower() or "test failed" not in test_output.lower()
            else:
                # Regular test result check
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
    
    @staticmethod
    def test_config(config, site_name, skip_ssl_check=False):
        """
        Test Nginx configuration on local machine
        
        Args:
            config: Nginx configuration string
            site_name: Name of the site for the config file
            skip_ssl_check: Whether to ignore SSL certificate errors
            
        Returns:
            tuple: (is_valid, error_message)
        """
        try:
            # Create a temporary file with the configuration
            with tempfile.NamedTemporaryFile(suffix='.conf', delete=False) as f:
                f.write(config.encode('utf-8'))
                temp_file = f.name
            
            # Test the configuration with nginx -t
            if skip_ssl_check:
                # Use -c option only to avoid loading other configs with SSL directives
                cmd = f"nginx -t -c {temp_file}"
            else:
                cmd = f"nginx -t -c {temp_file}"
                
            result = os.system(cmd)
            
            # Clean up
            os.unlink(temp_file)
            
            if result == 0:
                return True, None
            else:
                return False, "Configuration test failed. Check nginx syntax."
                
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def test_config_on_node(node_id, config, site_name, skip_ssl_check=False):
        """
        Test Nginx configuration on a remote node
        
        Args:
            node_id: ID of the node
            config: Nginx configuration string
            site_name: Name of the site for the config file
            skip_ssl_check: Whether to ignore SSL certificate errors
            
        Returns:
            tuple: (is_valid, error_message)
        """
        node = Node.query.get(node_id)
        if not node:
            return False, "Node not found"
        
        try:
            # Connect to the node
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if node.ssh_key_path:
                ssh_client.connect(
                    hostname=node.ip_address,
                    port=node.ssh_port,
                    username=node.ssh_user,
                    key_filename=node.ssh_key_path
                )
            else:
                ssh_client.connect(
                    hostname=node.ip_address,
                    port=node.ssh_port,
                    username=node.ssh_user,
                    password=node.ssh_password
                )
            
            # Create a temporary file on the remote server
            temp_file = f"/tmp/{site_name}_nginx_test.conf"
            
            # Add comment for testing mode if skipping SSL check
            if skip_ssl_check:
                # Comment out SSL certificate lines to test basic syntax
                modified_config = re.sub(r'(\s*ssl_certificate\s+.+;)', r'#\1 # Commented for testing', config)
                modified_config = re.sub(r'(\s*ssl_certificate_key\s+.+;)', r'#\1 # Commented for testing', modified_config)
                
                # Add a note at the top of the config
                test_note = "# NOTE: SSL certificate directives are commented out for syntax testing only\n"
                modified_config = test_note + modified_config
                
                sftp = ssh_client.open_sftp()
                with sftp.file(temp_file, 'w') as f:
                    f.write(modified_config)
                sftp.close()
            else:
                sftp = ssh_client.open_sftp()
                with sftp.file(temp_file, 'w') as f:
                    f.write(config)
                sftp.close()
            
            # Test the configuration with nginx -t on the remote server
            cmd = f"nginx -t -c {temp_file}"
            stdin, stdout, stderr = ssh_client.exec_command(cmd)
            exit_status = stdout.channel.recv_exit_status()
            
            # Capture output
            stdout_output = stdout.read().decode('utf-8')
            stderr_output = stderr.read().decode('utf-8')
            
            # Parse output for specific SSL certificate errors
            ssl_cert_error = None
            combined_output = stdout_output + stderr_output
            
            # Look for common SSL certificate errors
            ssl_cert_patterns = [
                r"cannot load certificate \"([^\"]+)\"",
                r"SSL_CTX_use_certificate_file\(\) failed"
            ]
            
            for pattern in ssl_cert_patterns:
                ssl_match = re.search(pattern, combined_output)
                if ssl_match:
                    ssl_cert_error = True
                    break
            
            # Check if Nginx executable is not found
            nginx_missing = "nginx: command not found" in combined_output or "nginx: not found" in combined_output
            
            # Clean up
            ssh_client.exec_command(f"rm {temp_file}")
            ssh_client.close()
            
            if exit_status == 0:
                # Configuration is valid
                return True, None
            else:
                if nginx_missing:
                    return False, "Could not find nginx executable on the server. Please install nginx."
                
                elif ssl_cert_error and not skip_ssl_check:
                    # SSL certificate error detected
                    # Try again with SSL certificates commented out to test basic syntax
                    is_valid_without_ssl, error_message = NginxValidationService.test_config_on_node(
                        node_id, config, site_name, skip_ssl_check=True
                    )
                    
                    if is_valid_without_ssl:
                        # The configuration is valid except for the SSL certificate issue
                        return False, f"Nginx configuration test failed due to missing SSL certificates. " + \
                                    f"Basic configuration syntax is valid. " + \
                                    f"Error: {stderr_output.strip()}"
                    else:
                        # There are other syntax issues besides the SSL certificate
                        return False, f"Nginx configuration test failed: {stderr_output.strip()}"
                else:
                    # Other configuration error
                    return False, f"Nginx configuration test failed: {stderr_output.strip()}"
                
        except Exception as e:
            return False, str(e)
    
    @staticmethod
    def extract_ssl_file_paths(config):
        """
        Extract SSL certificate file paths from Nginx configuration
        
        Args:
            config: Nginx configuration string
            
        Returns:
            tuple: (ssl_certificate, ssl_certificate_key)
        """
        ssl_certificate = None
        ssl_certificate_key = None
        
        # Extract SSL certificate paths
        cert_match = re.search(r'ssl_certificate\s+([^;]+);', config)
        if cert_match:
            ssl_certificate = cert_match.group(1).strip()
        
        key_match = re.search(r'ssl_certificate_key\s+([^;]+);', config)
        if key_match:
            ssl_certificate_key = key_match.group(1).strip()
        
        return ssl_certificate, ssl_certificate_key
    
    @staticmethod
    def check_ssl_certificate_paths(node_id, config):
        """
        Check if SSL certificate files exist on the node
        
        Args:
            node_id: ID of the node
            config: Nginx configuration string
            
        Returns:
            tuple: (all_exist, missing_files, warnings)
        """
        node = Node.query.get(node_id)
        if not node:
            return False, ["Node not found"], []
        
        # Extract SSL certificate paths from config
        ssl_certificate, ssl_certificate_key = NginxValidationService.extract_ssl_file_paths(config)
        
        if not ssl_certificate and not ssl_certificate_key:
            # No SSL configuration found
            return True, [], []
        
        try:
            # Connect to the node
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            if node.ssh_key_path:
                ssh_client.connect(
                    hostname=node.ip_address,
                    port=node.ssh_port,
                    username=node.ssh_user,
                    key_filename=node.ssh_key_path
                )
            else:
                ssh_client.connect(
                    hostname=node.ip_address,
                    port=node.ssh_port,
                    username=node.ssh_user,
                    password=node.ssh_password
                )
            
            missing_files = []
            warnings = []
            
            # Check if certificate file exists
            if ssl_certificate:
                cmd = f"test -f {ssl_certificate} && echo 'exists' || echo 'not found'"
                stdin, stdout, stderr = ssh_client.exec_command(cmd)
                result = stdout.read().decode('utf-8').strip()
                
                if result == 'not found':
                    missing_files.append(ssl_certificate)
                    warnings.append(f"SSL certificate file not found: {ssl_certificate}")
            
            # Check if key file exists
            if ssl_certificate_key:
                cmd = f"test -f {ssl_certificate_key} && echo 'exists' || echo 'not found'"
                stdin, stdout, stderr = ssh_client.exec_command(cmd)
                result = stdout.read().decode('utf-8').strip()
                
                if result == 'not found':
                    missing_files.append(ssl_certificate_key)
                    warnings.append(f"SSL certificate key file not found: {ssl_certificate_key}")
            
            ssh_client.close()
            
            all_exist = len(missing_files) == 0
            return all_exist, missing_files, warnings
            
        except Exception as e:
            return False, [str(e)], []
    
    @staticmethod
    def analyze_validation_error(error_message):
        """
        Analyze nginx validation error message and provide helpful feedback
        
        Args:
            error_message: Error message from nginx -t
            
        Returns:
            dict: Analysis results
        """
        result = {
            "error_type": "unknown",
            "details": error_message,
            "suggestion": "Check the nginx configuration syntax."
        }
        
        # Check for SSL certificate errors
        if "SSL_CTX_use_certificate_file" in error_message or "cannot load certificate" in error_message:
            result["error_type"] = "ssl_certificate"
            result["suggestion"] = "SSL certificate files are missing or not accessible. Consider using the SSL certificate management tools to request a valid certificate."
            
            # Extract certificate path if available
            cert_match = re.search(r"cannot load certificate \"([^\"]+)\"", error_message)
            if cert_match:
                result["certificate_path"] = cert_match.group(1)
                
            # Suggest DNS-based issuance if HTTP validation won't work
            result["alternate_solution"] = "If the domain is not yet pointing to this server, consider using DNS validation method for obtaining SSL certificates."
            
        # Check for directive errors    
        elif "unknown directive" in error_message:
            result["error_type"] = "unknown_directive"
            directive_match = re.search(r"unknown directive \"([^\"]+)\"", error_message)
            if directive_match:
                result["directive"] = directive_match.group(1)
                result["suggestion"] = f"The directive '{directive_match.group(1)}' is not recognized. Check for typos or missing modules."
        
        # Check for host not found errors
        elif "host not found in upstream" in error_message:
            result["error_type"] = "upstream_host"
            host_match = re.search(r"host not found in upstream \"([^\"]+)\"", error_message)
            if host_match:
                result["upstream"] = host_match.group(1)
                result["suggestion"] = f"The upstream server '{host_match.group(1)}' cannot be resolved. Check the hostname or IP address."
        
        return result
    
    @staticmethod
    def test_config_on_node(node_id, config_content, domain, detect_ssl_requirements=True):
        """
        Test the configuration on a remote node using nginx -t
        
        Args:
            node_id: ID of the node to test on
            config_content: Nginx configuration content
            domain: Domain name for the configuration
            detect_ssl_requirements: Automatically detect and handle SSL config requirements
            
        Returns:
            tuple: (is_valid, error_message, ssl_details)
        """
        node = Node.query.get(node_id)
        if not node:
            return False, "Node not found", None
        
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
            
            # Detect if this is an HTTPS config
            is_https_config = "ssl_certificate" in config_content or "listen 443 ssl" in config_content
            ssl_details = None
            
            if is_https_config and detect_ssl_requirements:
                # Extract SSL certificate paths from config
                ssl_certificate, ssl_certificate_key = NginxValidationService.extract_ssl_file_paths(config_content)
                cert_domain = domain
                
                # Check if the domain is using a wildcard certificate
                # This could be a subdomain using a wildcard cert for its parent domain
                domain_parts = domain.split('.')
                if len(domain_parts) > 2:
                    parent_domain = '.'.join(domain_parts[1:])
                    wildcard_cert_path = f"/etc/letsencrypt/live/{parent_domain}/fullchain.pem"
                    
                    # Check if a wildcard certificate exists for the parent domain
                    stdin, stdout, stderr = ssh_client.exec_command(f"test -f {wildcard_cert_path} && echo 'exists' || echo 'not found'")
                    wildcard_exists = stdout.read().decode('utf-8').strip() == 'exists'
                    
                    if wildcard_exists:
                        # Use the wildcard certificate instead
                        ssl_certificate = wildcard_cert_path
                        ssl_certificate_key = f"/etc/letsencrypt/live/{parent_domain}/privkey.pem"
                        cert_domain = parent_domain
                
                # Create a modified version for testing by commenting out SSL certificate directives
                modified_content = re.sub(
                    r'(\s*)(ssl_certificate|ssl_certificate_key|ssl_trusted_certificate)(.+?);',
                    r'\1# \2\3; # Commented for testing',
                    config_content
                )
                
                # Add dummy SSL directives for testing
                dummy_ssl_config = """
    # Dummy SSL certificates for testing only
    ssl_certificate /etc/nginx/ssl/dummy.crt;
    ssl_certificate_key /etc/nginx/ssl/dummy.key;
"""
                # Insert dummy SSL config
                if "# Custom configuration" in modified_content:
                    modified_content = modified_content.replace(
                        "# Custom configuration", 
                        "# Custom configuration\n" + dummy_ssl_config
                    )
                else:
                    # Otherwise add before the closing bracket of the server block
                    modified_content = modified_content.replace(
                        "}", 
                        dummy_ssl_config + "}", 
                        1  # Replace only first occurrence
                    )
                
                # Create the dummy SSL cert directory if needed
                ssh_client.exec_command("sudo mkdir -p /etc/nginx/ssl")
                
                # Create dummy SSL certificate if it doesn't exist
                ssh_client.exec_command("""
                if [ ! -f /etc/nginx/ssl/dummy.crt ]; then
                    # Create a root CA key and certificate
                    sudo openssl genrsa -out /etc/nginx/ssl/dummy-ca.key 2048 2>/dev/null
                    sudo openssl req -x509 -new -nodes -key /etc/nginx/ssl/dummy-ca.key -sha256 -days 365 \
                        -out /etc/nginx/ssl/dummy-ca.crt -subj "/CN=Dummy CA" 2>/dev/null
                    
                    # Create server key
                    sudo openssl genrsa -out /etc/nginx/ssl/dummy.key 2048 2>/dev/null
                    
                    # Create CSR
                    sudo openssl req -new -key /etc/nginx/ssl/dummy.key -out /etc/nginx/ssl/dummy.csr \
                        -subj "/CN=localhost" 2>/dev/null
                    
                    # Sign the certificate with our CA
                    sudo openssl x509 -req -in /etc/nginx/ssl/dummy.csr -CA /etc/nginx/ssl/dummy-ca.crt \
                        -CAkey /etc/nginx/ssl/dummy-ca.key -CAcreateserial -out /etc/nginx/ssl/dummy.crt \
                        -days 365 -sha256 2>/dev/null
                    
                    # Create chain file for SSL stapling
                    sudo cp /etc/nginx/ssl/dummy-ca.crt /etc/nginx/ssl/dummy-chain.pem
                    sudo cat /etc/nginx/ssl/dummy.crt /etc/nginx/ssl/dummy-ca.crt > /etc/nginx/ssl/dummy-fullchain.pem
                    sudo chmod 644 /etc/nginx/ssl/*.pem /etc/nginx/ssl/*.crt /etc/nginx/ssl/*.key
                fi
                """)
                
                # Check if real certificates exist
                if ssl_certificate:
                    stdin, stdout, stderr = ssh_client.exec_command(f"test -f {ssl_certificate} && echo 'exists' || echo 'not found'")
                    cert_exists = stdout.read().decode('utf-8').strip() == 'exists'
                    
                    if ssl_certificate_key:
                        stdin, stdout, stderr = ssh_client.exec_command(f"test -f {ssl_certificate_key} && echo 'exists' || echo 'not found'")
                        key_exists = stdout.read().decode('utf-8').strip() == 'exists'
                    else:
                        key_exists = False
                else:
                    cert_exists = False
                    key_exists = False
                
                # Gather SSL details for the caller
                ssl_details = {
                    "is_https": True,
                    "ssl_certificate": ssl_certificate,
                    "ssl_certificate_key": ssl_certificate_key,
                    "certificate_exists": cert_exists,
                    "key_exists": key_exists,
                    "certificate_domain": cert_domain
                }
                
                # Use modified content for testing
                test_content = modified_content
                log_activity('info', f"Testing HTTPS config for {domain} with dummy certificates")
            else:
                # For HTTP configs or when not detecting SSL, use the original content
                test_content = config_content
                
                if is_https_config and not detect_ssl_requirements:
                    ssl_details = {
                        "is_https": True,
                        "detection_skipped": True
                    }
            
            # Create a temporary file for testing
            with tempfile.NamedTemporaryFile(mode='w+', delete=False) as temp:
                # Wrap the server block in a complete Nginx config with events and http sections
                wrapped_content = """
events {
    worker_connections 1024;
}

http {
    # Basic mime types
    include /etc/nginx/mime.types;
    default_type application/octet-stream;
    
    # Add server configuration
%s
}
""" % test_content
                temp.write(wrapped_content)
                temp_path = temp.name
            
            # Upload the config to a temporary location on the remote server
            sftp = ssh_client.open_sftp()
            remote_temp_path = f"/tmp/{domain}_nginx_test.conf"
            sftp.put(temp_path, remote_temp_path)
            sftp.close()
            
            # Get the nginx path (using the existing detection code)
            # ...existing code to detect nginx path...
            
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
                    return False, f"Could not find nginx executable on the server ({os_info}). Please install nginx using: sudo apt update && sudo apt install -y nginx", ssl_details
                else:
                    return False, f"Could not find nginx executable on the server ({os_info}). Please check nginx installation.", ssl_details
            
            # Test the configuration
            test_command = f"{nginx_path} -t -c {remote_temp_path} 2>&1 || echo 'Test failed'"
            stdin, stdout, stderr = ssh_client.exec_command(test_command)
            test_output = stdout.read().decode('utf-8')
            
            # Remove temporary files
            ssh_client.exec_command(f"rm -f {remote_temp_path}")
            os.unlink(temp_path)
            
            # Special handling for SSL certificate errors in the test output
            if is_https_config and "SSL:" in test_output and "No such file or directory" in test_output:
                # This is expected for HTTPS sites without certificates yet
                if detect_ssl_requirements:
                    is_valid = True
                    test_output = "Configuration valid (SSL certificate paths ignored for testing)"
                    log_activity('info', f"HTTPS config test for {domain} passed with SSL certificate warnings ignored")
                    
                    # Add more details to SSL info
                    if ssl_details:
                        ssl_details["certificates_needed"] = True
                        ssl_details["test_note"] = "Configuration is valid, but certificates need to be provisioned"
                else:
                    is_valid = "test is successful" in test_output.lower() or "test failed" not in test_output.lower()
            else:
                # Regular test result check
                is_valid = "test is successful" in test_output.lower() or "test failed" not in test_output.lower()
            
            # Log the test
            if not is_valid:
                log_activity('warning', f"Nginx config test failed for {domain} on node {node.name}: {test_output}")
                
                # Analyze the error for better feedback
                error_analysis = NginxValidationService.analyze_validation_error(test_output)
                if is_https_config and error_analysis["error_type"] == "ssl_certificate":
                    # Add SSL error details to the response
                    if ssl_details:
                        ssl_details["validation_error"] = error_analysis
                        ssl_details["certificates_needed"] = True
            else:
                # If test succeeded, log the nginx path we found for future reference
                log_activity('info', f"Nginx config test successful using binary at {nginx_path}")
                
                # Store the detected nginx path in node properties for future use if it's different
                if hasattr(node, 'detected_nginx_path') and node.detected_nginx_path != nginx_path:
                    node.detected_nginx_path = nginx_path
                    db.session.commit()
            
            ssh_client.close()
            return is_valid, test_output.strip(), ssl_details
            
        except Exception as e:
            return False, f"Error testing config: {str(e)}", None
    
    @staticmethod
    def analyze_validation_error(error_message):
        """
        Analyze nginx validation error message and provide helpful feedback
        
        Args:
            error_message: Error message from nginx -t
            
        Returns:
            dict: Analysis results with error details and suggestions
        """
        result = {
            "error_type": "unknown",
            "details": error_message,
            "suggestion": "Check the nginx configuration syntax."
        }
        
        # Check for SSL certificate errors
        if "SSL_CTX_use_certificate_file" in error_message or "cannot load certificate" in error_message or "BIO_new_file() failed" in error_message:
            result["error_type"] = "ssl_certificate"
            result["suggestion"] = "SSL certificate files are missing or not accessible. Consider using the SSL certificate management tools to request a valid certificate."
            
            # Extract certificate path if available
            cert_match = re.search(r"cannot load certificate \"([^\"]+)\"", error_message)
            if cert_match:
                result["certificate_path"] = cert_match.group(1)
                
            # Check for specific error about non-existent file
            if "No such file or directory" in error_message:
                result["specific_issue"] = "certificate_missing"
                result["suggestion"] += " The certificate files do not exist on the server."
            
            # Look for specific Let's Encrypt path
            letsencrypt_match = re.search(r"/etc/letsencrypt/live/([^/]+)/", error_message)
            if letsencrypt_match:
                result["domain"] = letsencrypt_match.group(1)
                result["certificate_type"] = "letsencrypt"
                result["suggestion"] += f" Consider running certbot to obtain a certificate for {letsencrypt_match.group(1)}."
                
            # Suggest DNS-based issuance if HTTP validation won't work
            result["alternate_solution"] = "If the domain is not yet pointing to this server, consider using DNS validation method for obtaining SSL certificates."
            
        # Check for directive errors    
        elif "unknown directive" in error_message:
            result["error_type"] = "unknown_directive"
            directive_match = re.search(r"unknown directive \"([^\"]+)\"", error_message)
            if directive_match:
                result["directive"] = directive_match.group(1)
                result["suggestion"] = f"The directive '{directive_match.group(1)}' is not recognized. Check for typos or missing modules."
        
        # Check for host not found errors
        elif "host not found in upstream" in error_message:
            result["error_type"] = "upstream_host"
            host_match = re.search(r"host not found in upstream \"([^\"]+)\"", error_message)
            if host_match:
                result["upstream"] = host_match.group(1)
                result["suggestion"] = f"The upstream server '{host_match.group(1)}' cannot be resolved. Check the hostname or IP address."
        
        # Check for permission errors
        elif "permission denied" in error_message.lower():
            result["error_type"] = "permission"
            result["suggestion"] = "Nginx does not have permission to access a required file or directory. Check file permissions."
            
            # Try to extract the path with permission issues
            path_match = re.search(r"open\(\) \"([^\"]+)\"", error_message)
            if path_match:
                result["path"] = path_match.group(1)
                result["suggestion"] += f" Check permissions for: {path_match.group(1)}"
        
        # Check for duplicate listen errors
        elif "duplicate listen" in error_message:
            result["error_type"] = "duplicate_listen"
            listen_match = re.search(r"duplicate listen options for ([^\s]+)", error_message)
            if listen_match:
                result["address"] = listen_match.group(1)
                result["suggestion"] = f"There are duplicate listen directives for {listen_match.group(1)}. Check for conflicts with other server blocks."
        
        return result
    
    @staticmethod
    def test_config_on_node(node_id, nginx_config, domain):
        """
        Test a Nginx configuration on a node without applying it
        
        Args:
            node_id: ID of the node to test on
            nginx_config: Nginx configuration content to test
            domain: Domain name for the site
            
        Returns:
            tuple: (is_valid, error_message, ssl_details)
        """
        node = Node.query.get(node_id)
        
        if not node:
            return False, "Node not found", None
        
        try:
            # Connect to the node
            ssh_client = paramiko.SSHClient()
            ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
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
            
            # Detect the Nginx path if not already known
            nginx_path = node.detected_nginx_path if hasattr(node, 'detected_nginx_path') and node.detected_nginx_path else "nginx"
            
            if not node.detected_nginx_path:
                # Try to detect the Nginx path
                stdin, stdout, stderr = ssh_client.exec_command("which nginx")
                detected_path = stdout.read().decode('utf-8').strip()
                
                if detected_path:
                    # Store the detected path
                    node.detected_nginx_path = detected_path
                    db.session.commit()
                    nginx_path = detected_path
            
            # Create a temporary file for testing
            temp_file = f"/tmp/{domain}_nginx_test.conf"
            sftp = ssh_client.open_sftp()
            
            # Write to a temporary file
            with sftp.file(temp_file, 'w') as f:
                f.write(nginx_config)
            
            # Run a configuration test
            stdin, stdout, stderr = ssh_client.exec_command(f"sudo {nginx_path} -t -c {temp_file} 2>&1 || echo 'TEST_FAILED'")
            test_output = stdout.read().decode('utf-8')
            
            # Check if the test passed
            test_passed = "TEST_FAILED" not in test_output
            
            # Cleanup temporary file
            ssh_client.exec_command(f"rm -f {temp_file}")
            
            # Check for SSL certificate paths in the configuration
            ssl_certificate = None
            ssl_certificate_key = None
            
            if "ssl_certificate " in nginx_config:
                ssl_certificate_match = re.search(r'ssl_certificate\s+([^;]+);', nginx_config)
                if ssl_certificate_match:
                    ssl_certificate = ssl_certificate_match.group(1).strip()
            
            if "ssl_certificate_key " in nginx_config:
                ssl_key_match = re.search(r'ssl_certificate_key\s+([^;]+);', nginx_config)
                if ssl_key_match:
                    ssl_certificate_key = ssl_key_match.group(1).strip()
            
            # Check if certificate exists
            certificates_needed = False
            is_https = "listen 443 ssl" in nginx_config

            # For HTTPS sites, verify if certificate files exist and create placeholders if needed
            if is_https and (ssl_certificate or ssl_certificate_key):
                certificates_exist = True
                
                if ssl_certificate:
                    # Try to access the certificate file
                    stdin, stdout, stderr = ssh_client.exec_command(f"test -f {ssl_certificate} && echo 'exists' || echo 'missing'")
                    cert_exists = stdout.read().decode('utf-8').strip() == 'exists'
                    
                    if not cert_exists:
                        certificates_exist = False
                        certificates_needed = True
                        
                        # Create parent directory for certificate if it doesn't exist
                        cert_dir = os.path.dirname(ssl_certificate)
                        ssh_client.exec_command(f"mkdir -p {cert_dir}")
                
                if ssl_certificate_key:
                    # Try to access the key file
                    stdin, stdout, stderr = ssh_client.exec_command(f"test -f {ssl_certificate_key} && echo 'exists' || echo 'missing'")
                    key_exists = stdout.read().decode('utf-8').strip() == 'exists'
                    
                    if not key_exists:
                        certificates_exist = False
                        certificates_needed = True
                        
                        # Create parent directory for key if it doesn't exist
                        key_dir = os.path.dirname(ssl_certificate_key)
                        ssh_client.exec_command(f"mkdir -p {key_dir}")
                
                # Prepare dummy certificates for testing if they don't exist
                if not certificates_exist and test_passed:
                    # If the test passed but certificates don't exist, create dummy placeholder files
                    # This will help catch other configuration issues without being blocked by missing certificates
                    if ssl_certificate:
                        cert_dir = os.path.dirname(ssl_certificate)
                        ssh_client.exec_command(f"mkdir -p {cert_dir}")
                        
                        # Create a minimal dummy certificate file for testing only
                        ssh_client.exec_command(f"sudo touch {ssl_certificate}")
                        
                    if ssl_certificate_key:
                        key_dir = os.path.dirname(ssl_certificate_key)
                        ssh_client.exec_command(f"mkdir -p {key_dir}")
                        
                        # Create a minimal dummy key file for testing only
                        ssh_client.exec_command(f"sudo touch {ssl_certificate_key}")
                    
                    # Try the test again with the dummy files
                    stdin, stdout, stderr = ssh_client.exec_command(f"sudo {nginx_path} -t -c {temp_file} 2>&1 || echo 'TEST_FAILED'")
                    retest_output = stdout.read().decode('utf-8')
                    
                    # Update test result based on retest
                    if "TEST_FAILED" not in retest_output:
                        test_passed = True
                        test_output = retest_output
                    
                    # Clean up temporary dummy files
                    if ssl_certificate and not cert_exists:
                        ssh_client.exec_command(f"sudo rm -f {ssl_certificate}")
                    if ssl_certificate_key and not key_exists:
                        ssh_client.exec_command(f"sudo rm -f {ssl_certificate_key}")
            
            # Extract detailed error information if test failed
            error_message = test_output
            
            # Find specific error types
            syntax_error = False
            unknown_directive = False
            ssl_error = False
            
            if "syntax is ok" in test_output.lower():
                error_message = ""
            elif "syntax error" in test_output.lower():
                syntax_error = True
                error_message = "Syntax error in Nginx configuration"
                for line in test_output.split('\n'):
                    if "syntax error" in line.lower() or "unknown directive" in line.lower():
                        error_message = line.strip()
                        break
            elif "ssl_certificate" in test_output.lower() and ("failed" in test_output.lower() or "error" in test_output.lower()):
                ssl_error = True
                error_message = "SSL certificate error in Nginx configuration"
                for line in test_output.split('\n'):
                    if "ssl_certificate" in line.lower() and ("failed" in line.lower() or "error" in line.lower() or "no such file" in line.lower()):
                        error_message = line.strip()
                        break
            
            ssh_client.close()
            
            # Prepare SSL details for return
            ssl_details = {
                "is_https": is_https,
                "certificates_needed": certificates_needed,
                "ssl_certificate": ssl_certificate,
                "ssl_certificate_key": ssl_certificate_key
            }
            
            return test_passed, error_message, ssl_details
            
        except Exception as e:
            return False, f"Error testing configuration: {str(e)}", None