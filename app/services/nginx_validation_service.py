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
    def test_config_on_node(node_id, config_content, domain, detect_ssl_requirements=True, skip_ssl_check=False, site_name=None):
        """
        Test the configuration on a remote node using nginx -t
        
        Args:
            node_id: ID of the node to test on
            config_content: Nginx configuration content
            domain: Domain name for the configuration
            detect_ssl_requirements: Automatically detect and handle SSL config requirements
            skip_ssl_check: Whether to ignore SSL certificate errors
            site_name: Alternative name for the site (falls back to domain if not provided)
            
        Returns:
            tuple: (is_valid, error_message, ssl_details)
        """
        node = Node.query.get(node_id)
        if not node:
            return False, "Node not found", None
        
        # Use domain as site_name if not provided
        if site_name is None:
            site_name = domain
            
        # Initialize SSH client with proper cleanup
        ssh_client = None
        sftp = None
        temp_file_path = None
        remote_temp_path = None
        
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
            test_content = config_content
            
            # Extract SSL certificate paths and create details if needed
            if is_https_config:
                ssl_certificate, ssl_certificate_key = NginxValidationService.extract_ssl_file_paths(config_content)
                cert_domain = domain
                
                # Basic SSL details structure
                ssl_details = {
                    "is_https": True,
                    "ssl_certificate": ssl_certificate,
                    "ssl_certificate_key": ssl_certificate_key,
                    "certificate_exists": False,
                    "key_exists": False
                }
                
                # Check if the domain is using a wildcard certificate
                # This could be a subdomain using a wildcard cert for its parent domain
                if detect_ssl_requirements:
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
                            ssl_details["ssl_certificate"] = ssl_certificate
                            ssl_details["ssl_certificate_key"] = ssl_certificate_key
                            ssl_details["certificate_domain"] = cert_domain
                
                # Handle SSL for testing appropriately based on flags
                if skip_ssl_check or detect_ssl_requirements:
                    # Create a modified version by commenting out SSL certificate directives
                    modified_content = re.sub(
                        r'(\s*)(ssl_certificate|ssl_certificate_key|ssl_trusted_certificate)(.+?);',
                        r'\1# \2\3; # Commented for testing',
                        config_content
                    )
                    
                    # Add dummy SSL directives for test to pass
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
                    
                    test_content = modified_content
                    log_activity('info', f"Testing HTTPS config for {domain} with dummy certificates")
                
                # Check if real certificates exist (if we have a certificate path)
                if ssl_certificate:
                    stdin, stdout, stderr = ssh_client.exec_command(f"test -f {ssl_certificate} && echo 'exists' || echo 'not found'")
                    cert_exists = stdout.read().decode('utf-8').strip() == 'exists'
                    ssl_details["certificate_exists"] = cert_exists
                    
                    if ssl_certificate_key:
                        stdin, stdout, stderr = ssh_client.exec_command(f"test -f {ssl_certificate_key} && echo 'exists' || echo 'not found'")
                        key_exists = stdout.read().decode('utf-8').strip() == 'exists'
                        ssl_details["key_exists"] = key_exists
                    
                    # If certificates don't exist, they'll need to be provisioned
                    if not cert_exists or (ssl_certificate_key and not key_exists):
                        ssl_details["certificates_needed"] = True
            
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
                temp_file_path = temp.name
            
            # Upload the config to a temporary location on the remote server
            sftp = ssh_client.open_sftp()
            remote_temp_path = f"/tmp/{site_name}_nginx_test.conf"
            sftp.put(temp_file_path, remote_temp_path)
            sftp.close()
            sftp = None  # Reset for proper cleanup
            
            # Find the nginx executable path
            nginx_path = NginxValidationService._find_nginx_path(ssh_client, node)
            
            # If nginx binary not found, provide installation instructions
            if not nginx_path:
                # Try to determine the OS for better help message
                stdin, stdout, stderr = ssh_client.exec_command("lsb_release -ds 2>/dev/null || cat /etc/os-release 2>/dev/null | grep PRETTY_NAME | cut -d '\"' -f 2 || echo 'Unknown'")
                os_info = stdout.read().decode('utf-8').strip()
                
                error_msg = ""
                if "Ubuntu" in os_info or "Debian" in os_info:
                    error_msg = f"Could not find nginx executable on the server ({os_info}). Please install nginx using: sudo apt update && sudo apt install -y nginx"
                else:
                    error_msg = f"Could not find nginx executable on the server ({os_info}). Please check nginx installation."
                
                return False, error_msg, ssl_details
            
            # Test the configuration
            test_command = f"{nginx_path} -t -c {remote_temp_path} 2>&1 || echo 'TEST_FAILED'"
            stdin, stdout, stderr = ssh_client.exec_command(test_command)
            test_output = stdout.read().decode('utf-8')
            
            # Special handling for SSL certificate errors in the test output
            is_valid = False
            if is_https_config and ("SSL:" in test_output and "No such file or directory" in test_output):
                # This is expected for HTTPS sites without certificates yet
                if detect_ssl_requirements or skip_ssl_check:
                    is_valid = True
                    test_output = "Configuration valid (SSL certificate paths ignored for testing)"
                    log_activity('info', f"HTTPS config test for {domain} passed with SSL certificate warnings ignored")
                    
                    # Add more details to SSL info
                    if ssl_details:
                        ssl_details["certificates_needed"] = True
                        ssl_details["test_note"] = "Configuration is valid, but certificates need to be provisioned"
                else:
                    is_valid = "test is successful" in test_output.lower() or "TEST_FAILED" not in test_output
            else:
                # Regular test result check
                is_valid = "test is successful" in test_output.lower() or "TEST_FAILED" not in test_output
            
            # Log the test results
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
                # If test succeeded, log and store the nginx path for future use
                log_activity('info', f"Nginx config test successful using binary at {nginx_path}")
                
                # Store the detected nginx path if different
                if node.detected_nginx_path != nginx_path:
                    node.detected_nginx_path = nginx_path
                    db.session.commit()
            
            # Extract more specific error information if test failed
            error_message = test_output
            
            # Find specific error types for better reporting
            if "syntax is ok" in test_output.lower():
                error_message = ""
            elif "syntax error" in test_output.lower():
                error_message = "Syntax error in Nginx configuration"
                for line in test_output.split('\n'):
                    if "syntax error" in line.lower() or "unknown directive" in line.lower():
                        error_message = line.strip()
                        break
            elif "ssl_certificate" in test_output.lower() and ("failed" in test_output.lower() or "error" in test_output.lower()):
                error_message = "SSL certificate error in Nginx configuration"
                for line in test_output.split('\n'):
                    if "ssl_certificate" in line.lower() and ("failed" in line.lower() or "error" in line.lower() or "no such file" in line.lower()):
                        error_message = line.strip()
                        break
            
            return is_valid, error_message, ssl_details
            
        except Exception as e:
            # Log the exception
            log_activity('error', f"Error testing Nginx config for {domain}: {str(e)}")
            return False, f"Error testing config: {str(e)}", None
        
        finally:
            # Clean up resources to prevent leaks
            try:
                if remote_temp_path and ssh_client:
                    ssh_client.exec_command(f"rm -f {remote_temp_path}")
                
                if temp_file_path:
                    os.unlink(temp_file_path)
                
                if sftp:
                    sftp.close()
                
                if ssh_client:
                    ssh_client.close()
            except Exception as cleanup_error:
                log_activity('warning', f"Error during cleanup after Nginx config test: {str(cleanup_error)}")
    
    @staticmethod
    def _find_nginx_path(ssh_client, node):
        """
        Helper method to find the nginx executable path on a remote server
        
        Args:
            ssh_client: Connected SSH client
            node: Node object with server details
            
        Returns:
            str: Path to nginx executable or None if not found
        """
        # First check if we already know the path
        if hasattr(node, 'detected_nginx_path') and node.detected_nginx_path:
            # Verify the path still exists
            stdin, stdout, stderr = ssh_client.exec_command(f"test -x {node.detected_nginx_path} && echo 'exists' || echo 'not found'")
            result = stdout.read().decode('utf-8').strip()
            if result == 'exists':
                return node.detected_nginx_path
        
        # Try standard environment PATH with a full env sourcing
        stdin, stdout, stderr = ssh_client.exec_command("bash -l -c 'which nginx' 2>/dev/null || echo 'not found'")
        result = stdout.read().decode('utf-8').strip()
        if result != 'not found' and 'nginx' in result:
            return result
        
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
        for path in nginx_paths:
            stdin, stdout, stderr = ssh_client.exec_command(f"test -x {path} && echo {path} || echo 'not found'")
            result = stdout.read().decode('utf-8').strip()
            if result != 'not found':
                return result
        
        # If nginx binary still not found, try active service detection
        stdin, stdout, stderr = ssh_client.exec_command("systemctl status nginx 2>/dev/null | grep 'Main PID' | awk '{print $3}' || echo 'not found'")
        result = stdout.read().decode('utf-8').strip()
        if result != 'not found' and result.isdigit():
            # Get the executable path from the process
            pid = result
            stdin, stdout, stderr = ssh_client.exec_command(f"readlink -f /proc/{pid}/exe 2>/dev/null || echo 'not found'")
            result = stdout.read().decode('utf-8').strip()
            if result != 'not found' and 'nginx' in result:
                return result
        
        # If still not found, try a comprehensive file search
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
                return result.split('\n')[0]
        
        # Last resort: deep file search
        stdin, stdout, stderr = ssh_client.exec_command("find /usr /etc /opt /snap -name nginx -type f -executable 2>/dev/null | head -1 || echo 'not found'")
        result = stdout.read().decode('utf-8').strip()
        if result != 'not found':
            return result
        
        # Nginx not found
        return None
    
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