import paramiko
import tempfile
import os
from contextlib import contextmanager
from app.services.logger_service import log_activity

class SSHConnectionService:
    """
    Utility service for handling SSH connections to remote nodes.
    Reduces code duplication across proxy services.
    """
    
    @staticmethod
    def connect(node):
        """
        Create an SSH connection to a node
        
        Args:
            node: Node object with connection details
            
        Returns:
            paramiko.SSHClient: Connected SSH client
            
        Raises:
            Exception: If connection fails
        """
        ssh_client = paramiko.SSHClient()
        ssh_client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        try:
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
            
            return ssh_client
        except Exception as e:
            ssh_client.close()
            raise Exception(f"Failed to connect to {node.name} ({node.ip_address}): {str(e)}")
    
    @staticmethod
    @contextmanager
    def get_connection(node):
        """
        Context manager for SSH connections that ensures proper cleanup
        
        Args:
            node: Node object with connection details
            
        Yields:
            paramiko.SSHClient: Connected SSH client
        """
        ssh_client = None
        try:
            ssh_client = SSHConnectionService.connect(node)
            yield ssh_client
        finally:
            if ssh_client:
                ssh_client.close()
    
    @staticmethod
    @contextmanager
    def get_sftp_connection(node):
        """
        Context manager for SFTP connections
        
        Args:
            node: Node object with connection details
            
        Yields:
            tuple: (ssh_client, sftp_client)
        """
        ssh_client = None
        sftp = None
        try:
            ssh_client = SSHConnectionService.connect(node)
            sftp = ssh_client.open_sftp()
            yield (ssh_client, sftp)
        finally:
            if sftp:
                sftp.close()
            if ssh_client:
                ssh_client.close()
    
    @staticmethod
    def execute_command(ssh_client, command, log_errors=True):
        """
        Execute a command on the remote server
        
        Args:
            ssh_client: Connected SSH client
            command: Command to execute
            log_errors: Whether to log command errors
            
        Returns:
            tuple: (exit_code, stdout_str, stderr_str)
        """
        stdin, stdout, stderr = ssh_client.exec_command(command)
        exit_code = stdout.channel.recv_exit_status()
        stdout_str = stdout.read().decode('utf-8')
        stderr_str = stderr.read().decode('utf-8')
        
        return (exit_code, stdout_str, stderr_str)
    
    @staticmethod
    def execute_commands(ssh_client, commands, stop_on_error=True):
        """
        Execute multiple commands on the remote server
        
        Args:
            ssh_client: Connected SSH client
            commands: List of commands to execute
            stop_on_error: Whether to stop executing commands after an error
            
        Returns:
            tuple: (success, results) where results is a list of (command, exit_code, stdout, stderr)
        """
        results = []
        
        for cmd in commands:
            exit_code, stdout_str, stderr_str = SSHConnectionService.execute_command(ssh_client, cmd)
            results.append((cmd, exit_code, stdout_str, stderr_str))
            
            if exit_code != 0 and stop_on_error:
                return (False, results)
        
        return (True, results)
    
    @staticmethod
    def upload_file(node, local_path, remote_path):
        """
        Upload a file to the remote server
        
        Args:
            node: Node object with connection details
            local_path: Path to the local file
            remote_path: Path on the remote server
            
        Returns:
            bool: True if successful, False otherwise
        """
        with SSHConnectionService.get_sftp_connection(node) as (ssh_client, sftp):
            try:
                sftp.put(local_path, remote_path)
                return True
            except Exception as e:
                log_activity('error', f"Failed to upload file to {node.name}: {str(e)}", 'node', node.id)
                return False
    
    @staticmethod
    def download_file(node, remote_path, local_path):
        """
        Download a file from the remote server
        
        Args:
            node: Node object with connection details
            remote_path: Path on the remote server
            local_path: Path to save the local file
            
        Returns:
            bool: True if successful, False otherwise
        """
        with SSHConnectionService.get_sftp_connection(node) as (ssh_client, sftp):
            try:
                sftp.get(remote_path, local_path)
                return True
            except Exception as e:
                log_activity('error', f"Failed to download file from {node.name}: {str(e)}", 'node', node.id)
                return False
    
    @staticmethod
    def create_temp_file_with_content(content):
        """
        Create a temporary file with the given content
        
        Args:
            content: Content to write to the file
            
        Returns:
            str: Path to the temporary file
        """
        with tempfile.NamedTemporaryFile(delete=False) as tmp:
            tmp_path = tmp.name
            if isinstance(content, str):
                tmp.write(content.encode('utf-8'))
            else:
                tmp.write(content)
        
        return tmp_path
    
    @staticmethod
    def upload_string_to_remote_file(node, content, remote_path):
        """
        Upload a string to a file on the remote server
        
        Args:
            node: Node object with connection details
            content: String content to upload
            remote_path: Path on the remote server
            
        Returns:
            bool: True if successful, False otherwise
        """
        try:
            tmp_path = SSHConnectionService.create_temp_file_with_content(content)
            result = SSHConnectionService.upload_file(node, tmp_path, remote_path)
            os.unlink(tmp_path)  # Clean up local temp file
            return result
        except Exception as e:
            log_activity('error', f"Failed to upload string to {node.name}: {str(e)}", 'node', node.id)
            return False