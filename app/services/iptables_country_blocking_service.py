import os
import subprocess
import logging
from app.services.logger_service import LoggerService

logger = LoggerService.get_logger(__name__)

class IptablesCountryBlockingService:
    """Service for managing iptables-based country blocking at the node level.
    This is an admin-only feature that blocks traffic at the firewall level."""
    
    @staticmethod
    def check_geoip_module(node):
        """Check if the GeoIP module is installed and available on the node"""
        try:
            # Check if iptables-extensions package is installed
            cmd_ext = f"ssh root@{node.ip_address} 'dpkg -l | grep iptables-extensions'"
            ext_result = subprocess.run(cmd_ext, shell=True, capture_output=True, text=True)
            
            # Check if xt_geoip module is available
            cmd_module = f"ssh root@{node.ip_address} 'lsmod | grep xt_geoip'"
            module_result = subprocess.run(cmd_module, shell=True, capture_output=True, text=True)
            
            # Check if GeoIP database is installed
            cmd_db = f"ssh root@{node.ip_address} 'ls -la /usr/share/xt_geoip'"
            db_result = subprocess.run(cmd_db, shell=True, capture_output=True, text=True)
            
            # Check for overall functionality
            cmd_test = f"ssh root@{node.ip_address} 'iptables -m geoip -h'"
            test_result = subprocess.run(cmd_test, shell=True, capture_output=True, text=True)
            
            # Prepare the status result
            module_available = ext_result.returncode == 0
            module_loaded = module_result.returncode == 0
            geoip_db_installed = db_result.returncode == 0
            fully_functional = test_result.returncode == 0
            
            status = {
                'module_available': module_available,
                'module_loaded': module_loaded,
                'geoip_db_installed': geoip_db_installed,
                'fully_functional': fully_functional,
                'error': None
            }
            
            # If there are issues, log them
            if not fully_functional:
                error_details = []
                if not module_available:
                    error_details.append("GeoIP module package not installed")
                if not module_loaded:
                    error_details.append("GeoIP module not loaded")
                if not geoip_db_installed:
                    error_details.append("GeoIP database not installed")
                
                status['error'] = ", ".join(error_details) or "Unknown error with GeoIP functionality"
            
            return status
            
        except Exception as e:
            logger.error(f"Error checking GeoIP module: {e}")
            return {
                'module_available': False,
                'module_loaded': False,
                'geoip_db_installed': False,
                'fully_functional': False,
                'error': str(e)
            }
    
    @staticmethod
    def install_geoip_module(node, user_id):
        """Install the GeoIP module on the node"""
        try:
            # Install the required packages
            install_cmd = f"ssh root@{node.ip_address} 'apt-get update && apt-get install -y xtables-addons-common iptables-extensions libtext-csv-xs-perl && mkdir -p /usr/share/xt_geoip'"
            subprocess.run(install_cmd, shell=True, check=True)
            
            # Download the latest GeoIP database
            download_cmd = f"ssh root@{node.ip_address} 'cd /tmp && wget -O GeoIPCountryCSV.zip https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country-CSV&license_key=YOUR_LICENSE_KEY&suffix=zip || wget -O GeoIPCountryCSV.zip https://mailfud.org/geoip-legacy/GeoIPCountryCSV.zip && unzip -o GeoIPCountryCSV.zip'"
            subprocess.run(download_cmd, shell=True, check=True)
            
            # Convert the GeoIP database to xt_geoip format
            convert_cmd = f"ssh root@{node.ip_address} '/usr/lib/xtables-addons/xt_geoip_build -D /tmp/GeoIPCountryWhois.csv /usr/share/xt_geoip'"
            subprocess.run(convert_cmd, shell=True, check=True)
            
            # Load the GeoIP module
            load_cmd = f"ssh root@{node.ip_address} 'modprobe xt_geoip'"
            subprocess.run(load_cmd, shell=True, check=True)
            
            # Ensure the GeoIP module is loaded at boot
            boot_cmd = f"ssh root@{node.ip_address} 'echo \"xt_geoip\" >> /etc/modules'"
            subprocess.run(boot_cmd, shell=True, check=True)
            
            # Log the installation
            logger.info(f"GeoIP module installed on node {node.id} by user {user_id}")
            
            return True, "GeoIP module installed successfully."
            
        except Exception as e:
            logger.error(f"Error installing GeoIP module: {e}")
            return False, f"Error installing GeoIP module: {e}"
    
    @staticmethod
    def get_blocked_countries(node):
        """Get the list of countries currently blocked by iptables"""
        try:
            cmd = f"ssh root@{node.ip_address} 'iptables -L INPUT -v | grep geoip'"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            
            blocked_countries = []
            if result.returncode == 0:
                # Parse the output to extract country codes
                output_lines = result.stdout.strip().split('\n')
                for line in output_lines:
                    if 'geoip' in line and '--source-country' in line:
                        # Extract country code from the line
                        parts = line.split('--source-country')
                        if len(parts) > 1:
                            country_code = parts[1].strip().split()[0]
                            blocked_countries.append(country_code)
            
            return blocked_countries
            
        except Exception as e:
            logger.error(f"Error getting blocked countries: {e}")
            return []
    
    @staticmethod
    def block_countries(node, countries, user_id):
        """Block traffic from specified countries using iptables"""
        try:
            # Validate country codes (should be 2-letter ISO codes)
            valid_countries = [country.upper() for country in countries if len(country) == 2]
            
            if not valid_countries:
                return False, "No valid country codes provided. Country codes should be 2-letter ISO codes."
            
            # Create an iptables rule for each country
            for country in valid_countries:
                cmd = f"ssh root@{node.ip_address} 'iptables -A INPUT -m geoip --source-country {country} -j DROP'"
                subprocess.run(cmd, shell=True, check=True)
            
            # Log the action
            logger.info(f"Countries {', '.join(valid_countries)} blocked on node {node.id} by user {user_id}")
            
            return True, f"Successfully blocked traffic from {len(valid_countries)} countries."
            
        except Exception as e:
            logger.error(f"Error blocking countries: {e}")
            return False, f"Error blocking countries: {e}"
    
    @staticmethod
    def unblock_countries(node, countries, user_id):
        """Unblock traffic from specified countries by removing iptables rules"""
        try:
            # Validate country codes (should be 2-letter ISO codes)
            valid_countries = [country.upper() for country in countries if len(country) == 2]
            
            if not valid_countries:
                return False, "No valid country codes provided. Country codes should be 2-letter ISO codes."
            
            # Remove iptables rules for each country
            for country in valid_countries:
                # Find and delete all matching rules
                cmd = f"ssh root@{node.ip_address} 'iptables -D INPUT -m geoip --source-country {country} -j DROP'"
                subprocess.run(cmd, shell=True, check=True)
            
            # Log the action
            logger.info(f"Countries {', '.join(valid_countries)} unblocked on node {node.id} by user {user_id}")
            
            return True, f"Successfully unblocked traffic from {len(valid_countries)} countries."
            
        except Exception as e:
            logger.error(f"Error unblocking countries: {e}")
            return False, f"Error unblocking countries: {e}"
    
    @staticmethod
    def save_iptables_rules(node):
        """Save the current iptables rules to persist across reboots"""
        try:
            cmd = f"ssh root@{node.ip_address} 'iptables-save > /etc/iptables/rules.v4'"
            subprocess.run(cmd, shell=True, check=True)
            
            # Ensure the iptables-persistent package is installed
            install_cmd = f"ssh root@{node.ip_address} 'apt-get install -y iptables-persistent'"
            subprocess.run(install_cmd, shell=True)
            
            return True, "iptables rules saved successfully."
            
        except Exception as e:
            logger.error(f"Error saving iptables rules: {e}")
            return False, f"Error saving iptables rules: {e}"