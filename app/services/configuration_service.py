import os
import json
import logging
from collections import defaultdict
from flask import current_app
from app.models.models import db, SystemSetting

class ConfigurationService:
    """Service for managing system configuration and settings"""
    
    # Cache of all settings to avoid frequent database queries
    _settings_cache = {}
    
    # Indicates if cache has been initialized
    _cache_initialized = False
    
    # Default settings that will be used if not defined in the database
    # These provide fallbacks for essential configs while allowing overrides
    _default_settings = {
        # Paths
        'paths.nginx_config_dir': '/etc/nginx/conf.d',
        'paths.nginx_sites_dir': '/etc/nginx/sites-available',
        'paths.nginx_enabled_sites_dir': '/etc/nginx/sites-enabled',
        'paths.nginx_includes_dir': '/etc/nginx/includes',
        'paths.letsencrypt_dir': '/etc/letsencrypt',
        'paths.webroot_dir': '/var/www/html',
        'paths.acme_challenge_dir': '/var/www/letsencrypt/.well-known/acme-challenge',
        'paths.geoip_dir': '/usr/share/GeoIP',
        'paths.logs_dir': '/var/log/nginx',
        'paths.cache_dir': '/var/cache/nginx',
        'paths.modsecurity_dir': '/etc/nginx/modsec',
        'paths.crs_dir': '/usr/share/modsecurity-crs',
        
        # Proxy default values
        'proxy.default_http_port': '80',
        'proxy.default_https_port': '443',
        'proxy.default_protocol': 'http',
        'proxy.client_max_body_size': '10M',
        'proxy.server_tokens': 'off',
        'proxy.buffer_size': '8k',
        'proxy.connect_timeout': '60s',
        'proxy.send_timeout': '60s',
        'proxy.read_timeout': '60s',
        'proxy.keepalive_timeout': '65s',
        'proxy.keepalive_requests': '100',
        'proxy.worker_connections': '1024',
        'proxy.worker_processes': 'auto',
        
        # SSL/TLS settings
        'ssl.protocols': 'TLSv1.2 TLSv1.3',
        'ssl.ciphers': 'ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384',
        'ssl.prefer_server_ciphers': 'on',
        'ssl.dhparam_size': '2048',
        'ssl.hsts_max_age': '31536000',
        'ssl.session_cache': 'shared:SSL:10m',
        'ssl.session_timeout': '10m',
        'ssl.session_tickets': 'off',
        
        # Certbot/Let's Encrypt settings
        'certbot.email': 'admin@example.com',
        'certbot.staging': 'true',
        'certbot.renew_before_expiry': '30',
        'certbot.preferred_challenges': 'http',
        
        # ModSecurity settings
        'waf.default_ruleset': 'OWASP-CRS',
        'waf.rule_engine_mode': 'On',
        'waf.paranoia_level': '1',
        'waf.anomaly_threshold': '5',
        'waf.custom_rules_file': '/etc/nginx/modsec/custom-rules.conf',
        
        # GeoIP settings
        'geoip.database_source': 'maxmind',
        'geoip.auto_update': 'true',
        'geoip.update_interval': '30',
        
        # Container settings
        'container.default_image': 'nginx:latest',
        'container.http_port': '80',
        'container.https_port': '443',
        'container.timezone': 'UTC',
        
        # Authentication and security
        'security.password_min_length': '8',
        'security.password_complexity': 'true',
        'security.session_timeout': '3600',
        'security.login_attempts': '5',
        'security.lockout_time': '300',
        'security.api_token_expiry': '86400',
        'security.csp_header': "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'",
        
        # Email settings
        'email.smtp_server': 'smtp.example.com',
        'email.smtp_port': '587',
        'email.use_tls': 'true',
        'email.from_email': 'no-reply@example.com',
        'email.from_name': 'Proxy Manager',
        'email.enable_notifications': 'false',
        
        # System settings
        'system.log_level': 'info',
        'system.log_retention': '30',
        'system.backup_interval': '7',
        'system.backup_retention': '30',
        'system.auto_node_discovery': 'false',
        'system.auto_activate_nodes': 'false',
        
        # Rate limiting
        'rate_limiting.global_rate': '100',
        'rate_limiting.global_rate_period': '60',
        'rate_limiting.api_rate': '60',
        'rate_limiting.api_rate_period': '60',
        'rate_limiting.login_rate': '5',
        'rate_limiting.login_rate_period': '300',
    }
    
    @classmethod
    def initialize(cls):
        """Initialize the configuration service by loading all settings from the database"""
        # Load all settings from database
        try:
            cls._refresh_cache()
            cls._cache_initialized = True
            logging.info("Configuration service initialized successfully")
        except Exception as e:
            logging.error(f"Error initializing configuration service: {str(e)}")
    
    @classmethod
    def _refresh_cache(cls):
        """Refresh the settings cache from the database"""
        settings = SystemSetting.query.all()
        
        # Create a new cache dictionary
        new_cache = {}
        
        # Add all database settings to the cache
        for setting in settings:
            new_cache[setting.key] = setting.value
        
        # Update the cache atomically
        cls._settings_cache = new_cache
    
    @classmethod
    def get(cls, key, default=None):
        """
        Get a configuration value by key
        
        Args:
            key: Configuration key
            default: Default value if key is not found
            
        Returns:
            str: Configuration value or default
        """
        # Ensure the cache is initialized
        if not cls._cache_initialized:
            cls.initialize()
        
        # First, check the cache
        if key in cls._settings_cache:
            return cls._settings_cache[key]
        
        # Then, check the default settings
        if key in cls._default_settings:
            return cls._default_settings[key]
        
        # Return the provided default if key is not found anywhere
        return default
    
    @classmethod
    def get_int(cls, key, default=0):
        """Get a configuration value as an integer"""
        value = cls.get(key, default)
        try:
            return int(value)
        except (TypeError, ValueError):
            return default
    
    @classmethod
    def get_float(cls, key, default=0.0):
        """Get a configuration value as a float"""
        value = cls.get(key, default)
        try:
            return float(value)
        except (TypeError, ValueError):
            return default
    
    @classmethod
    def get_bool(cls, key, default=False):
        """Get a configuration value as a boolean"""
        value = cls.get(key, default)
        if isinstance(value, bool):
            return value
        if isinstance(value, str):
            return value.lower() in ('true', 'yes', '1', 'on')
        return bool(value)
    
    @classmethod
    def get_json(cls, key, default=None):
        """Get a configuration value as a JSON object"""
        value = cls.get(key, None)
        if value is None:
            return default
        try:
            return json.loads(value)
        except (TypeError, ValueError):
            return default
    
    @classmethod
    def get_list(cls, key, default=None):
        """Get a configuration value as a list"""
        if default is None:
            default = []
        value = cls.get(key, None)
        if value is None:
            return default
        
        if isinstance(value, list):
            return value
        
        # Try to parse as JSON first
        try:
            json_value = json.loads(value)
            if isinstance(json_value, list):
                return json_value
        except (TypeError, ValueError):
            pass
        
        # Fallback to comma-separated string
        if isinstance(value, str):
            return [item.strip() for item in value.split(',') if item.strip()]
        
        return default
    
    @classmethod
    def set(cls, key, value):
        """
        Set a configuration value
        
        Args:
            key: Configuration key
            value: Configuration value
        """
        if value is None:
            cls.delete(key)
            return
        
        # Convert value to string if needed
        if not isinstance(value, str):
            if isinstance(value, (dict, list)):
                value = json.dumps(value)
            else:
                value = str(value)
        
        # Update or create the setting
        setting = SystemSetting.query.filter_by(key=key).first()
        
        if setting:
            setting.value = value
        else:
            setting = SystemSetting(key=key, value=value)
            db.session.add(setting)
        
        db.session.commit()
        
        # Update the cache
        cls._settings_cache[key] = value
    
    @classmethod
    def delete(cls, key):
        """
        Delete a configuration value
        
        Args:
            key: Configuration key
        """
        setting = SystemSetting.query.filter_by(key=key).first()
        
        if setting:
            db.session.delete(setting)
            db.session.commit()
        
        # Remove from cache
        cls._settings_cache.pop(key, None)
    
    @classmethod
    def get_all(cls, prefix=None):
        """
        Get all configuration values, optionally filtered by prefix
        
        Args:
            prefix: Optional prefix to filter settings
            
        Returns:
            dict: Dictionary of configuration values
        """
        # Ensure the cache is initialized
        if not cls._cache_initialized:
            cls.initialize()
        
        result = {}
        
        # Get all settings and default values
        for key, value in cls._default_settings.items():
            if prefix is None or key.startswith(prefix):
                result[key] = value
        
        # Override with database values
        for key, value in cls._settings_cache.items():
            if prefix is None or key.startswith(prefix):
                result[key] = value
        
        return result
    
    @classmethod
    def get_grouped(cls):
        """
        Get all configuration values grouped by section
        
        Returns:
            dict: Nested dictionary of configuration values grouped by section
        """
        # Ensure the cache is initialized
        if not cls._cache_initialized:
            cls.initialize()
        
        # Combine default settings and database settings
        all_settings = cls._default_settings.copy()
        all_settings.update(cls._settings_cache)
        
        # Group settings by section (first part of the key before the dot)
        grouped = defaultdict(dict)
        
        for key, value in all_settings.items():
            if '.' in key:
                section, param = key.split('.', 1)
                grouped[section][param] = value
            else:
                grouped['general'][key] = value
        
        return dict(grouped)
    
    @classmethod
    def import_settings(cls, settings_data):
        """
        Import settings from a dictionary or JSON string
        
        Args:
            settings_data: Dictionary of settings or JSON string
            
        Returns:
            tuple: (success, count)
        """
        if isinstance(settings_data, str):
            try:
                settings_data = json.loads(settings_data)
            except ValueError:
                return False, 0
        
        if not isinstance(settings_data, dict):
            return False, 0
        
        count = 0
        
        for key, value in settings_data.items():
            try:
                cls.set(key, value)
                count += 1
            except Exception as e:
                logging.error(f"Error importing setting {key}: {str(e)}")
        
        return True, count
    
    @classmethod
    def export_settings(cls, include_defaults=False):
        """
        Export all settings as a dictionary
        
        Args:
            include_defaults: Whether to include default values
            
        Returns:
            dict: Dictionary of all settings
        """
        # Ensure the cache is initialized
        if not cls._cache_initialized:
            cls.initialize()
        
        if include_defaults:
            result = cls._default_settings.copy()
            result.update(cls._settings_cache)
            return result
        else:
            return cls._settings_cache.copy()
    
    @classmethod
    def get_effective_value(cls, key):
        """
        Get the effective value for a key with possible variable substitution
        
        Args:
            key: Configuration key
            
        Returns:
            str: Resolved configuration value
        """
        value = cls.get(key)
        
        # If the value contains variable references, resolve them
        if value and isinstance(value, str) and '${' in value:
            import re
            
            def replace_var(match):
                var_name = match.group(1)
                default = None
                
                # Check if there's a default value specified
                if ':' in var_name:
                    var_name, default = var_name.split(':', 1)
                
                # Try to get from environment first
                env_value = os.environ.get(var_name)
                if env_value is not None:
                    return env_value
                
                # Try to get from configuration
                config_value = cls.get(var_name)
                if config_value is not None:
                    return config_value
                
                # Fall back to default
                return default or match.group(0)
            
            # Replace all ${var} or ${var:default} references
            value = re.sub(r'\${([^}]+)}', replace_var, value)
        
        return value
    
    @classmethod
    def get_path(cls, key, default=None):
        """
        Get a path configuration value, ensuring it exists and is accessible
        
        Args:
            key: Configuration key
            default: Default value if key is not found
            
        Returns:
            str: Path value
        """
        path = cls.get_effective_value(key) or default
        
        if path:
            # Create directory if it doesn't exist
            os.makedirs(path, exist_ok=True)
        
        return path