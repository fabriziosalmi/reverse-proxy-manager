import os
import json
from flask import current_app
from app.models.models import db, Site
from datetime import datetime

class ConfigTemplateService:
    """Service for managing Nginx configuration templates and presets"""
    
    @staticmethod
    def get_templates_directory():
        """Get the directory where templates are stored"""
        return current_app.config.get('NGINX_TEMPLATES_DIR', 
                                      os.path.join(current_app.root_path, '..', 'nginx_templates'))
    
    @staticmethod
    def get_presets_directory():
        """Get the directory where presets are stored"""
        templates_dir = ConfigTemplateService.get_templates_directory()
        presets_dir = os.path.join(templates_dir, 'presets')
        # Create directory if it doesn't exist
        os.makedirs(presets_dir, exist_ok=True)
        return presets_dir
    
    @staticmethod
    def list_templates():
        """
        List available nginx configuration templates
        
        Returns:
            list: List of template info dictionaries
        """
        templates_dir = ConfigTemplateService.get_templates_directory()
        templates = []
        
        try:
            for filename in os.listdir(templates_dir):
                # Only include .conf files that are not in subdirectories
                if filename.endswith('.conf') and os.path.isfile(os.path.join(templates_dir, filename)):
                    template_path = os.path.join(templates_dir, filename)
                    stat = os.stat(template_path)
                    
                    # Read the first few lines to extract any description
                    description = ""
                    with open(template_path, 'r') as f:
                        first_lines = [next(f, '') for _ in range(5)]
                        for line in first_lines:
                            if line.startswith('#') and 'description:' in line.lower():
                                description = line.split('description:', 1)[1].strip()
                                break
                    
                    templates.append({
                        'filename': filename,
                        'name': os.path.splitext(filename)[0],
                        'path': template_path,
                        'description': description,
                        'size': stat.st_size,
                        'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                    })
        except Exception as e:
            current_app.logger.error(f"Error listing templates: {str(e)}")
        
        return templates
    
    @staticmethod
    def get_template_content(template_name):
        """
        Get the content of a template
        
        Args:
            template_name: Name of the template (with or without .conf extension)
            
        Returns:
            str: Template content or None if not found
        """
        if not template_name.endswith('.conf'):
            template_name += '.conf'
            
        template_path = os.path.join(ConfigTemplateService.get_templates_directory(), template_name)
        
        if os.path.exists(template_path):
            try:
                with open(template_path, 'r') as f:
                    return f.read()
            except Exception as e:
                current_app.logger.error(f"Error reading template {template_name}: {str(e)}")
                return None
        else:
            return None
    
    @staticmethod
    def save_template(template_name, content, overwrite=False):
        """
        Save a template
        
        Args:
            template_name: Name of the template (with or without .conf extension)
            content: Template content
            overwrite: Whether to overwrite an existing template
            
        Returns:
            bool: Success or failure
        """
        if not template_name.endswith('.conf'):
            template_name += '.conf'
            
        template_path = os.path.join(ConfigTemplateService.get_templates_directory(), template_name)
        
        if os.path.exists(template_path) and not overwrite:
            return False
        
        try:
            with open(template_path, 'w') as f:
                f.write(content)
            return True
        except Exception as e:
            current_app.logger.error(f"Error saving template {template_name}: {str(e)}")
            return False
    
    @staticmethod
    def delete_template(template_name):
        """
        Delete a template
        
        Args:
            template_name: Name of the template (with or without .conf extension)
            
        Returns:
            bool: Success or failure
        """
        if not template_name.endswith('.conf'):
            template_name += '.conf'
            
        template_path = os.path.join(ConfigTemplateService.get_templates_directory(), template_name)
        
        # Check if template is one of the default ones (http.conf or https.conf)
        # Don't allow deleting these
        if template_name in ['http.conf', 'https.conf']:
            return False
        
        if os.path.exists(template_path):
            try:
                os.remove(template_path)
                return True
            except Exception as e:
                current_app.logger.error(f"Error deleting template {template_name}: {str(e)}")
                return False
        else:
            return False
    
    @staticmethod
    def list_presets():
        """
        List available configuration presets
        
        Returns:
            list: List of preset info dictionaries
        """
        presets_dir = ConfigTemplateService.get_presets_directory()
        presets = []
        
        try:
            for filename in os.listdir(presets_dir):
                if filename.endswith('.json') and os.path.isfile(os.path.join(presets_dir, filename)):
                    preset_path = os.path.join(presets_dir, filename)
                    stat = os.stat(preset_path)
                    
                    # Load the preset to get its description
                    try:
                        with open(preset_path, 'r') as f:
                            preset_data = json.load(f)
                            description = preset_data.get('description', '')
                            preset_type = preset_data.get('type', 'custom')
                    except:
                        description = ''
                        preset_type = 'custom'
                    
                    presets.append({
                        'filename': filename,
                        'name': os.path.splitext(filename)[0],
                        'path': preset_path,
                        'description': description,
                        'type': preset_type,
                        'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                    })
        except Exception as e:
            current_app.logger.error(f"Error listing presets: {str(e)}")
        
        return presets
    
    @staticmethod
    def get_preset(preset_name):
        """
        Get a preset by name
        
        Args:
            preset_name: Name of the preset (with or without .json extension)
            
        Returns:
            dict: Preset data or None if not found
        """
        if not preset_name.endswith('.json'):
            preset_name += '.json'
            
        preset_path = os.path.join(ConfigTemplateService.get_presets_directory(), preset_name)
        
        if os.path.exists(preset_path):
            try:
                with open(preset_path, 'r') as f:
                    return json.load(f)
            except Exception as e:
                current_app.logger.error(f"Error reading preset {preset_name}: {str(e)}")
                return None
        else:
            return None
    
    @staticmethod
    def save_preset(preset_name, preset_data, overwrite=False):
        """
        Save a preset
        
        Args:
            preset_name: Name of the preset (with or without .json extension)
            preset_data: Preset data dictionary
            overwrite: Whether to overwrite an existing preset
            
        Returns:
            bool: Success or failure
        """
        if not preset_name.endswith('.json'):
            preset_name += '.json'
            
        preset_path = os.path.join(ConfigTemplateService.get_presets_directory(), preset_name)
        
        if os.path.exists(preset_path) and not overwrite:
            return False
        
        try:
            with open(preset_path, 'w') as f:
                json.dump(preset_data, f, indent=2)
            return True
        except Exception as e:
            current_app.logger.error(f"Error saving preset {preset_name}: {str(e)}")
            return False
    
    @staticmethod
    def delete_preset(preset_name):
        """
        Delete a preset
        
        Args:
            preset_name: Name of the preset (with or without .json extension)
            
        Returns:
            bool: Success or failure
        """
        if not preset_name.endswith('.json'):
            preset_name += '.json'
            
        preset_path = os.path.join(ConfigTemplateService.get_presets_directory(), preset_name)
        
        if os.path.exists(preset_path):
            try:
                os.remove(preset_path)
                return True
            except Exception as e:
                current_app.logger.error(f"Error deleting preset {preset_name}: {str(e)}")
                return False
        else:
            return False
    
    @staticmethod
    def apply_preset_to_site(site_id, preset_name):
        """
        Apply a preset to a site
        
        Args:
            site_id: ID of the site
            preset_name: Name of the preset to apply
            
        Returns:
            tuple: (bool success, str message)
        """
        site = Site.query.get(site_id)
        if not site:
            return False, "Site not found"
        
        preset = ConfigTemplateService.get_preset(preset_name)
        if not preset:
            return False, f"Preset '{preset_name}' not found"
        
        try:
            # Apply the preset settings to the site
            if 'use_waf' in preset:
                site.use_waf = preset['use_waf']
                
            if 'force_https' in preset:
                site.force_https = preset['force_https']
                
            if 'enable_cache' in preset:
                site.enable_cache = preset['enable_cache']
                
            if 'cache_time' in preset:
                site.cache_time = preset['cache_time']
                
            if 'cache_browser_time' in preset:
                site.cache_browser_time = preset['cache_browser_time']
                
            if 'cache_static_time' in preset:
                site.cache_static_time = preset['cache_static_time']
                
            if 'custom_config' in preset:
                site.custom_config = preset['custom_config']
                
            if 'custom_cache_rules' in preset:
                site.custom_cache_rules = preset['custom_cache_rules']
                
            # Save the changes
            db.session.commit()
            
            # Return success message
            preset_type = preset.get('type', 'custom')
            return True, f"Successfully applied {preset_type} preset '{preset_name}' to {site.domain}"
            
        except Exception as e:
            db.session.rollback()
            current_app.logger.error(f"Error applying preset: {str(e)}")
            return False, f"Error applying preset: {str(e)}"
    
    @staticmethod
    def create_preset_from_site(site_id, preset_name, description=''):
        """
        Create a preset from a site's current configuration
        
        Args:
            site_id: ID of the site
            preset_name: Name for the new preset
            description: Description of the preset
            
        Returns:
            tuple: (bool success, str message)
        """
        site = Site.query.get(site_id)
        if not site:
            return False, "Site not found"
        
        # Extract configuration settings
        preset_data = {
            'name': preset_name,
            'description': description,
            'type': 'custom',
            'created_from': site.domain,
            'created_at': datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S'),
            'use_waf': site.use_waf,
            'force_https': site.force_https,
            'enable_cache': site.enable_cache,
            'cache_time': site.cache_time,
            'cache_browser_time': site.cache_browser_time,
            'cache_static_time': site.cache_static_time
        }
        
        # Only include non-empty values
        if site.custom_config:
            preset_data['custom_config'] = site.custom_config
        
        if site.custom_cache_rules:
            preset_data['custom_cache_rules'] = site.custom_cache_rules
        
        # Save the preset
        success = ConfigTemplateService.save_preset(preset_name, preset_data)
        
        if success:
            return True, f"Successfully created preset '{preset_name}' from {site.domain}"
        else:
            return False, f"Failed to create preset '{preset_name}'"