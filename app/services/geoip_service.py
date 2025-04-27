from flask import Blueprint, jsonify, request, current_app
from flask_login import login_required, current_user
from app.decorators import admin_required
from app.models.models import db, Node, SystemSetting
from app.services.logger_service import log_activity
import requests
import os
import gzip
import shutil
import subprocess
import time
from datetime import datetime, timedelta

geoip_bp = Blueprint('geoip', __name__)

@geoip_bp.route('/admin/geoip/update', methods=['POST'])
@login_required
@admin_required
def update_geoip_databases():
    """Update GeoIP databases on all nodes"""
    # Get list of nodes to update
    node_ids = request.form.getlist('node_ids', type=int)
    
    if not node_ids:
        return jsonify({
            'success': False,
            'message': 'Please select at least one node to update'
        }), 400
    
    nodes = Node.query.filter(Node.id.in_(node_ids)).all()
    
    if not nodes:
        return jsonify({
            'success': False,
            'message': 'No valid nodes selected'
        }), 400
    
    # Get GeoIP database source settings
    geoip_source = SystemSetting.get('geoip_database_source', 'maxmind')
    geoip_license_key = SystemSetting.get('maxmind_license_key', '')
    
    results = []
    success_count = 0
    error_count = 0
    
    for node in nodes:
        try:
            result = update_node_geoip_database(node, geoip_source, geoip_license_key)
            results.append({
                'node_id': node.id,
                'node_name': node.name,
                'success': result['success'],
                'message': result['message']
            })
            
            if result['success']:
                success_count += 1
            else:
                error_count += 1
                
        except Exception as e:
            results.append({
                'node_id': node.id,
                'node_name': node.name,
                'success': False,
                'message': f"Error updating GeoIP database: {str(e)}"
            })
            error_count += 1
    
    # Update last update time
    if success_count > 0:
        SystemSetting.set('geoip_last_update', datetime.utcnow().isoformat())
    
    return jsonify({
        'success': True,
        'results': results,
        'summary': f"Updated GeoIP databases on {success_count} nodes. {error_count} nodes failed."
    })

def update_node_geoip_database(node, source='maxmind', license_key=None):
    """Update GeoIP database on a specific node
    
    Args:
        node: Node object
        source: Database source ('maxmind' or 'dbip')
        license_key: License key for MaxMind (if applicable)
        
    Returns:
        dict: Result of the update operation
    """
    try:
        from app.services.ssh_connection_service import SSHConnectionService
        
        with SSHConnectionService.get_connection(node) as ssh_client:
            # Create GeoIP directory if it doesn't exist
            SSHConnectionService.execute_command(ssh_client, "sudo mkdir -p /usr/share/GeoIP")
            
            # Download and install GeoIP databases based on source
            if source == 'maxmind':
                if license_key:
                    # Use official MaxMind databases with license key
                    country_v4_url = f"https://download.maxmind.com/app/geoip_download?edition_id=GeoLite2-Country&license_key={license_key}&suffix=tar.gz"
                    country_v6_url = country_v4_url  # Same URL, the database handles both IPv4 and IPv6
                    
                    commands = [
                        f"cd /tmp && curl -s -L '{country_v4_url}' -o maxmind.tar.gz",
                        "cd /tmp && tar -xzf maxmind.tar.gz",
                        "cd /tmp && find . -name '*.mmdb' -exec sudo cp {{}} /usr/share/GeoIP/ \\;",
                        "cd /tmp && rm -rf GeoLite2-Country_* maxmind.tar.gz",
                        "sudo chmod 644 /usr/share/GeoIP/*.mmdb"
                    ]
                else:
                    # Fallback to free sources without license key
                    commands = [
                        "cd /tmp && sudo wget -q https://dl.miyuru.lk/geoip/maxmind/country/maxmind4.dat.gz -O /tmp/maxmind4.dat.gz || wget -q https://cdn.jsdelivr.net/npm/geoip-country-mirror@1.1.0/GeoIP.dat.gz -O /tmp/maxmind4.dat.gz",
                        "cd /tmp && sudo gunzip -f /tmp/maxmind4.dat.gz",
                        "cd /tmp && sudo mv -f /tmp/maxmind4.dat /usr/share/GeoIP/GeoIP.dat",
                        "cd /tmp && sudo wget -q https://dl.miyuru.lk/geoip/maxmind/country/maxmind6.dat.gz -O /tmp/maxmind6.dat.gz || wget -q https://cdn.jsdelivr.net/npm/geoip-country-mirror@1.1.0/GeoIPv6.dat.gz -O /tmp/maxmind6.dat.gz",
                        "cd /tmp && sudo gunzip -f /tmp/maxmind6.dat.gz",
                        "cd /tmp && sudo mv -f /tmp/maxmind6.dat /usr/share/GeoIP/GeoIPv6.dat",
                        "sudo chmod 644 /usr/share/GeoIP/GeoIP*.dat"
                    ]
            elif source == 'dbip':
                # Use DB-IP free databases
                commands = [
                    "cd /tmp && wget -q https://download.db-ip.com/free/dbip-country-lite-$(date +\"%Y-%m\").mmdb.gz -O /tmp/dbip-country.mmdb.gz",
                    "cd /tmp && gunzip -f /tmp/dbip-country.mmdb.gz",
                    "cd /tmp && sudo mv -f /tmp/dbip-country*.mmdb /usr/share/GeoIP/dbip-country.mmdb",
                    "cd /tmp && sudo ln -sf /usr/share/GeoIP/dbip-country.mmdb /usr/share/GeoIP/GeoIP.dat",
                    "cd /tmp && sudo ln -sf /usr/share/GeoIP/dbip-country.mmdb /usr/share/GeoIP/GeoIPv6.dat",
                    "sudo chmod 644 /usr/share/GeoIP/*.mmdb /usr/share/GeoIP/GeoIP*.dat"
                ]
            else:
                # Default case with miyuru.lk source
                commands = [
                    "cd /tmp && sudo wget -q https://dl.miyuru.lk/geoip/maxmind/country/maxmind4.dat.gz -O /tmp/maxmind4.dat.gz",
                    "cd /tmp && sudo gunzip -f /tmp/maxmind4.dat.gz",
                    "cd /tmp && sudo mv -f /tmp/maxmind4.dat /usr/share/GeoIP/GeoIP.dat",
                    "cd /tmp && sudo wget -q https://dl.miyuru.lk/geoip/maxmind/country/maxmind6.dat.gz -O /tmp/maxmind6.dat.gz",
                    "cd /tmp && sudo gunzip -f /tmp/maxmind6.dat.gz",
                    "cd /tmp && sudo mv -f /tmp/maxmind6.dat /usr/share/GeoIP/GeoIPv6.dat",
                    "sudo chmod 644 /usr/share/GeoIP/GeoIP*.dat"
                ]
            
            # Execute commands
            success, results = SSHConnectionService.execute_commands(ssh_client, commands)
            
            if not success:
                # Find the command that failed
                for cmd, exit_code, stdout, stderr in results:
                    if exit_code != 0:
                        return {
                            'success': False,
                            'message': f"Failed to update GeoIP database: {stderr}"
                        }
            
            # Reload Nginx to apply changes
            reload_cmd = node.proxy_reload_command or "sudo systemctl reload nginx"
            exit_code, stdout, stderr = SSHConnectionService.execute_command(ssh_client, reload_cmd)
            
            if exit_code != 0:
                return {
                    'success': False,
                    'message': f"Updated GeoIP database but failed to reload Nginx: {stderr}"
                }
            
            # Log the update
            log_activity(
                category='admin',
                action='update_geoip',
                resource_type='node',
                resource_id=node.id,
                user_id=current_user.id if current_user and current_user.is_authenticated else None,
                details=f"Updated GeoIP database on node {node.name} using {source} source"
            )
            
            return {
                'success': True,
                'message': f"Successfully updated GeoIP database on {node.name}"
            }
            
    except Exception as e:
        log_activity(
            category='error',
            action='update_geoip',
            resource_type='node',
            resource_id=node.id,
            user_id=current_user.id if current_user and current_user.is_authenticated else None,
            details=f"Error updating GeoIP database: {str(e)}"
        )
        
        return {
            'success': False,
            'message': f"Error updating GeoIP database: {str(e)}"
        }

@geoip_bp.route('/admin/geoip/settings', methods=['GET', 'POST'])
@login_required
@admin_required
def geoip_settings():
    """Get or update GeoIP settings"""
    if request.method == 'GET':
        settings = {
            'geoip_database_source': SystemSetting.get('geoip_database_source', 'maxmind'),
            'maxmind_license_key': SystemSetting.get('maxmind_license_key', ''),
            'geoip_auto_update': SystemSetting.get('geoip_auto_update', 'false'),
            'geoip_update_interval': SystemSetting.get('geoip_update_interval', '30'),
            'geoip_last_update': SystemSetting.get('geoip_last_update', None)
        }
        
        return jsonify({
            'success': True,
            'settings': settings
        })
    
    elif request.method == 'POST':
        # Update settings
        source = request.form.get('geoip_database_source', 'maxmind')
        license_key = request.form.get('maxmind_license_key', '')
        auto_update = request.form.get('geoip_auto_update', 'false')
        update_interval = request.form.get('geoip_update_interval', '30')
        
        # Validate settings
        if source not in ['maxmind', 'dbip', 'miyuru']:
            return jsonify({
                'success': False,
                'message': 'Invalid database source. Supported sources: maxmind, dbip, miyuru'
            }), 400
        
        # Update settings
        SystemSetting.set('geoip_database_source', source)
        SystemSetting.set('maxmind_license_key', license_key)
        SystemSetting.set('geoip_auto_update', auto_update)
        SystemSetting.set('geoip_update_interval', update_interval)
        
        # Log the update
        log_activity(
            category='admin',
            action='update_geoip_settings',
            resource_type='system',
            resource_id=None,
            user_id=current_user.id,
            details=f"Updated GeoIP settings: source={source}, auto_update={auto_update}, interval={update_interval} days"
        )
        
        return jsonify({
            'success': True,
            'message': 'GeoIP settings updated successfully'
        })

# Task to check for GeoIP updates
def check_geoip_updates():
    """Check if GeoIP databases need to be updated and update them if needed"""
    try:
        # Check if auto update is enabled
        auto_update = SystemSetting.get('geoip_auto_update', 'false')
        
        if auto_update.lower() != 'true':
            return
        
        # Check last update time
        last_update_str = SystemSetting.get('geoip_last_update', None)
        update_interval = int(SystemSetting.get('geoip_update_interval', '30'))
        
        if last_update_str:
            try:
                last_update = datetime.fromisoformat(last_update_str)
                next_update = last_update + timedelta(days=update_interval)
                
                if datetime.utcnow() < next_update:
                    # Not time to update yet
                    return
            except (ValueError, TypeError):
                # Invalid date format, proceed with update
                pass
        
        # Get all active nodes
        nodes = Node.query.filter_by(is_active=True).all()
        
        if not nodes:
            return
        
        # Get GeoIP settings
        geoip_source = SystemSetting.get('geoip_database_source', 'maxmind')
        geoip_license_key = SystemSetting.get('maxmind_license_key', '')
        
        # Update databases on all nodes
        success_count = 0
        for node in nodes:
            try:
                result = update_node_geoip_database(node, geoip_source, geoip_license_key)
                
                if result['success']:
                    success_count += 1
                    
            except Exception as e:
                log_activity(
                    category='error',
                    action='auto_update_geoip',
                    resource_type='node',
                    resource_id=node.id,
                    details=f"Error in automatic GeoIP update: {str(e)}"
                )
        
        # Update last update time
        if success_count > 0:
            SystemSetting.set('geoip_last_update', datetime.utcnow().isoformat())
            
            log_activity(
                category='system',
                action='auto_update_geoip',
                resource_type='system',
                details=f"Automatically updated GeoIP databases on {success_count} out of {len(nodes)} nodes"
            )
    
    except Exception as e:
        log_activity(
            category='error',
            action='auto_update_geoip',
            resource_type='system',
            details=f"Error running automatic GeoIP update task: {str(e)}"
        )