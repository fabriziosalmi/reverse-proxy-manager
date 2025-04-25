#!/usr/bin/env python3
import os
import sys
import unittest
import json
import time
from datetime import datetime, timedelta
from flask import url_for
from werkzeug.datastructures import MultiDict
from app import create_app, db
from app.models.models import User, Node, Site, SiteNode, DeploymentLog, SSLCertificate, SystemLog
import colorama
from colorama import Fore, Back, Style
import warnings
import io
import contextlib

# Initialize colorama for cross-platform colored terminal output
colorama.init(autoreset=True)

class TestResult(unittest.TextTestResult):
    """Custom test result class with colored output"""
    
    def startTest(self, test):
        super().startTest(test)
        test_name = self.getDescription(test)
        self.stream.write(f"{Fore.CYAN}Running: {test_name}{Style.RESET_ALL} ... ")
        self.stream.flush()
    
    def addSuccess(self, test):
        super().addSuccess(test)
        self.stream.write(f"{Fore.GREEN}✓ PASS{Style.RESET_ALL}\n")
    
    def addError(self, test, err):
        super().addError(test, err)
        self.stream.write(f"{Fore.RED}✗ ERROR{Style.RESET_ALL}\n")
    
    def addFailure(self, test, err):
        super().addFailure(test, err)
        self.stream.write(f"{Fore.YELLOW}✗ FAIL{Style.RESET_ALL}\n")
    
    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self.stream.write(f"{Fore.BLUE}⚪ SKIPPED{Style.RESET_ALL} ({reason})\n")

class CustomTestRunner(unittest.TextTestRunner):
    """Custom test runner with better formatting"""
    
    def __init__(self, **kwargs):
        super().__init__(**kwargs)
        self.resultclass = TestResult
    
    def run(self, test):
        # Filter certain warnings
        with warnings.catch_warnings():
            warnings.filterwarnings("ignore", category=DeprecationWarning)
            warnings.filterwarnings("ignore", message=".*?Using the in-memory storage for tracking rate limits.*?")
            warnings.filterwarnings("ignore", message=".*?TripleDES has been moved to.*?")
            
            # Buffer outputs to suppress unimportant messages
            with contextlib.redirect_stderr(io.StringIO()):
                result = super().run(test)
        
        # Print summary
        print("\n" + "="*80)
        print(f"{Fore.CYAN}Test Summary:{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}Passed:{Style.RESET_ALL} {result.testsRun - len(result.failures) - len(result.errors)}")
        print(f"  {Fore.YELLOW}Failed:{Style.RESET_ALL} {len(result.failures)}")
        print(f"  {Fore.RED}Errors:{Style.RESET_ALL} {len(result.errors)}")
        
        # Print failures and errors with more details
        if result.failures:
            print("\n" + "="*80)
            print(f"{Fore.YELLOW}Failures:{Style.RESET_ALL}")
            for i, (test, traceback) in enumerate(result.failures, 1):
                print(f"\n{i}. {test}")
                print(f"{Fore.YELLOW}{traceback.split('Traceback')[0].strip()}{Style.RESET_ALL}")
        
        if result.errors:
            print("\n" + "="*80)
            print(f"{Fore.RED}Errors:{Style.RESET_ALL}")
            for i, (test, traceback) in enumerate(result.errors, 1):
                print(f"\n{i}. {test}")
                error_lines = traceback.split('\n')
                error_summary = '\n' + '\n'.join([line for line in error_lines if "File" in line][-1:] + [error_lines[-1]])
                print(f"{Fore.RED}{error_summary}{Style.RESET_ALL}")
        
        print("\n" + "="*80)
        
        if result.wasSuccessful():
            print(f"{Fore.GREEN}All tests passed successfully!{Style.RESET_ALL}")
        else:
            print(f"{Fore.YELLOW}Some tests failed or had errors. See details above.{Style.RESET_ALL}")
        
        return result

class ItaliaProxyTestCase(unittest.TestCase):
    """Comprehensive test case for Italia CDN Proxy application"""
    
    def setUp(self):
        """Set up test environment before each test"""
        self.app = create_app('testing')
        self.app.config['WTF_CSRF_ENABLED'] = False  # Disable CSRF for testing
        self.app.config['TESTING'] = True
        self.app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///:memory:'
        self.app.config['PASSWORD_ENCRYPTION_KEY'] = 'testkeyfortesting12345'  # For Node password encryption
        self.app_context = self.app.app_context()
        self.app_context.push()
        self.client = self.app.test_client()
        db.create_all()
        
        # Create test admin user - only use parameters that the User model accepts
        admin = User(
            username='testadmin',
            email='admin@example.com',
            password='Testing123',  # Meets password complexity requirements
            role='admin'
        )
        # Set is_active separately after creation
        admin.is_active = True
        
        # Create test client user - only use parameters that the User model accepts
        client_user = User(
            username='testclient',
            email='client@example.com',
            password='Testing123',  # Meets password complexity requirements
            role='client'
        )
        # Set is_active separately after creation
        client_user.is_active = True
        
        db.session.add(admin)
        db.session.add(client_user)
        db.session.commit()
        
    def tearDown(self):
        """Clean up after each test"""
        db.session.remove()
        db.drop_all()
        self.app_context.pop()
    
    def login(self, username, password):
        """Helper method to log in a user"""
        return self.client.post('/auth/login', data={
            'username': username,
            'password': password
        }, follow_redirects=True)
    
    def logout(self):
        """Helper method to log out a user"""
        return self.client.get('/auth/logout', follow_redirects=True)
    
    # ========== AUTH TESTS ==========
    
    def test_login_success(self):
        """Test successful login"""
        response = self.login('testadmin', 'Testing123')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Dashboard', response.data)
    
    def test_login_failure(self):
        """Test failed login attempt"""
        response = self.login('testadmin', 'wrongpassword')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Invalid username or password', response.data)
    
    def test_logout(self):
        """Test user logout"""
        self.login('testadmin', 'Testing123')
        response = self.logout()
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'You have been logged out', response.data)
    
    # ========== USER MANAGEMENT TESTS ==========
    
    def test_admin_create_user(self):
        """Test creating a new user as admin"""
        self.login('testadmin', 'Testing123')
        response = self.client.post('/admin/users/new', data={
            'username': 'newuser',
            'email': 'newuser@example.com',
            'password': 'Testing123',
            'confirm_password': 'Testing123',
            'role': 'client',
            'is_active': True
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        # Verify user exists in database
        user = User.query.filter_by(username='newuser').first()
        self.assertIsNotNone(user)
        self.assertEqual(user.email, 'newuser@example.com')
        self.assertEqual(user.role, 'client')
    
    def test_admin_edit_user(self):
        """Test editing an existing user as admin"""
        # Create a user to edit
        user = User(username='editme', email='editme@example.com', password='Password123', role='client')
        db.session.add(user)
        db.session.commit()
        
        self.login('testadmin', 'Testing123')
        response = self.client.post(f'/admin/users/{user.id}/edit', data={
            'username': 'editme',
            'email': 'updated@example.com',
            'role': 'client',
            'is_active': True
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        # Verify user was updated
        updated_user = User.query.get(user.id)
        self.assertEqual(updated_user.email, 'updated@example.com')
    
    def test_admin_delete_user(self):
        """Test deleting a user as admin"""
        # Create a user to delete
        user = User(username='deleteme', email='deleteme@example.com', password='Password123', role='client')
        db.session.add(user)
        db.session.commit()
        user_id = user.id
        
        self.login('testadmin', 'Testing123')
        response = self.client.post(f'/admin/users/{user_id}/delete', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        # Verify user was deleted
        deleted_user = User.query.get(user_id)
        self.assertIsNone(deleted_user)
    
    # ========== NODE MANAGEMENT TESTS ==========
    
    def test_admin_create_node(self):
        """Test creating a new node as admin"""
        self.login('testadmin', 'Testing123')
        response = self.client.post('/admin/nodes/new', data={
            'name': 'Test Node',
            'ip_address': '192.168.1.100',
            'ssh_user': 'root',
            'auth_method': 'password',
            'ssh_password': 'testpassword',
            'ssh_port': 22,
            'proxy_type': 'nginx',
            'proxy_config_path': '/etc/nginx/sites-available',
            'proxy_reload_command': 'systemctl reload nginx',
            'is_active': True
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        # Verify node exists in database
        node = Node.query.filter_by(name='Test Node').first()
        self.assertIsNotNone(node)
        self.assertEqual(node.ip_address, '192.168.1.100')
        self.assertEqual(node.proxy_type, 'nginx')
    
    def test_admin_edit_node(self):
        """Test editing an existing node as admin"""
        # Create a node to edit
        node = Node(
            name='Edit Node',
            ip_address='192.168.1.101',
            ssh_user='root',
            ssh_password='testpassword',
            ssh_port=22,
            proxy_type='nginx',
            proxy_config_path='/etc/nginx/sites-available',
            proxy_reload_command='systemctl reload nginx',
            is_active=True
        )
        db.session.add(node)
        db.session.commit()
        
        self.login('testadmin', 'Testing123')
        response = self.client.post(f'/admin/nodes/{node.id}/edit', data={
            'name': 'Updated Node',
            'ip_address': '192.168.1.101',
            'ssh_user': 'root',
            'ssh_port': 22,
            'proxy_type': 'caddy',
            'proxy_config_path': '/etc/caddy',
            'proxy_reload_command': 'systemctl reload caddy',
            'is_active': True
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        # Verify node was updated
        updated_node = Node.query.get(node.id)
        self.assertEqual(updated_node.name, 'Updated Node')
        self.assertEqual(updated_node.proxy_type, 'caddy')
    
    def test_admin_toggle_node_active(self):
        """Test toggling a node's active status"""
        # Create a node
        node = Node(
            name='Toggle Node',
            ip_address='192.168.1.102',
            ssh_user='root',
            ssh_password='testpassword',
            ssh_port=22,
            proxy_type='nginx',
            is_active=True
        )
        db.session.add(node)
        db.session.commit()
        
        self.login('testadmin', 'Testing123')
        
        # Mock the NginxValidationService.test_config_on_node method to avoid SSH connections
        from unittest.mock import patch
        with patch('app.services.nginx_validation_service.NginxValidationService.test_config_on_node') as mock_test:
            # Configure the mock to return a valid response
            mock_test.return_value = (True, "", "")
            
            # First toggle - should deactivate the node
            response = self.client.post(f'/admin/nodes/{node.id}/toggle_active', follow_redirects=True)
            self.assertEqual(response.status_code, 200)
            
            # Verify node status was toggled
            db.session.expire_all()
            updated_node = Node.query.get(node.id)
            self.assertFalse(updated_node.is_active)
            
            # Second toggle - should reactivate the node
            response = self.client.post(f'/admin/nodes/{node.id}/toggle_active', follow_redirects=True)
            self.assertEqual(response.status_code, 200)
            
            # Verify node was reactivated
            db.session.expire_all()
            updated_node = Node.query.get(node.id)
            self.assertTrue(updated_node.is_active)
    
    def test_admin_delete_node(self):
        """Test deleting a node"""
        # Create a node to delete
        node = Node(
            name='Delete Node',
            ip_address='192.168.1.103',
            ssh_user='root',
            ssh_password='testpassword',
            ssh_port=22,
            proxy_type='nginx',
            is_active=True
        )
        db.session.add(node)
        db.session.commit()
        node_id = node.id
        
        self.login('testadmin', 'Testing123')
        response = self.client.post(f'/admin/nodes/{node_id}/delete', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        # Verify node was deleted
        deleted_node = Node.query.get(node_id)
        self.assertIsNone(deleted_node)
    
    # ========== SITE MANAGEMENT TESTS ==========
    
    def test_client_create_site(self):
        """Test creating a new site as client"""
        # Create a node for the site
        node = Node(
            name='Site Node',
            ip_address='192.168.1.104',
            ssh_user='root',
            ssh_password='testpassword',
            ssh_port=22,
            proxy_type='nginx',
            is_active=True
        )
        db.session.add(node)
        db.session.commit()
        
        self.login('testclient', 'Testing123')
        response = self.client.post('/client/sites/new', data={
            'name': 'Test Site',
            'domain': 'testsite.com',
            'protocol': 'https',
            'origin_address': 'origin.testsite.com',
            'origin_port': 443,
            'nodes[]': [node.id],
            'use_waf': True,
            'force_https': True
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        # Verify site exists in database
        site = Site.query.filter_by(name='Test Site').first()
        self.assertIsNotNone(site)
        self.assertEqual(site.domain, 'testsite.com')
        self.assertEqual(site.protocol, 'https')
        self.assertTrue(site.force_https)  # Check force_https is True
        
        # Verify site-node relationship
        site_node = SiteNode.query.filter_by(site_id=site.id, node_id=node.id).first()
        self.assertIsNotNone(site_node)
    
    def test_client_edit_site(self):
        """Test editing a site as client"""
        # Create a client user
        client = User.query.filter_by(username='testclient').first()
        
        # Create a site to edit
        site = Site(
            name='Edit Site',
            domain='editsite.com',
            protocol='http',
            origin_address='origin.editsite.com',
            origin_port=80,
            user_id=client.id,
            is_active=True
        )
        db.session.add(site)
        db.session.commit()
        
        self.login('testclient', 'Testing123')
        response = self.client.post(f'/client/sites/{site.id}/edit', data={
            'name': 'Updated Site',
            'domain': 'editsite.com',
            'protocol': 'https',
            'origin_address': 'origin.editsite.com',
            'origin_port': 443,
            'use_waf': True,
            'force_https': True
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        # Verify site was updated
        updated_site = Site.query.get(site.id)
        self.assertEqual(updated_site.name, 'Updated Site')
        self.assertEqual(updated_site.protocol, 'https')
        self.assertEqual(updated_site.origin_port, 443)
    
    def test_client_toggle_site_active(self):
        """Test toggling a site's active status"""
        # Create a client user
        client = User.query.filter_by(username='testclient').first()
        
        # Create a site
        site = Site(
            name='Toggle Site',
            domain='togglesite.com',
            protocol='https',
            origin_address='origin.togglesite.com',
            origin_port=443,
            user_id=client.id,
            is_active=True
        )
        db.session.add(site)
        db.session.commit()
        
        self.login('testclient', 'Testing123')
        response = self.client.post(f'/client/sites/{site.id}/toggle_active', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        # Verify site status was toggled
        updated_site = Site.query.get(site.id)
        self.assertFalse(updated_site.is_active)
        
        # Toggle back
        response = self.client.post(f'/client/sites/{site.id}/toggle_active', follow_redirects=True)
        updated_site = Site.query.get(site.id)
        self.assertTrue(updated_site.is_active)
    
    def test_admin_block_site(self):
        """Test blocking a site as admin"""
        # Create a site to block
        client = User.query.filter_by(username='testclient').first()
        site = Site(
            name='Block Site',
            domain='blocksite.com',
            protocol='https',
            origin_address='origin.blocksite.com',
            origin_port=443,
            user_id=client.id,
            is_active=True,
            is_blocked=False
        )
        db.session.add(site)
        db.session.commit()
        
        self.login('testadmin', 'Testing123')
        response = self.client.post(f'/admin/sites/{site.id}/toggle_blocked', follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        # Verify site was blocked
        updated_site = Site.query.get(site.id)
        self.assertTrue(updated_site.is_blocked)
    
    def test_admin_bulk_toggle_sites(self):
        """Test bulk toggling site status"""
        # Create sites to toggle
        client = User.query.filter_by(username='testclient').first()
        sites = []
        for i in range(3):
            site = Site(
                name=f'Bulk Site {i}',
                domain=f'bulksite{i}.com',
                protocol='https',
                origin_address=f'origin.bulksite{i}.com',
                origin_port=443,
                user_id=client.id,
                is_active=True
            )
            sites.append(site)
            db.session.add(site)
        db.session.commit()
        
        site_ids = ','.join([str(site.id) for site in sites])
        
        self.login('testadmin', 'Testing123')
        response = self.client.post('/admin/sites/bulk-toggle', data={
            'action': 'deactivate',
            'site_ids': site_ids
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        # Verify sites were deactivated
        for site in sites:
            updated_site = Site.query.get(site.id)
            self.assertFalse(updated_site.is_active)
    
    # ========== WAF SETTINGS TESTS ==========
    
    def test_admin_manage_waf_settings(self):
        """Test configuring WAF settings for a site"""
        # Create a site 
        client = User.query.filter_by(username='testclient').first()
        site = Site(
            name='WAF Test Site',
            domain='wafsite.com',
            protocol='https',
            origin_address='origin.wafsite.com',
            origin_port=443,
            user_id=client.id,
            is_active=True,
            use_waf=False
        )
        db.session.add(site)
        db.session.commit()
        
        self.login('testadmin', 'Testing123')
        response = self.client.post(f'/admin/sites/{site.id}/waf', data={
            'use_waf': 'on',
            'waf_rule_level': 'medium',
            'waf_custom_rules': 'SecRule REQUEST_HEADERS:User-Agent "badbot" "id:1000,phase:1,deny,status:403,log,msg:\'Blocked Bad Bot\'"',
            'waf_max_request_size': '10',
            'waf_request_timeout': '60',
            'waf_block_tor_exit_nodes': 'on',
            'waf_rate_limiting_enabled': 'on',
            'waf_rate_limiting_requests': '100',
            'waf_rate_limiting_burst': '200',
            'waf_use_owasp_crs': 'on',
            'waf_owasp_crs_paranoia': '1',
            'waf_disabled_rule_ids': '942100,942110'
        }, follow_redirects=True)
        self.assertEqual(response.status_code, 200)
        
        # Verify WAF settings were updated
        updated_site = Site.query.get(site.id)
        self.assertTrue(updated_site.use_waf)
        self.assertEqual(updated_site.waf_rule_level, 'medium')
        self.assertTrue(updated_site.waf_block_tor_exit_nodes)
        self.assertTrue(updated_site.waf_rate_limiting_enabled)
        self.assertEqual(updated_site.waf_rate_limiting_requests, 100)
        self.assertTrue(updated_site.waf_use_owasp_crs)
        self.assertEqual(updated_site.waf_owasp_crs_paranoia, 1)
    
    # ========== SSL CERTIFICATE TESTS ==========
    
    def test_view_ssl_dashboard(self):
        """Test viewing SSL certificate dashboard"""
        # Create a node
        node = Node(
            name='SSL Node',
            ip_address='192.168.1.105',
            ssh_user='root',
            ssh_password='testpassword',
            ssh_port=22,
            proxy_type='nginx',
            is_active=True
        )
        db.session.add(node)
        db.session.commit()
        
        # Get the client user
        client = User.query.filter_by(username='testclient').first()
        
        # Create a site for the certificates
        site = Site(
            name='SSL Test Site',
            domain='ssl-test.com',
            protocol='https',
            origin_address='origin.ssl-test.com',
            origin_port=443,
            user_id=client.id,
            is_active=True
        )
        db.session.add(site)
        db.session.commit()
        
        # Create certificates using the actual fields in your SSLCertificate model
        cert1 = SSLCertificate(
            site_id=site.id,
            node_id=node.id,
            domain='example.com',
            issuer='Let\'s Encrypt',
            status='valid',
            valid_until=datetime.now() + timedelta(days=60)
        )
        
        cert2 = SSLCertificate(
            site_id=site.id,
            node_id=node.id,
            domain='expiring.com',
            issuer='Let\'s Encrypt',
            status='expiring_soon',
            valid_until=datetime.now() + timedelta(days=10)
        )
        
        db.session.add(cert1)
        db.session.add(cert2)
        db.session.commit()
        
        self.login('testadmin', 'Testing123')
        response = self.client.get('/admin/ssl-dashboard')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'example.com', response.data)
        self.assertIn(b'expiring.com', response.data)
    
    # ========== PROXY OPERATIONS TESTS ==========
    
    def test_admin_check_proxy_status(self):
        """Test checking proxy service status on a node"""
        # Create a node
        node = Node(
            name='Proxy Status Node',
            ip_address='192.168.1.106',
            ssh_user='root',
            ssh_password='testpassword',
            ssh_port=22,
            proxy_type='nginx',
            is_active=True
        )
        db.session.add(node)
        db.session.commit()
        
        self.login('testadmin', 'Testing123')
        response = self.client.get(f'/admin/nodes/{node.id}/proxy-status')
        self.assertEqual(response.status_code, 200)
        # Note: This test will return a mock response since we can't actually SSH to a node

    # ========== LOGGING TESTS ==========
    
    def test_activity_logging(self):
        """Test system activity logging"""
        from app.services.logger_service import log_activity
        
        # Log an activity
        log_activity(
            category='admin',
            action='test_action',
            resource_type='test',
            resource_id=1,
            details='This is a test log entry'
        )
        
        # Verify log entry was created
        log_entry = SystemLog.query.filter_by(action='test_action').first()
        self.assertIsNotNone(log_entry)
        self.assertEqual(log_entry.category, 'admin')
        self.assertEqual(log_entry.resource_type, 'test')
        self.assertEqual(log_entry.details, 'This is a test log entry')
    
    def test_admin_view_system_logs(self):
        """Test viewing system logs as admin"""
        # Create some log entries
        log1 = SystemLog(
            category='admin',
            action='create_user',
            resource_type='user',
            resource_id=1,
            details='Created new admin user'
        )
        
        log2 = SystemLog(
            category='security',
            action='login_failed',
            resource_type='user',
            resource_id=None,
            details='Failed login attempt'
        )
        
        db.session.add(log1)
        db.session.add(log2)
        db.session.commit()
        
        self.login('testadmin', 'Testing123')
        response = self.client.get('/admin/system/logs')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Created new admin user', response.data)
        self.assertIn(b'Failed login attempt', response.data)

    # ========== DEPLOYMENT TESTS ==========
    
    def test_deployment_logs(self):
        """Test viewing deployment logs"""
        # Create a client user
        client = User.query.filter_by(username='testclient').first()
        
        # Create a site and node
        site = Site(
            name='Deployment Site',
            domain='deploysite.com',
            protocol='https',
            origin_address='origin.deploysite.com',
            origin_port=443,
            user_id=client.id,
            is_active=True
        )
        
        node = Node(
            name='Deployment Node',
            ip_address='192.168.1.107',
            ssh_user='root',
            ssh_password='testpassword',
            ssh_port=22,
            proxy_type='nginx',
            is_active=True
        )
        
        db.session.add(site)
        db.session.add(node)
        db.session.commit()
        
        # Create deployment logs
        log1 = DeploymentLog(
            site_id=site.id,
            node_id=node.id,
            action='Initial deployment',
            status='success',
            message='Site deployed successfully'
        )
        
        log2 = DeploymentLog(
            site_id=site.id,
            node_id=node.id,
            action='Configuration update',
            status='error',
            message='Failed to update configuration: Connection error'
        )
        
        db.session.add(log1)
        db.session.add(log2)
        db.session.commit()
        
        self.login('testadmin', 'Testing123')
        response = self.client.get('/admin/logs')
        self.assertEqual(response.status_code, 200)
        self.assertIn(b'Initial deployment', response.data)
        self.assertIn(b'Configuration update', response.data)
        self.assertIn(b'success', response.data)
        self.assertIn(b'error', response.data)

def load_tests(loader, standard_tests, pattern):
    """Load tests in specific groups to improve organization"""
    suite = unittest.TestSuite()
    
    # Group 1: Authentication Tests
    auth_tests = unittest.TestSuite()
    auth_tests.addTest(ItaliaProxyTestCase('test_login_success'))
    auth_tests.addTest(ItaliaProxyTestCase('test_login_failure'))
    auth_tests.addTest(ItaliaProxyTestCase('test_logout'))
    suite.addTest(auth_tests)
    
    # Group 2: User Management Tests
    user_mgmt_tests = unittest.TestSuite()
    user_mgmt_tests.addTest(ItaliaProxyTestCase('test_admin_create_user'))
    user_mgmt_tests.addTest(ItaliaProxyTestCase('test_admin_edit_user'))
    user_mgmt_tests.addTest(ItaliaProxyTestCase('test_admin_delete_user'))
    suite.addTest(user_mgmt_tests)
    
    # Group 3: Node Management Tests
    node_mgmt_tests = unittest.TestSuite()
    node_mgmt_tests.addTest(ItaliaProxyTestCase('test_admin_create_node'))
    node_mgmt_tests.addTest(ItaliaProxyTestCase('test_admin_edit_node'))
    node_mgmt_tests.addTest(ItaliaProxyTestCase('test_admin_toggle_node_active'))
    node_mgmt_tests.addTest(ItaliaProxyTestCase('test_admin_delete_node'))
    suite.addTest(node_mgmt_tests)
    
    # Group 4: Site Management Tests
    site_mgmt_tests = unittest.TestSuite()
    site_mgmt_tests.addTest(ItaliaProxyTestCase('test_client_create_site'))
    site_mgmt_tests.addTest(ItaliaProxyTestCase('test_client_edit_site'))
    site_mgmt_tests.addTest(ItaliaProxyTestCase('test_client_toggle_site_active'))
    site_mgmt_tests.addTest(ItaliaProxyTestCase('test_admin_block_site'))
    site_mgmt_tests.addTest(ItaliaProxyTestCase('test_admin_bulk_toggle_sites'))
    suite.addTest(site_mgmt_tests)
    
    # Add other groups as needed
    
    return suite

def run_tests():
    """Run the test suite with colored output"""
    print(f"{Fore.CYAN}{Style.BRIGHT}======================================{Style.RESET_ALL}")
    print(f"{Fore.CYAN}{Style.BRIGHT}  Italia CDN Proxy - Test Runner     {Style.RESET_ALL}")
    print(f"{Fore.CYAN}{Style.BRIGHT}======================================{Style.RESET_ALL}")
    print(f"Starting tests at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
    
    runner = CustomTestRunner(verbosity=2)
    unittest.main(testRunner=runner, exit=False)

if __name__ == '__main__':
    run_tests()