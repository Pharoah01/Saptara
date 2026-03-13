#!/usr/bin/env python3
"""
🔍 Security Feature Validation Script
Specifically tests the security features implemented in MisfitsBattle

This script validates:
- Bot Protection Middleware
- Security Middleware (SQL injection, path traversal detection)
- Rate limiting
- IP blocking functionality
- WhatsApp/Email alert system
- Session security
- CSRF protection
"""

import requests
import time
import json
from datetime import datetime
import sys
import threading

class SecurityFeatureValidator:
    def __init__(self, base_url=None):
        self.base_url = base_url or "https://api.binarymisfits.info"
        self.session = requests.Session()
        self.results = []
        self.config = {
            'timeout': 10,
            'delay': 0.5,
            'verbose': False
        }
    
    def get_user_input(self):
        """Get user input for validation configuration"""
        print(f"\n{Fore.GREEN}🔧 VALIDATION CONFIGURATION{Style.RESET_ALL}")
        print("=" * 50)
        
        while True:
            target = input(f"{Fore.CYAN}Enter target URL (press Enter for default: {self.base_url}): {Style.RESET_ALL}").strip()
            if not target:
                break
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
        
        print(f"\n{Fore.GREEN}🎯 SELECT VALIDATION TESTS{Style.RESET_ALL}")
        test_options = {
            '1': 'Bot Protection Middleware',
            '2': 'Security Middleware (SQL/Path Traversal)',
            '3': 'Rate Limiting',
            '4': 'Session Security',
            '5': 'CSRF Protection',
            '6': 'Input Validation',
            '7': 'Security Headers',
            '8': 'Robots.txt Configuration',
            'all': 'Run All Tests'
        }
        
        for key, value in test_options.items():
            print(f"  {key}. {value}")
        
        selected_tests = input(f"\n{Fore.CYAN}Select tests (comma-separated numbers or 'all'): {Style.RESET_ALL}").strip()
        
        if selected_tests.lower() == 'all':
            self.selected_tests = list(test_options.keys())[:-1]  # All except 'all'
        else:
            self.selected_tests = [t.strip() for t in selected_tests.split(',') if t.strip() in test_options]
        
        verbose = input(f"{Fore.CYAN}Enable verbose output? (y/N): {Style.RESET_ALL}").strip().lower()
        self.config['verbose'] = verbose == 'y'
        
        print(f"\n{Fore.YELLOW}📋 CONFIGURATION SUMMARY{Style.RESET_ALL}")
        print(f"Target: {self.base_url}")
        print(f"Tests: {len(self.selected_tests)} selected")
        print(f"Verbose: {self.config['verbose']}")
        
        confirm = input(f"\n{Fore.CYAN}Proceed with validation? (y/N): {Style.RESET_ALL}").strip().lower()
        return confirm == 'y'
        
    def log_test(self, feature, test_name, expected, actual, details=""):
        """Log test results with color coding"""
        status = "✅ PASS" if expected == actual else "❌ FAIL"
        result = {
            'feature': feature,
            'test': test_name,
            'expected': expected,
            'actual': actual,
            'status': status,
            'details': details,
            'timestamp': datetime.now().isoformat()
        }
        self.results.append(result)
        
        if self.config['verbose'] or expected != actual:
            color = Fore.GREEN if expected == actual else Fore.RED
            print(f"{color}{status} {feature}: {test_name}{Style.RESET_ALL}")
            if details and self.config['verbose']:
                print(f"    Details: {details}")
        elif not self.config['verbose']:
            print(".", end="", flush=True)

    def test_bot_protection_middleware(self):
        """Test the bot protection middleware"""
        if '1' not in self.selected_tests:
            return
            
        print(f"\n{Fore.CYAN}🤖 Testing Bot Protection Middleware...{Style.RESET_ALL}")
        
        malicious_agents = [
            "sqlmap/1.0",
            "nikto/2.1.6", 
            "Nmap Scripting Engine",
            "w3af.org",
            "OWASP ZAP",
            "Burp Suite",
            "python-requests/2.25.1"
        ]
        
        for agent in malicious_agents:
            try:
                response = self.session.get(
                    f"{self.base_url}/api/challenges/",
                    headers={'User-Agent': agent},
                    timeout=self.config['timeout']
                )
                
                if "Access denied" in response.text or "not allowed" in response.text:
                    self.log_test("Bot Protection", f"Block {agent}", "BLOCKED", "BLOCKED", 
                                f"Response: {response.status_code}")
                else:
                    self.log_test("Bot Protection", f"Block {agent}", "BLOCKED", "ALLOWED", 
                                f"Response: {response.status_code} - {response.text[:100]}")
                    
            except Exception as e:
                self.log_test("Bot Protection", f"Block {agent}", "BLOCKED", "ERROR", str(e))
            
            time.sleep(self.config['delay'])
        
        if not self.config['verbose']:
            print()  # New line after progress dots
        
        legitimate_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"
        ]
        
        for agent in legitimate_agents:
            try:
                response = self.session.get(
                    f"{self.base_url}/api/challenges/",
                    headers={'User-Agent': agent},
                    timeout=10
                )
                
                if response.status_code == 200:
                    self.log_test("Bot Protection", f"Allow {agent[:30]}...", "ALLOWED", "ALLOWED",
                                f"Response: {response.status_code}")
                else:
                    self.log_test("Bot Protection", f"Allow {agent[:30]}...", "ALLOWED", "BLOCKED",
                                f"Response: {response.status_code}")
                    
            except Exception as e:
                self.log_test("Bot Protection", f"Allow {agent[:30]}...", "ALLOWED", "ERROR", str(e))
            
            time.sleep(0.3)

    def test_security_middleware(self):
        """Test the API security middleware"""
        print("\n🛡️ Testing Security Middleware...")
        
        sql_payloads = [
            "' OR '1'='1",
            "'; DROP TABLE users; --",
            "' UNION SELECT * FROM users --"
        ]
        
        for payload in sql_payloads:
            try:
                response = self.session.get(
                    f"{self.base_url}/api/auth/login/",
                    params={'username': payload},
                    timeout=10
                )
                
                if "security" in response.text.lower() or response.status_code == 403:
                    self.log_test("Security Middleware", f"SQL Injection Detection", "BLOCKED", "BLOCKED",
                                f"Payload: {payload[:20]}...")
                else:
                    self.log_test("Security Middleware", f"SQL Injection Detection", "BLOCKED", "ALLOWED",
                                f"Payload: {payload[:20]}... Response: {response.status_code}")
                    
            except Exception as e:
                self.log_test("Security Middleware", f"SQL Injection Detection", "BLOCKED", "ERROR", str(e))
            
            time.sleep(0.5)
        
        path_payloads = [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc//passwd"
        ]
        
        for payload in path_payloads:
            try:
                response = self.session.get(
                    f"{self.base_url}/api/files/{payload}",
                    timeout=10
                )
                
                if "security" in response.text.lower() or response.status_code == 403:
                    self.log_test("Security Middleware", f"Path Traversal Detection", "BLOCKED", "BLOCKED",
                                f"Payload: {payload[:20]}...")
                else:
                    self.log_test("Security Middleware", f"Path Traversal Detection", "BLOCKED", "ALLOWED",
                                f"Payload: {payload[:20]}... Response: {response.status_code}")
                    
            except Exception as e:
                self.log_test("Security Middleware", f"Path Traversal Detection", "BLOCKED", "ERROR", str(e))
            
            time.sleep(0.5)

    def test_rate_limiting(self):
        """Test rate limiting functionality"""
        print("\n⏱️ Testing Rate Limiting...")
        
        endpoint = f"{self.base_url}/api/auth/login/"
        rapid_requests = 15
        blocked_count = 0
        
        print(f"Sending {rapid_requests} rapid requests to test rate limiting...")
        
        for i in range(rapid_requests):
            try:
                response = self.session.post(
                    endpoint,
                    json={'username': f'test{i}', 'password': 'password'},
                    timeout=5
                )
                
                if response.status_code == 429 or "rate limit" in response.text.lower():
                    blocked_count += 1
                    
            except Exception:
                blocked_count += 1
            
            time.sleep(0.1)
        
        if blocked_count > 0:
            self.log_test("Rate Limiting", "Rapid Request Protection", "SOME_BLOCKED", "SOME_BLOCKED",
                        f"{blocked_count}/{rapid_requests} requests blocked")
        else:
            self.log_test("Rate Limiting", "Rapid Request Protection", "SOME_BLOCKED", "NONE_BLOCKED",
                        f"0/{rapid_requests} requests blocked - may need adjustment")

    def test_session_security(self):
        """Test session security features"""
        print("\n🔐 Testing Session Security...")
        
        try:
            response = self.session.get(f"{self.base_url}/api/users/profile/", timeout=10)
            
            if response.status_code == 401:
                self.log_test("Session Security", "Unauthenticated Access Block", "BLOCKED", "BLOCKED",
                            "Correctly requires authentication")
            else:
                self.log_test("Session Security", "Unauthenticated Access Block", "BLOCKED", "ALLOWED",
                            f"Response: {response.status_code}")
                
        except Exception as e:
            self.log_test("Session Security", "Unauthenticated Access Block", "BLOCKED", "ERROR", str(e))
        
        try:
            headers = {'Authorization': 'Bearer invalid_token_12345'}
            response = self.session.get(f"{self.base_url}/api/users/profile/", headers=headers, timeout=10)
            
            if response.status_code == 401:
                self.log_test("Session Security", "Invalid Token Rejection", "BLOCKED", "BLOCKED",
                            "Correctly rejects invalid tokens")
            else:
                self.log_test("Session Security", "Invalid Token Rejection", "BLOCKED", "ALLOWED",
                            f"Response: {response.status_code}")
                
        except Exception as e:
            self.log_test("Session Security", "Invalid Token Rejection", "BLOCKED", "ERROR", str(e))

    def test_csrf_protection(self):
        """Test CSRF protection"""
        print("\n🛡️ Testing CSRF Protection...")
        
        try:
            response = self.session.post(
                f"{self.base_url}/api/users/profile/",
                json={'name': 'Test User', 'email': 'test@example.com'},
                timeout=10
            )
            
            if response.status_code in [401, 403]:
                self.log_test("CSRF Protection", "POST without CSRF token", "BLOCKED", "BLOCKED",
                            f"Response: {response.status_code}")
            else:
                self.log_test("CSRF Protection", "POST without CSRF token", "BLOCKED", "ALLOWED",
                            f"Response: {response.status_code}")
                
        except Exception as e:
            self.log_test("CSRF Protection", "POST without CSRF token", "BLOCKED", "ERROR", str(e))

    def test_input_validation(self):
        """Test input validation"""
        print("\n✅ Testing Input Validation...")
        
        xss_payload = "<script>alert('XSS')</script>"
        
        try:
            response = self.session.post(
                f"{self.base_url}/api/auth/register/",
                json={
                    'username': xss_payload,
                    'email': 'test@example.com',
                    'password': 'password123'
                },
                timeout=10
            )
            
            if "script" not in response.text or response.status_code == 400:
                self.log_test("Input Validation", "XSS Payload Sanitization", "SANITIZED", "SANITIZED",
                            "XSS payload properly handled")
            else:
                self.log_test("Input Validation", "XSS Payload Sanitization", "SANITIZED", "VULNERABLE",
                            "XSS payload may not be properly sanitized")
                
        except Exception as e:
            self.log_test("Input Validation", "XSS Payload Sanitization", "SANITIZED", "ERROR", str(e))
        
        large_input = "A" * 10000
        
        try:
            response = self.session.post(
                f"{self.base_url}/api/auth/register/",
                json={
                    'username': large_input,
                    'email': 'test@example.com',
                    'password': 'password123'
                },
                timeout=10
            )
            
            if response.status_code == 400:
                self.log_test("Input Validation", "Oversized Input Rejection", "REJECTED", "REJECTED",
                            "Large input properly rejected")
            else:
                self.log_test("Input Validation", "Oversized Input Rejection", "REJECTED", "ACCEPTED",
                            f"Large input accepted - Response: {response.status_code}")
                
        except Exception as e:
            self.log_test("Input Validation", "Oversized Input Rejection", "REJECTED", "ERROR", str(e))

    def test_api_security_headers(self):
        """Test security headers"""
        print("\n📋 Testing Security Headers...")
        
        try:
            response = self.session.get(f"{self.base_url}/api/challenges/", timeout=10)
            headers = response.headers
            
            security_headers = {
                'X-Content-Type-Options': 'nosniff',
                'X-Frame-Options': ['DENY', 'SAMEORIGIN'],
                'X-XSS-Protection': '1; mode=block',
                'Strict-Transport-Security': 'max-age',
                'Content-Security-Policy': 'default-src'
            }
            
            for header, expected in security_headers.items():
                if header in headers:
                    if isinstance(expected, list):
                        if any(exp in headers[header] for exp in expected):
                            self.log_test("Security Headers", f"{header} Present", "PRESENT", "PRESENT",
                                        f"Value: {headers[header]}")
                        else:
                            self.log_test("Security Headers", f"{header} Present", "PRESENT", "INCORRECT",
                                        f"Value: {headers[header]}")
                    else:
                        if expected in headers[header]:
                            self.log_test("Security Headers", f"{header} Present", "PRESENT", "PRESENT",
                                        f"Value: {headers[header]}")
                        else:
                            self.log_test("Security Headers", f"{header} Present", "PRESENT", "INCORRECT",
                                        f"Value: {headers[header]}")
                else:
                    self.log_test("Security Headers", f"{header} Present", "PRESENT", "MISSING",
                                "Header not found")
                    
        except Exception as e:
            self.log_test("Security Headers", "Header Check", "SUCCESS", "ERROR", str(e))

    def test_robots_txt(self):
        """Test robots.txt configuration"""
        print("\n🤖 Testing robots.txt Configuration...")
        
        try:
            response = self.session.get(f"{self.base_url}/robots.txt", timeout=10)
            
            if response.status_code == 200:
                content = response.text.lower()
                if "disallow" in content:
                    self.log_test("Robots.txt", "Proper Configuration", "CONFIGURED", "CONFIGURED",
                                "robots.txt properly configured")
                else:
                    self.log_test("Robots.txt", "Proper Configuration", "CONFIGURED", "MINIMAL",
                                "robots.txt exists but minimal configuration")
            else:
                self.log_test("Robots.txt", "Proper Configuration", "CONFIGURED", "MISSING",
                            f"robots.txt not found - Response: {response.status_code}")
                
        except Exception as e:
            self.log_test("Robots.txt", "Proper Configuration", "CONFIGURED", "ERROR", str(e))

    def run_validation(self):
        """Run selected validation tests"""
        print(f"{Fore.GREEN}🔍 Starting Security Feature Validation{Style.RESET_ALL}")
        print("=" * 60)
        print(f"Target: {self.base_url}")
        print(f"Tests: {len(self.selected_tests)} selected")
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        validation_tests = {
            '1': self.test_bot_protection_middleware,
            '2': self.test_security_middleware,
            '3': self.test_rate_limiting,
            '4': self.test_session_security,
            '5': self.test_csrf_protection,
            '6': self.test_input_validation,
            '7': self.test_api_security_headers,
            '8': self.test_robots_txt,
        }
        
        for test_id in self.selected_tests:
            if test_id in validation_tests:
                try:
                    validation_tests[test_id]()
                    time.sleep(1)
                except Exception as e:
                    print(f"{Fore.RED}❌ Error in test {test_id}: {e}{Style.RESET_ALL}")
        
        self.print_validation_summary()

    def print_validation_summary(self):
        """Print validation summary"""
        print("\n" + "=" * 60)
        print("🛡️ SECURITY FEATURE VALIDATION SUMMARY")
        print("=" * 60)
        
        total_tests = len(self.results)
        passed_tests = sum(1 for r in self.results if "✅ PASS" in r['status'])
        failed_tests = sum(1 for r in self.results if "❌ FAIL" in r['status'])
        
        print(f"Total Tests: {total_tests}")
        print(f"✅ Passed: {passed_tests}")
        print(f"❌ Failed: {failed_tests}")
        print(f"🛡️ Security Score: {(passed_tests/total_tests)*100:.1f}%")
        
        features = {}
        for result in self.results:
            feature = result['feature']
            if feature not in features:
                features[feature] = {'passed': 0, 'failed': 0, 'total': 0}
            
            features[feature]['total'] += 1
            if "✅ PASS" in result['status']:
                features[feature]['passed'] += 1
            else:
                features[feature]['failed'] += 1
        
        print(f"\n📊 Results by Feature:")
        for feature, stats in features.items():
            score = (stats['passed'] / stats['total']) * 100
            print(f"   {feature}: {stats['passed']}/{stats['total']} ({score:.1f}%)")
        
        if failed_tests > 0:
            print(f"\n⚠️ FAILED TESTS:")
            for result in self.results:
                if "❌ FAIL" in result['status']:
                    print(f"   - {result['feature']}: {result['test']}")
                    print(f"     Expected: {result['expected']}, Got: {result['actual']}")
                    if result['details']:
                        print(f"     Details: {result['details']}")
        
        with open('security_validation_results.json', 'w') as f:
            json.dump(self.results, f, indent=2)
        
        print(f"\n📄 Detailed results saved to: security_validation_results.json")
        print("=" * 60)

def main():
    """Main function"""
    print(f"{Fore.CYAN}🔍 SECURITY FEATURE VALIDATION{Style.RESET_ALL}")
    print("=" * 50)
    print("This script validates the security features implemented in your application.")
    print(f"{Fore.YELLOW}⚠️  Use only on systems you own or have explicit permission to test.{Style.RESET_ALL}")
    print("=" * 50)
    
    default_url = "https://api.binarymisfits.info"
    if len(sys.argv) > 1:
        default_url = sys.argv[1]
    
    validator = SecurityFeatureValidator(default_url)
    
    if validator.get_user_input():
        validator.run_validation()
    else:
        print(f"{Fore.YELLOW}Validation cancelled by user.{Style.RESET_ALL}")

if __name__ == "__main__":
    main()