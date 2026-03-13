#!/usr/bin/env python3
"""
�️ Universal Security Testing Suite Runner
Comprehensive security testing orchestrator for web applications

This script provides a unified interface to run all security testing tools:
- Universal Security Scanner (comprehensive vulnerability testing)
- Security Feature Validation (validates implemented security features)
- Security Vulnerability Simulation (targeted attack simulation)

⚠️  ETHICAL USE ONLY - Use only on systems you own or have explicit permission to test
"""

import sys
import os
import subprocess
import time
from datetime import datetime

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

class SecurityTestRunner:
    def __init__(self):
        self.scripts = {
            '1': {
                'name': 'Universal Security Scanner',
                'file': 'universal_security_scanner.py',
                'description': 'Comprehensive vulnerability testing with 100+ endpoints and 12 test categories'
            },
            '2': {
                'name': 'Security Feature Validation',
                'file': 'security_feature_validation.py',
                'description': 'Validates your implemented security features (bot protection, middleware, etc.)'
            },
            '3': {
                'name': 'Security Vulnerability Simulation',
                'file': 'security_vulnerability_simulation.py',
                'description': 'Targeted attack simulation for specific vulnerabilities'
            }
        }
    
    def print_banner(self):
        """Print application banner"""
        banner = f"""
{Fore.CYAN}╔══════════════════════════════════════════════════════════════════════╗
║                    🛡️  SECURITY TESTING SUITE                        ║
║                     Universal Web Security Testing                   ║
╚══════════════════════════════════════════════════════════════════════╝{Style.RESET_ALL}

{Fore.YELLOW}⚠️  ETHICAL USE DISCLAIMER ⚠️{Style.RESET_ALL}
This suite is for authorized security testing only.
Only use on systems you own or have explicit written permission to test.
Unauthorized testing may be illegal in your jurisdiction.

{Fore.GREEN}📋 AVAILABLE TESTING TOOLS:{Style.RESET_ALL}
"""
        print(banner)
        
        for key, script in self.scripts.items():
            print(f"  {key}. {Fore.CYAN}{script['name']}{Style.RESET_ALL}")
            print(f"     {script['description']}")
            print()
    
    def get_user_choice(self):
        """Get user's choice of testing tool"""
        while True:
            print(f"{Fore.GREEN}🎯 SELECT TESTING MODE:{Style.RESET_ALL}")
            for key, script in self.scripts.items():
                print(f"  {key}. {script['name']}")
            print(f"  all. Run All Tests (Sequential)")
            print(f"  q. Quit")
            
            choice = input(f"\n{Fore.CYAN}Enter your choice (1-3, all, or q): {Style.RESET_ALL}").strip().lower()
            
            if choice == 'q':
                return None
            elif choice in self.scripts or choice == 'all':
                return choice
            else:
                print(f"{Fore.RED}❌ Invalid choice. Please try again.{Style.RESET_ALL}\n")
    
    def check_script_exists(self, script_file):
        """Check if script file exists"""
        if not os.path.exists(script_file):
            print(f"{Fore.RED}❌ Error: {script_file} not found in current directory{Style.RESET_ALL}")
            print(f"Please ensure all security testing scripts are in the same directory.")
            return False
        return True
    
    def run_script(self, script_file, script_name):
        """Run a security testing script"""
        print(f"\n{Fore.GREEN}🚀 Starting {script_name}...{Style.RESET_ALL}")
        print("=" * 60)
        
        try:
            result = subprocess.run([sys.executable, script_file], 
                                  capture_output=False, 
                                  text=True)
            
            if result.returncode == 0:
                print(f"\n{Fore.GREEN}✅ {script_name} completed successfully{Style.RESET_ALL}")
            else:
                print(f"\n{Fore.YELLOW}⚠️  {script_name} completed with warnings (exit code: {result.returncode}){Style.RESET_ALL}")
                
        except KeyboardInterrupt:
            print(f"\n{Fore.YELLOW}⚠️  {script_name} interrupted by user{Style.RESET_ALL}")
        except Exception as e:
            print(f"\n{Fore.RED}❌ Error running {script_name}: {e}{Style.RESET_ALL}")
    
    def run_all_tests(self):
        """Run all security tests sequentially"""
        print(f"\n{Fore.GREEN}🚀 RUNNING ALL SECURITY TESTS{Style.RESET_ALL}")
        print("=" * 60)
        print(f"Started: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("This will run all three security testing tools sequentially.")
        print("Each tool will prompt for its own configuration.")
        print("=" * 60)
        
        confirm = input(f"\n{Fore.CYAN}Continue with all tests? (y/N): {Style.RESET_ALL}").strip().lower()
        if confirm != 'y':
            print(f"{Fore.YELLOW}All tests cancelled by user.{Style.RESET_ALL}")
            return
        
        start_time = time.time()
        completed_tests = 0
        
        for key, script in self.scripts.items():
            if not self.check_script_exists(script['file']):
                continue
                
            print(f"\n{Fore.MAGENTA}{'='*60}")
            print(f"TEST {key}/3: {script['name'].upper()}")
            print(f"{'='*60}{Style.RESET_ALL}")
            
            self.run_script(script['file'], script['name'])
            completed_tests += 1
            
            if key != '3':
                print(f"\n{Fore.CYAN}⏸️  Pausing 5 seconds before next test...{Style.RESET_ALL}")
                time.sleep(5)
        
        end_time = time.time()
        duration = end_time - start_time
        
        print(f"\n{Fore.GREEN}{'='*60}")
        print("🛡️ ALL SECURITY TESTS COMPLETED")
        print(f"{'='*60}{Style.RESET_ALL}")
        print(f"Tests Completed: {completed_tests}/3")
        print(f"Total Duration: {duration/60:.1f} minutes")
        print(f"Finished: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        
        result_files = [
            'security_scan_results_*.json',
            'security_validation_results.json',
            'security_test_results.json'
        ]
        
        print(f"\n{Fore.CYAN}📄 Check these files for detailed results:{Style.RESET_ALL}")
        for pattern in result_files:
            print(f"   - {pattern}")
        
        print(f"\n{Fore.GREEN}🎉 Security testing suite completed!{Style.RESET_ALL}")
    
    def run_single_test(self, choice):
        """Run a single security test"""
        script = self.scripts[choice]
        
        if not self.check_script_exists(script['file']):
            return
        
        print(f"\n{Fore.GREEN}Selected: {script['name']}{Style.RESET_ALL}")
        print(f"Description: {script['description']}")
        
        confirm = input(f"\n{Fore.CYAN}Run this test? (y/N): {Style.RESET_ALL}").strip().lower()
        if confirm == 'y':
            self.run_script(script['file'], script['name'])
        else:
            print(f"{Fore.YELLOW}Test cancelled by user.{Style.RESET_ALL}")
    
    def run(self):
        """Main runner method"""
        self.print_banner()
        
        while True:
            choice = self.get_user_choice()
            
            if choice is None:
                print(f"{Fore.CYAN}👋 Goodbye!{Style.RESET_ALL}")
                break
            elif choice == 'all':
                self.run_all_tests()
                break
            else:
                self.run_single_test(choice)
                
                another = input(f"\n{Fore.CYAN}Run another test? (y/N): {Style.RESET_ALL}").strip().lower()
                if another != 'y':
                    print(f"{Fore.CYAN}👋 Goodbye!{Style.RESET_ALL}")
                    break
                print()  # Add spacing

def main():
    """Main function"""
    try:
        runner = SecurityTestRunner()
        runner.run()
    except KeyboardInterrupt:
        print(f"\n{Fore.YELLOW}⚠️  Security testing suite interrupted by user{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}❌ Unexpected error: {e}{Style.RESET_ALL}")

if __name__ == "__main__":
    main()