#!/usr/bin/env python3
"""
PHP-enabled HTTP Server for Local Website Testing
Uses PHP's built-in server to properly execute PHP files
"""

import subprocess
import os
import sys
import signal
import time

def find_php():
    """Find PHP executable - check local first, then system PATH"""
    # Check for local PHP installation
    local_php = os.path.join(os.getcwd(), "php", "php.exe")
    if os.path.exists(local_php):
        return local_php
    
    # Check system PATH
    try:
        result = subprocess.run(["php", "--version"], capture_output=True, text=True)
        if result.returncode == 0:
            return "php"
    except FileNotFoundError:
        pass
    
    return None

def main():
    PORT = 8080
    
    # Check if local_test_site directory exists
    if not os.path.exists("local_test_site"):
        print("Error: local_test_site directory not found!")
        print("Please run download_site.py first to download a website.")
        sys.exit(1)
    
    # Check if testphp.vulnweb.com subdirectory exists
    if not os.path.exists("local_test_site/testphp.vulnweb.com"):
        print("Error: testphp.vulnweb.com directory not found!")
        print("Please run download_site.py first to download a website.")
        sys.exit(1)
    
    # Find PHP executable
    php_exe = find_php()
    if not php_exe:
        print("Error: PHP not found!")
        print("Please run install_php.bat to install PHP locally, or")
        print("install PHP from https://www.php.net/downloads and add it to PATH.")
        sys.exit(1)
    
    print(f"Using PHP: {php_exe}")
    
    # Change to the PHP site directory
    os.chdir("local_test_site/testphp.vulnweb.com")
    
    print(f"Starting PHP server...")
    print(f"Server will run at: http://localhost:{PORT}")
    print(f"Serving files from: {os.path.abspath('.')}")
    print(f"Available pages:")
    print(f"  - http://localhost:{PORT}/ (index.php)")
    print(f"  - http://localhost:{PORT}/artists.php?artist=1")
    print(f"  - http://localhost:{PORT}/login.php")
    print(f"  - http://localhost:{PORT}/signup.php")
    print(f"  - http://localhost:{PORT}/newuser.php")
    print(f"Press Ctrl+C to stop the server")
    print("-" * 50)
    
    try:
        # Start PHP's built-in server
        cmd = [php_exe, "-S", f"localhost:{PORT}"]
        process = subprocess.Popen(cmd)
        
        # Wait for the process
        process.wait()
        
    except KeyboardInterrupt:
        print("\nStopping PHP server...")
        if 'process' in locals():
            process.terminate()
            process.wait()
        print("Server stopped by user")
    except Exception as e:
        print(f"Error starting PHP server: {e}")
        sys.exit(1)

if __name__ == "__main__":
    main() 