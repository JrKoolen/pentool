#!/usr/bin/env python3
"""
Simple HTTP Server for Local Website Testing
Serves the downloaded website on localhost for penetration testing
"""

import http.server
import socketserver
import os
import sys
from pathlib import Path

class CustomHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        # Serve from the testphp.vulnweb.com directory by default
        super().__init__(*args, directory="local_test_site/testphp.vulnweb.com", **kwargs)
    
    def end_headers(self):
        # Add CORS headers for testing
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', '*')
        super().end_headers()
    
    def do_GET(self):
        # Redirect root to index.html if it exists
        if self.path == '/':
            if os.path.exists(os.path.join(self.directory, 'index.html')):
                self.path = '/index.html'
        super().do_GET()
    
    def log_message(self, format, *args):
        # Custom logging
        print(f"[{self.log_date_time_string()}] {format % args}")

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
    
    with socketserver.TCPServer(("", PORT), CustomHTTPRequestHandler) as httpd:
        print(f"Local web server started!")
        print(f"Server running at: http://localhost:{PORT}")
        print(f"Serving files from: {os.path.abspath('local_test_site/testphp.vulnweb.com')}")
        print(f"Available pages:")
        print(f"  - http://localhost:{PORT}/ (index.html)")
        print(f"  - http://localhost:{PORT}/artists.php?artist=1")
        print(f"  - http://localhost:{PORT}/login.php")
        print(f"  - http://localhost:{PORT}/signup.php")
        print(f"  - http://localhost:{PORT}/newuser.php")
        print(f"Note: PHP files will be served as static files (no execution)")
        print(f"Press Ctrl+C to stop the server")
        print("-" * 50)
        
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\nServer stopped by user")
            httpd.shutdown()

if __name__ == "__main__":
    main() 