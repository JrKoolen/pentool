#!/usr/bin/env python3
"""
Test script for SQL injection vulnerability scanning.
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), 'src'))

from src.modules.vulnerabilities.sql_injection import SQLInjectionScanner
from src.core.utils import Logger

def test_sql_injection():
    """Test SQL injection scanning."""
    print("=== SQL Injection Vulnerability Scanner Test ===\n")
    
    # Initialize scanner
    scanner = SQLInjectionScanner()
    
    # Test URLs with potential SQL injection vulnerabilities
    test_urls = [
        "http://testphp.vulnweb.com/artists.php?artist=1",
        "http://testphp.vulnweb.com/listproducts.php?cat=1",
        "http://testphp.vulnweb.com/search.php?test=query"
    ]
    
    for url in test_urls:
        print(f"Testing URL: {url}")
        print("-" * 50)
        
        try:
            # Scan for SQL injection vulnerabilities
            results = scanner.scan_url(url)
            
            # Display results
            vulnerabilities = results.get('vulnerabilities', [])
            
            if vulnerabilities:
                print(f"Found {len(vulnerabilities)} SQL injection vulnerabilities:")
                for i, vuln in enumerate(vulnerabilities, 1):
                    print(f"\n{i}. Parameter: {vuln['parameter']}")
                    print(f"   Type: {vuln['injection_type']}")
                    print(f"   Severity: {vuln['severity']}")
                    print(f"   Payload: {vuln['payload']}")
                    print(f"   Evidence: {vuln['evidence']}")
            else:
                print("No SQL injection vulnerabilities found.")
            
            # Display summary
            summary = results.get('summary', {})
            print(f"\nSummary:")
            print(f"  Total parameters tested: {summary.get('total_tested', 0)}")
            print(f"  Vulnerable parameters: {summary.get('vulnerable_parameters', 0)}")
            print(f"  Injection types found: {', '.join(summary.get('injection_types', []))}")
            
        except Exception as e:
            print(f"Error scanning {url}: {e}")
        
        print("\n" + "=" * 60 + "\n")

def test_specific_payload():
    """Test specific SQL injection payloads."""
    print("=== Testing Specific SQL Injection Payloads ===\n")
    
    scanner = SQLInjectionScanner()
    
    # Test URL with a parameter
    test_url = "http://testphp.vulnweb.com/artists.php?artist=1"
    
    # Test specific payloads
    payloads = [
        "'",
        "' OR 1=1--",
        "' AND 1=1--",
        "' UNION SELECT NULL--",
        "'; DROP TABLE users--"
    ]
    
    print(f"Testing URL: {test_url}")
    print("Testing individual payloads:")
    print("-" * 50)
    
    for payload in payloads:
        print(f"\nTesting payload: {payload}")
        
        try:
            # Create test URL with payload
            test_url_with_payload = f"{test_url.replace('artist=1', 'artist=' + payload)}"
            
            # Send request and check for SQL errors
            import requests
            response = requests.get(test_url_with_payload, timeout=10)
            
            # Check for SQL error patterns
            content = response.text.lower()
            sql_errors = [
                'sql syntax',
                'mysql error',
                'oracle error',
                'sql server error',
                'postgresql error'
            ]
            
            found_errors = []
            for error in sql_errors:
                if error in content:
                    found_errors.append(error)
            
            if found_errors:
                print(f"  ✓ SQL Error detected: {', '.join(found_errors)}")
            else:
                print(f"  ✗ No SQL errors detected")
                
        except Exception as e:
            print(f"  ✗ Error: {e}")

if __name__ == "__main__":
    print("SQL Injection Vulnerability Scanner Test")
    print("=" * 50)
    print()
    print("This script tests SQL injection vulnerability scanning.")
    print("It will test against known vulnerable test sites.")
    print("WARNING: Only test against sites you have permission to test!")
    print()
    
    try:
        # Test full SQL injection scanning
        test_sql_injection()
        
        # Test specific payloads
        test_specific_payload()
        
    except KeyboardInterrupt:
        print("\nTest interrupted by user.")
    except Exception as e:
        print(f"\nTest failed with error: {e}")
    
    print("\nTest completed.") 