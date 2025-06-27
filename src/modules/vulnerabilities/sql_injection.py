"""
SQL Injection vulnerability scanner module.
"""

import time
import re
import random
import string
from typing import Dict, List, Any, Optional, Tuple
from urllib.parse import urljoin, urlparse, parse_qs, urlencode, urlunparse
import requests

from src.core.utils import Logger, HTTPClient, normalize_url, random_delay
from src.core.config import config

class SQLInjectionScanner:
    """SQL Injection vulnerability scanner."""
    
    def __init__(self):
        self.http_client = HTTPClient()
        self.results = {
            'vulnerabilities': [],
            'tested_parameters': [],
            'summary': {
                'total_tested': 0,
                'vulnerable_parameters': 0,
                'injection_types': []
            }
        }
        self.vulnerable_params = []
    
    def scan_url(self, url: str, forms: List[Dict] = None) -> Dict[str, Any]:
        """Scan a URL for SQL injection vulnerabilities."""
        Logger.info(f"Starting SQL injection scan for: {url}")
        
        # Parse URL to get parameters
        parsed_url = urlparse(url)
        params = parse_qs(parsed_url.query)
        
        # Test URL parameters
        if params:
            Logger.info(f"Testing {len(params)} URL parameters")
            for param_name, param_values in params.items():
                for param_value in param_values:
                    self.test_parameter(url, param_name, param_value, 'url')
        
        # Test forms if provided
        if forms:
            Logger.info(f"Testing {len(forms)} forms")
            for form in forms:
                self.test_form(url, form)
        
        # Generate summary
        self.generate_summary()
        
        Logger.success(f"SQL injection scan completed. Found {len(self.vulnerable_params)} vulnerable parameters")
        return self.results
    
    def test_parameter(self, url: str, param_name: str, param_value: str, param_type: str):
        """Test a single parameter for SQL injection vulnerabilities."""
        self.results['summary']['total_tested'] += 1
        
        # Test different injection types
        injection_types = [
            ('boolean', self.test_boolean_injection),
            ('error', self.test_error_injection),
            ('time', self.test_time_injection),
            ('union', self.test_union_injection)
        ]
        
        for injection_type, test_func in injection_types:
            try:
                is_vulnerable, payload, response = test_func(url, param_name, param_value)
                
                if is_vulnerable:
                    vulnerability = {
                        'parameter': param_name,
                        'parameter_type': param_type,
                        'injection_type': injection_type,
                        'payload': payload,
                        'evidence': response,
                        'severity': self.get_severity(injection_type),
                        'url': url
                    }
                    
                    self.results['vulnerabilities'].append(vulnerability)
                    self.vulnerable_params.append(param_name)
                    
                    Logger.warning(f"SQL Injection found: {param_name} ({injection_type})")
                    break  # Found vulnerability, no need to test other types
                
                random_delay(0.1, 0.3)  # Be respectful
                
            except Exception as e:
                Logger.warning(f"Error testing {param_name} for {injection_type}: {e}")
    
    def test_boolean_injection(self, url: str, param_name: str, param_value: str) -> Tuple[bool, str, str]:
        """Test for boolean-based SQL injection."""
        # Boolean-based payloads
        payloads = [
            "' AND 1=1--",
            "' AND 1=2--",
            "' OR 1=1--",
            "' OR 1=2--",
            "') AND 1=1--",
            "') AND 1=2--"
        ]
        
        # Get baseline response
        baseline_response = self.http_client.get(url)
        if not baseline_response:
            return False, "", ""
        
        baseline_content = baseline_response.text
        baseline_length = len(baseline_content)
        
        for payload in payloads:
            # Create test URL with payload
            test_url = self.inject_payload(url, param_name, payload)
            
            # Send request
            response = self.http_client.get(test_url)
            if not response:
                continue
            
            test_content = response.text
            test_length = len(test_content)
            
            # Check for significant differences
            if abs(test_length - baseline_length) > 100:  # Significant difference
                return True, payload, f"Content length changed: {baseline_length} -> {test_length}"
            
            # Check for specific SQL error messages
            if self.detect_sql_errors(test_content):
                return True, payload, f"SQL error detected in response"
        
        return False, "", ""
    
    def test_error_injection(self, url: str, param_name: str, param_value: str) -> Tuple[bool, str, str]:
        """Test for error-based SQL injection."""
        # Error-based payloads
        payloads = [
            "'",
            "''",
            "`",
            "``",
            ",",
            "\"",
            "\\",
            "%27",
            "%25%27",
            "%60",
            "%5C"
        ]
        
        for payload in payloads:
            # Create test URL with payload
            test_url = self.inject_payload(url, param_name, payload)
            
            # Send request
            response = self.http_client.get(test_url)
            if not response:
                continue
            
            content = response.text
            
            # Check for SQL error messages
            if self.detect_sql_errors(content):
                return True, payload, f"SQL error: {self.extract_sql_error(content)}"
        
        return False, "", ""
    
    def test_time_injection(self, url: str, param_name: str, param_value: str) -> Tuple[bool, str, str]:
        """Test for time-based SQL injection."""
        # Time-based payloads
        payloads = [
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "' WAITFOR DELAY '00:00:05'--",
            "' AND 1=(SELECT COUNT(*) FROM tabname); WAITFOR DELAY '00:00:05'--",
            "' AND (SELECT COUNT(*) FROM generate_series(1,5000000))--"
        ]
        
        for payload in payloads:
            # Create test URL with payload
            test_url = self.inject_payload(url, param_name, payload)
            
            # Measure response time
            start_time = time.time()
            response = self.http_client.get(test_url)
            end_time = time.time()
            
            if not response:
                continue
            
            response_time = end_time - start_time
            
            # Check if response time indicates successful injection
            if response_time > 4:  # More than 4 seconds
                return True, payload, f"Delayed response: {response_time:.2f} seconds"
        
        return False, "", ""
    
    def test_union_injection(self, url: str, param_name: str, param_value: str) -> Tuple[bool, str, str]:
        """Test for union-based SQL injection."""
        # Union-based payloads
        payloads = [
            "' UNION SELECT NULL--",
            "' UNION SELECT NULL,NULL--",
            "' UNION SELECT NULL,NULL,NULL--",
            "' UNION SELECT 1--",
            "' UNION SELECT 1,2--",
            "' UNION SELECT 1,2,3--",
            "' UNION SELECT 'a'--",
            "' UNION SELECT 'a','b'--"
        ]
        
        # Get baseline response
        baseline_response = self.http_client.get(url)
        if not baseline_response:
            return False, "", ""
        
        baseline_content = baseline_response.text
        
        for payload in payloads:
            # Create test URL with payload
            test_url = self.inject_payload(url, param_name, payload)
            
            # Send request
            response = self.http_client.get(test_url)
            if not response:
                continue
            
            test_content = response.text
            
            # Check for union injection indicators
            if self.detect_union_injection(test_content, baseline_content):
                return True, payload, f"Union injection detected"
        
        return False, "", ""
    
    def test_form(self, url: str, form: Dict):
        """Test a form for SQL injection vulnerabilities."""
        form_url = form.get('action', url)
        method = form.get('method', 'GET').upper()
        inputs = form.get('inputs', [])
        
        for input_field in inputs:
            if input_field.get('type') in ['text', 'search', 'email', 'password']:
                param_name = input_field.get('name', '')
                if param_name:
                    self.test_parameter(form_url, param_name, '', 'form')
    
    def inject_payload(self, url: str, param_name: str, payload: str) -> str:
        """Inject a payload into a URL parameter."""
        parsed = urlparse(url)
        params = parse_qs(parsed.query)
        
        # Replace the parameter value with payload
        params[param_name] = [payload]
        
        # Rebuild URL
        new_query = urlencode(params, doseq=True)
        new_url = urlunparse((
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            parsed.params,
            new_query,
            parsed.fragment
        ))
        
        return new_url
    
    def detect_sql_errors(self, content: str) -> bool:
        """Detect SQL error messages in response content."""
        sql_error_patterns = [
            r'sql syntax.*mysql',
            r'warning.*mysql',
            r'mysql.*error',
            r'valid mysql result',
            r'check the manual that corresponds to your (mysql|mariadb) server version',
            r'unknown column',
            r'incorrect syntax',
            r'unclosed quotation mark after the character string',
            r'quoted string not properly terminated',
            r'oracle.*error',
            r'oracle.*exception',
            r'microsoft.*database.*error',
            r'odbc.*error',
            r'jdbc.*error',
            r'postgresql.*error',
            r'postgres.*error',
            r'ora-[0-9][0-9][0-9][0-9]',
            r'oracle.*ora-[0-9][0-9][0-9][0-9]',
            r'microsoft.*database.*engine.*error',
            r'microsoft.*ole.*db.*provider.*error',
            r'microsoft.*odbc.*driver.*error',
            r'access.*database.*engine.*error',
            r'jdbc:oracle:thin.*error',
            r'jdbc:mysql.*error',
            r'jdbc:postgresql.*error',
            r'jdbc:sqlserver.*error',
            r'jdbc:db2.*error',
            r'jdbc:sybase.*error',
            r'jdbc:informix.*error',
            r'jdbc:ingres.*error',
            r'jdbc:hsqldb.*error',
            r'jdbc:h2.*error',
            r'jdbc:derby.*error',
            r'jdbc:sqlite.*error',
            r'jdbc:firebird.*error',
            r'jdbc:maxdb.*error',
            r'jdbc:sapdb.*error',
            r'jdbc:interbase.*error',
            r'jdbc:pointbase.*error',
            r'jdbc:frontbase.*error',
            r'jdbc:db2j.*error',
            r'jdbc:db2jcc.*error',
            r'jdbc:db2jcc4.*error',
            r'jdbc:db2jcc2.*error',
            r'jdbc:db2jcc1.*error',
            r'jdbc:db2jcc0.*error',
            r'jdbc:db2jcc3.*error',
            r'jdbc:db2jcc5.*error',
            r'jdbc:db2jcc6.*error',
            r'jdbc:db2jcc7.*error',
            r'jdbc:db2jcc8.*error',
            r'jdbc:db2jcc9.*error',
            r'jdbc:db2jcc10.*error',
            r'jdbc:db2jcc11.*error',
            r'jdbc:db2jcc12.*error',
            r'jdbc:db2jcc13.*error',
            r'jdbc:db2jcc14.*error',
            r'jdbc:db2jcc15.*error',
            r'jdbc:db2jcc16.*error',
            r'jdbc:db2jcc17.*error',
            r'jdbc:db2jcc18.*error',
            r'jdbc:db2jcc19.*error',
            r'jdbc:db2jcc20.*error'
        ]
        
        content_lower = content.lower()
        for pattern in sql_error_patterns:
            if re.search(pattern, content_lower, re.IGNORECASE):
                return True
        
        return False
    
    def extract_sql_error(self, content: str) -> str:
        """Extract SQL error message from response."""
        # Look for common error patterns
        error_patterns = [
            r'error.*sql.*syntax',
            r'mysql.*error.*\d+',
            r'oracle.*error.*\d+',
            r'sql.*syntax.*error',
            r'incorrect.*syntax'
        ]
        
        for pattern in error_patterns:
            match = re.search(pattern, content, re.IGNORECASE)
            if match:
                return match.group(0)
        
        return "SQL error detected"
    
    def detect_union_injection(self, test_content: str, baseline_content: str) -> bool:
        """Detect union-based SQL injection."""
        # Check for significant content differences
        if len(test_content) > len(baseline_content) * 1.5:
            return True
        
        # Check for union injection indicators
        union_indicators = [
            'union select',
            'union all select',
            'null,null',
            '1,2,3',
            'a,b,c'
        ]
        
        test_content_lower = test_content.lower()
        for indicator in union_indicators:
            if indicator in test_content_lower:
                return True
        
        return False
    
    def get_severity(self, injection_type: str) -> str:
        """Get severity level for injection type."""
        severity_map = {
            'boolean': 'medium',
            'error': 'high',
            'time': 'high',
            'union': 'critical'
        }
        return severity_map.get(injection_type, 'medium')
    
    def generate_summary(self):
        """Generate scan summary."""
        summary = self.results['summary']
        summary['vulnerable_parameters'] = len(self.vulnerable_params)
        summary['injection_types'] = list(set([v['injection_type'] for v in self.results['vulnerabilities']]))
    
    def save_results(self, filename: str = None):
        """Save scan results to file."""
        if not filename:
            from datetime import datetime
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"sql_injection_scan_{timestamp}.json"
        
        import os
        import json
        
        os.makedirs('results', exist_ok=True)
        filepath = os.path.join('results', filename)
        
        with open(filepath, 'w') as f:
            json.dump(self.results, f, indent=4, default=str)
        
        Logger.success(f"SQL injection results saved to {filepath}")
        return filepath 