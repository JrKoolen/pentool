"""
Security headers analysis module.
"""

import requests
from typing import Dict, List, Any, Optional
from datetime import datetime
import re

from src.core.utils import Logger, HTTPClient, normalize_url
from src.core.config import config

class SecurityHeadersAnalyzer:
    """Comprehensive security headers analyzer."""
    
    def __init__(self):
        self.http_client = HTTPClient()
        self.results = {}
        
        # Define security headers and their expected values
        self.security_headers = {
            'Strict-Transport-Security': {
                'description': 'Enforces HTTPS connections',
                'recommended_value': 'max-age=31536000; includeSubDomains',
                'severity': 'High'
            },
            'Content-Security-Policy': {
                'description': 'Prevents XSS and other injection attacks',
                'recommended_value': "default-src 'self'; script-src 'self' 'unsafe-inline' 'unsafe-eval'; style-src 'self' 'unsafe-inline';",
                'severity': 'High'
            },
            'X-Frame-Options': {
                'description': 'Prevents clickjacking attacks',
                'recommended_value': 'DENY',
                'severity': 'Medium'
            },
            'X-Content-Type-Options': {
                'description': 'Prevents MIME type sniffing',
                'recommended_value': 'nosniff',
                'severity': 'Medium'
            },
            'X-XSS-Protection': {
                'description': 'Enables browser XSS protection',
                'recommended_value': '1; mode=block',
                'severity': 'Low'
            },
            'Referrer-Policy': {
                'description': 'Controls referrer information',
                'recommended_value': 'strict-origin-when-cross-origin',
                'severity': 'Low'
            },
            'Permissions-Policy': {
                'description': 'Controls browser features and APIs',
                'recommended_value': 'geolocation=(), microphone=(), camera=()',
                'severity': 'Medium'
            },
            'Cross-Origin-Embedder-Policy': {
                'description': 'Prevents cross-origin resource loading',
                'recommended_value': 'require-corp',
                'severity': 'Medium'
            },
            'Cross-Origin-Opener-Policy': {
                'description': 'Isolates browsing context',
                'recommended_value': 'same-origin',
                'severity': 'Medium'
            },
            'Cross-Origin-Resource-Policy': {
                'description': 'Controls cross-origin resource access',
                'recommended_value': 'same-origin',
                'severity': 'Medium'
            }
        }
    
    def analyze_target(self, target: str) -> Dict[str, Any]:
        """Analyze security headers for a target."""
        Logger.info(f"Analyzing security headers for {target}")
        
        url = normalize_url(target)
        
        self.results = {
            'target': target,
            'url': url,
            'timestamp': datetime.now().isoformat(),
            'headers_analysis': {},
            'security_score': 0,
            'recommendations': [],
            'vulnerabilities': []
        }
        
        # Get HTTP response
        response = self.http_client.get(url)
        if not response:
            Logger.error(f"Could not fetch {url}")
            return {'error': 'Could not fetch target'}
        
        # Analyze each security header
        total_headers = len(self.security_headers)
        present_headers = 0
        
        for header_name, header_info in self.security_headers.items():
            header_value = response.headers.get(header_name)
            
            analysis = {
                'present': bool(header_value),
                'value': header_value,
                'description': header_info['description'],
                'recommended_value': header_info['recommended_value'],
                'severity': header_info['severity'],
                'score': 0,
                'issues': []
            }
            
            if header_value:
                present_headers += 1
                analysis['score'] = self._evaluate_header(header_name, header_value, analysis)
            else:
                analysis['issues'].append(f"Missing {header_name} header")
                analysis['score'] = 0
            
            self.results['headers_analysis'][header_name] = analysis
        
        # Calculate overall security score
        self.results['security_score'] = round((present_headers / total_headers) * 100, 2)
        
        # Generate recommendations
        self.results['recommendations'] = self._generate_recommendations()
        
        # Identify vulnerabilities
        self.results['vulnerabilities'] = self._identify_vulnerabilities()
        
        Logger.success(f"Security headers analysis completed. Score: {self.results['security_score']}%")
        return self.results
    
    def _evaluate_header(self, header_name: str, header_value: str, analysis: Dict) -> int:
        """Evaluate the quality of a security header."""
        score = 0
        
        if header_name == 'Strict-Transport-Security':
            score = self._evaluate_hsts(header_value, analysis)
        elif header_name == 'Content-Security-Policy':
            score = self._evaluate_csp(header_value, analysis)
        elif header_name == 'X-Frame-Options':
            score = self._evaluate_xfo(header_value, analysis)
        elif header_name == 'X-Content-Type-Options':
            score = self._evaluate_xcto(header_value, analysis)
        elif header_name == 'X-XSS-Protection':
            score = self._evaluate_xxp(header_value, analysis)
        elif header_name == 'Referrer-Policy':
            score = self._evaluate_referrer_policy(header_value, analysis)
        elif header_name == 'Permissions-Policy':
            score = self._evaluate_permissions_policy(header_value, analysis)
        else:
            # Generic evaluation
            if header_value and header_value.strip():
                score = 80  # Basic score for presence
            else:
                score = 0
        
        return score
    
    def _evaluate_hsts(self, value: str, analysis: Dict) -> int:
        """Evaluate HSTS header."""
        score = 0
        
        # Check for max-age
        max_age_match = re.search(r'max-age=(\d+)', value, re.IGNORECASE)
        if max_age_match:
            max_age = int(max_age_match.group(1))
            if max_age >= 31536000:  # 1 year
                score += 40
            elif max_age >= 86400:  # 1 day
                score += 20
        
        # Check for includeSubDomains
        if 'includesubdomains' in value.lower():
            score += 30
        
        # Check for preload
        if 'preload' in value.lower():
            score += 30
        
        analysis['issues'] = []
        if score < 40:
            analysis['issues'].append("HSTS max-age should be at least 1 year")
        if 'includesubdomains' not in value.lower():
            analysis['issues'].append("Consider adding includeSubDomains directive")
        
        return min(score, 100)
    
    def _evaluate_csp(self, value: str, analysis: Dict) -> int:
        """Evaluate Content Security Policy header."""
        score = 0
        issues = []
        
        # Check for default-src
        if 'default-src' in value.lower():
            score += 20
        else:
            issues.append("Missing default-src directive")
        
        # Check for script-src
        if 'script-src' in value.lower():
            score += 20
        else:
            issues.append("Missing script-src directive")
        
        # Check for unsafe-inline in script-src
        if "'unsafe-inline'" in value.lower():
            issues.append("script-src contains unsafe-inline (security risk)")
            score -= 10
        
        # Check for unsafe-eval in script-src
        if "'unsafe-eval'" in value.lower():
            issues.append("script-src contains unsafe-eval (security risk)")
            score -= 10
        
        # Check for style-src
        if 'style-src' in value.lower():
            score += 15
        else:
            issues.append("Missing style-src directive")
        
        # Check for object-src
        if 'object-src' in value.lower():
            score += 15
        else:
            issues.append("Missing object-src directive")
        
        # Check for base-uri
        if 'base-uri' in value.lower():
            score += 10
        else:
            issues.append("Missing base-uri directive")
        
        # Check for frame-ancestors
        if 'frame-ancestors' in value.lower():
            score += 10
        else:
            issues.append("Missing frame-ancestors directive")
        
        analysis['issues'] = issues
        return max(score, 0)
    
    def _evaluate_xfo(self, value: str, analysis: Dict) -> int:
        """Evaluate X-Frame-Options header."""
        value_lower = value.lower()
        
        if value_lower == 'deny':
            return 100
        elif value_lower == 'sameorigin':
            return 80
        elif value_lower.startswith('allow-from'):
            return 40
        else:
            analysis['issues'].append("Invalid X-Frame-Options value")
            return 0
    
    def _evaluate_xcto(self, value: str, analysis: Dict) -> int:
        """Evaluate X-Content-Type-Options header."""
        if value.lower() == 'nosniff':
            return 100
        else:
            analysis['issues'].append("X-Content-Type-Options should be 'nosniff'")
            return 0
    
    def _evaluate_xxp(self, value: str, analysis: Dict) -> int:
        """Evaluate X-XSS-Protection header."""
        value_lower = value.lower()
        
        if '1; mode=block' in value_lower:
            return 100
        elif '1' in value_lower:
            return 60
        else:
            analysis['issues'].append("X-XSS-Protection should be '1; mode=block'")
            return 0
    
    def _evaluate_referrer_policy(self, value: str, analysis: Dict) -> int:
        """Evaluate Referrer-Policy header."""
        value_lower = value.lower()
        
        if value_lower == 'strict-origin-when-cross-origin':
            return 100
        elif value_lower == 'strict-origin':
            return 90
        elif value_lower == 'origin-when-cross-origin':
            return 70
        elif value_lower == 'no-referrer':
            return 60
        else:
            analysis['issues'].append("Consider using 'strict-origin-when-cross-origin'")
            return 50
    
    def _evaluate_permissions_policy(self, value: str, analysis: Dict) -> int:
        """Evaluate Permissions-Policy header."""
        score = 0
        issues = []
        
        # Check for common permissions
        permissions = ['geolocation', 'microphone', 'camera', 'payment', 'usb']
        for permission in permissions:
            if permission in value.lower():
                score += 20
            else:
                issues.append(f"Consider restricting {permission} permission")
        
        analysis['issues'] = issues
        return min(score, 100)
    
    def _generate_recommendations(self) -> List[str]:
        """Generate security recommendations."""
        recommendations = []
        
        for header_name, analysis in self.results['headers_analysis'].items():
            if not analysis['present']:
                recommendations.append(f"Add {header_name} header: {analysis['recommended_value']}")
            elif analysis['score'] < 80:
                recommendations.append(f"Improve {header_name} header: {analysis['recommended_value']}")
        
        # Add general recommendations
        if self.results['security_score'] < 70:
            recommendations.append("Overall security headers need significant improvement")
        elif self.results['security_score'] < 90:
            recommendations.append("Security headers are good but can be improved")
        else:
            recommendations.append("Security headers are well configured")
        
        return recommendations
    
    def _identify_vulnerabilities(self) -> List[Dict[str, Any]]:
        """Identify security vulnerabilities."""
        vulnerabilities = []
        
        for header_name, analysis in self.results['headers_analysis'].items():
            if not analysis['present']:
                vulnerabilities.append({
                    'type': 'Missing Security Header',
                    'header': header_name,
                    'severity': analysis['severity'],
                    'description': f"Missing {header_name} header",
                    'impact': analysis['description'],
                    'recommendation': f"Add {header_name}: {analysis['recommended_value']}"
                })
            elif analysis['score'] < 50:
                vulnerabilities.append({
                    'type': 'Weak Security Header',
                    'header': header_name,
                    'severity': analysis['severity'],
                    'description': f"Weak {header_name} configuration",
                    'impact': f"Current value: {analysis['value']}",
                    'recommendation': f"Improve to: {analysis['recommended_value']}"
                })
        
        return vulnerabilities
    
    def save_results(self, filename: str = None) -> str:
        """Save analysis results to file."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"security_headers_{self.results.get('target', 'unknown')}_{timestamp}.json"
        
        import json
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        Logger.success(f"Security headers analysis saved to {filename}")
        return filename

def main():
    """Main function for testing."""
    analyzer = SecurityHeadersAnalyzer()
    
    # Example usage
    target = "https://example.com"
    results = analyzer.analyze_target(target)
    
    print(f"Security Headers Analysis for {target}")
    print(f"Overall Score: {results['security_score']}%")
    print("\nHeaders Analysis:")
    for header, analysis in results['headers_analysis'].items():
        status = "✓" if analysis['present'] else "✗"
        print(f"  {status} {header}: {analysis.get('value', 'Not present')}")
    
    print("\nRecommendations:")
    for rec in results['recommendations']:
        print(f"  - {rec}")
    
    # Save results
    analyzer.save_results()

if __name__ == "__main__":
    main() 