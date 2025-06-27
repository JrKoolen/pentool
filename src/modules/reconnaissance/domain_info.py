"""
Domain information gathering module.
"""

import dns.resolver
import socket
import whois
from typing import Dict, List, Any, Optional
from datetime import datetime
import json
import re

from src.core.utils import Logger, HTTPClient, normalize_url, extract_domain
from src.core.config import config

class DomainInfoGatherer:
    """Domain information gathering class."""
    
    def __init__(self):
        self.http_client = HTTPClient()
        self.results = {}
    
    def gather_all(self, domain: str) -> Dict[str, Any]:
        """Gather all domain information."""
        Logger.info(f"Starting domain information gathering for: {domain}")
        
        self.results = {
            'domain': domain,
            'timestamp': datetime.now().isoformat(),
            'whois_info': self.get_whois_info(domain),
            'dns_records': self.get_dns_records(domain),
            'ip_info': self.get_ip_info(domain),
            'subdomains': self.get_subdomains(domain),
            'ports': self.scan_common_ports(domain),
            'technologies': self.detect_technologies(domain),
            'ssl_info': self.get_ssl_info(domain)
        }
        
        return self.results
    
    def get_whois_info(self, domain: str) -> Dict[str, Any]:
        """Get WHOIS information for the domain."""
        Logger.info(f"Gathering WHOIS information for {domain}")
        
        try:
            w = whois.whois(domain)
            whois_info = {
                'registrar': w.registrar,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'updated_date': str(w.updated_date) if w.updated_date else None,
                'status': w.status,
                'name_servers': w.name_servers,
                'emails': w.emails,
                'org': w.org,
                'country': w.country
            }
            
            Logger.success(f"WHOIS information retrieved for {domain}")
            return whois_info
            
        except Exception as e:
            Logger.warning(f"WHOIS lookup failed for {domain}: {e}")
            return {'error': str(e)}
    
    def get_dns_records(self, domain: str) -> Dict[str, List[str]]:
        """Get various DNS records for the domain."""
        Logger.info(f"Gathering DNS records for {domain}")
        
        dns_records = {}
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR']
        
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                dns_records[record_type] = [str(answer) for answer in answers]
                Logger.success(f"Found {len(answers)} {record_type} records")
            except dns.resolver.NXDOMAIN:
                continue
            except dns.resolver.NoAnswer:
                continue
            except Exception as e:
                Logger.warning(f"DNS {record_type} lookup failed: {e}")
        
        return dns_records
    
    def get_ip_info(self, domain: str) -> Dict[str, Any]:
        """Get IP information for the domain."""
        Logger.info(f"Gathering IP information for {domain}")
        
        try:
            # Get A records (IPv4)
            ipv4_addresses = []
            try:
                answers = dns.resolver.resolve(domain, 'A')
                ipv4_addresses = [str(answer) for answer in answers]
            except Exception:
                pass
            
            # Get AAAA records (IPv6)
            ipv6_addresses = []
            try:
                answers = dns.resolver.resolve(domain, 'AAAA')
                ipv6_addresses = [str(answer) for answer in answers]
            except Exception:
                pass
            
            # Reverse DNS lookup for first IPv4
            reverse_dns = None
            if ipv4_addresses:
                try:
                    reverse_dns = socket.gethostbyaddr(ipv4_addresses[0])[0]
                except Exception:
                    pass
            
            ip_info = {
                'ipv4_addresses': ipv4_addresses,
                'ipv6_addresses': ipv6_addresses,
                'reverse_dns': reverse_dns,
                'total_ips': len(ipv4_addresses) + len(ipv6_addresses)
            }
            
            Logger.success(f"IP information gathered: {len(ipv4_addresses)} IPv4, {len(ipv6_addresses)} IPv6")
            return ip_info
            
        except Exception as e:
            Logger.error(f"IP information gathering failed: {e}")
            return {'error': str(e)}
    
    def get_subdomains(self, domain: str) -> List[str]:
        """Get subdomains using various methods."""
        Logger.info(f"Searching for subdomains of {domain}")
        
        subdomains = set()
        
        # Method 1: Common subdomain wordlist
        common_subdomains = config.get_wordlist('subdomains')
        for subdomain in common_subdomains:
            full_domain = f"{subdomain}.{domain}"
            try:
                socket.gethostbyname(full_domain)
                subdomains.add(full_domain)
                Logger.success(f"Found subdomain: {full_domain}")
            except socket.gaierror:
                continue
            except Exception as e:
                Logger.warning(f"Error checking subdomain {full_domain}: {e}")
        
        # Method 2: Certificate Transparency logs (basic implementation)
        # This would require API access to CT logs
        Logger.info("Certificate Transparency logs check would require API integration")
        
        return list(subdomains)
    
    def scan_common_ports(self, domain: str) -> Dict[int, str]:
        """Scan common ports on the domain."""
        Logger.info(f"Scanning common ports for {domain}")
        
        # Get IP address for scanning
        try:
            ip = socket.gethostbyname(domain)
        except Exception as e:
            Logger.error(f"Could not resolve IP for {domain}: {e}")
            return {}
        
        common_ports = config.get('reconnaissance.common_ports', [80, 443, 8080, 8443])
        open_ports = {}
        
        for port in common_ports:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(3)
                result = sock.connect_ex((ip, port))
                sock.close()
                
                if result == 0:
                    service = self.get_service_name(port)
                    open_ports[port] = service
                    Logger.success(f"Open port {port} ({service}) on {domain}")
                    
            except Exception as e:
                Logger.warning(f"Port scan failed for {port}: {e}")
        
        return open_ports
    
    def get_service_name(self, port: int) -> str:
        """Get service name for common ports."""
        services = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
            80: 'HTTP', 110: 'POP3', 143: 'IMAP', 443: 'HTTPS', 993: 'IMAPS',
            995: 'POP3S', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt'
        }
        return services.get(port, 'Unknown')
    
    def detect_technologies(self, domain: str) -> Dict[str, Any]:
        """Detect technologies used by the website."""
        Logger.info(f"Detecting technologies for {domain}")
        
        url = normalize_url(domain)
        response = self.http_client.get(url)
        
        if not response:
            return {'error': 'Could not fetch website'}
        
        technologies = {
            'server': response.headers.get('Server', 'Unknown'),
            'powered_by': response.headers.get('X-Powered-By', 'Unknown'),
            'framework': self.detect_framework(response),
            'cms': self.detect_cms(response),
            'javascript_frameworks': self.detect_js_frameworks(response),
            'security_headers': self.check_security_headers(response)
        }
        
        Logger.success(f"Technology detection completed for {domain}")
        return technologies
    
    def detect_framework(self, response) -> str:
        """Detect web framework from response."""
        # Check headers
        powered_by = response.headers.get('X-Powered-By', '').lower()
        if 'php' in powered_by:
            return 'PHP'
        elif 'asp.net' in powered_by:
            return 'ASP.NET'
        elif 'express' in powered_by:
            return 'Express.js'
        
        # Check response content
        content = response.text.lower()
        if 'wordpress' in content:
            return 'WordPress'
        elif 'django' in content:
            return 'Django'
        elif 'flask' in content:
            return 'Flask'
        elif 'laravel' in content:
            return 'Laravel'
        
        return 'Unknown'
    
    def detect_cms(self, response) -> str:
        """Detect CMS from response."""
        content = response.text.lower()
        
        cms_signatures = {
            'wordpress': ['wp-content', 'wp-includes', 'wordpress'],
            'joomla': ['joomla', 'mod_', 'com_'],
            'drupal': ['drupal', 'sites/default'],
            'magento': ['magento', 'skin/frontend'],
            'shopify': ['shopify', 'cdn.shopify.com']
        }
        
        for cms, signatures in cms_signatures.items():
            if any(sig in content for sig in signatures):
                return cms.title()
        
        return 'Unknown'
    
    def detect_js_frameworks(self, response) -> List[str]:
        """Detect JavaScript frameworks."""
        content = response.text.lower()
        frameworks = []
        
        js_frameworks = {
            'React': ['react', 'reactjs'],
            'Angular': ['angular', 'ng-'],
            'Vue.js': ['vue', 'vuejs'],
            'jQuery': ['jquery'],
            'Bootstrap': ['bootstrap'],
            'Foundation': ['foundation']
        }
        
        for framework, signatures in js_frameworks.items():
            if any(sig in content for sig in signatures):
                frameworks.append(framework)
        
        return frameworks
    
    def check_security_headers(self, response) -> Dict[str, str]:
        """Check for security headers."""
        security_headers = [
            'X-Frame-Options', 'X-Content-Type-Options', 'X-XSS-Protection',
            'Strict-Transport-Security', 'Content-Security-Policy',
            'Referrer-Policy', 'Permissions-Policy'
        ]
        
        headers = {}
        for header in security_headers:
            value = response.headers.get(header)
            if value:
                headers[header] = value
        
        return headers
    
    def get_ssl_info(self, domain: str) -> Dict[str, Any]:
        """Get SSL certificate information."""
        Logger.info(f"Gathering SSL information for {domain}")
        
        try:
            import ssl
            import socket
            
            context = ssl.create_default_context()
            with socket.create_connection((domain, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert()
                    
                    ssl_info = {
                        'subject': dict(x[0] for x in cert['subject']),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'version': cert['version'],
                        'serial_number': cert['serialNumber'],
                        'not_before': cert['notBefore'],
                        'not_after': cert['notAfter'],
                        'san': cert.get('subjectAltName', [])
                    }
                    
                    Logger.success(f"SSL information retrieved for {domain}")
                    return ssl_info
                    
        except Exception as e:
            Logger.warning(f"SSL information gathering failed: {e}")
            return {'error': str(e)}
    
    def save_results(self, filename: str = None):
        """Save results to file."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            # Sanitize domain name for filename
            domain = self.results['domain']
            # Remove protocol and path, keep only domain
            if '://' in domain:
                domain = domain.split('://')[1]
            if '/' in domain:
                domain = domain.split('/')[0]
            # Remove invalid characters for filenames
            sanitized_domain = re.sub(r'[<>:"/\\|?*]', '_', domain)
            filename = f"domain_info_{sanitized_domain}_{timestamp}.json"
        
        import os
        os.makedirs('results', exist_ok=True)
        filepath = os.path.join('results', filename)
        
        with open(filepath, 'w') as f:
            json.dump(self.results, f, indent=4, default=str)
        
        Logger.success(f"Domain information saved to {filepath}")
        return filepath

def main():
    """Main function for testing."""
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python domain_info.py <domain>")
        sys.exit(1)
    
    domain = sys.argv[1]
    gatherer = DomainInfoGatherer()
    results = gatherer.gather_all(domain)
    gatherer.save_results()
    
    print("\n=== Domain Information Summary ===")
    print(f"Domain: {results['domain']}")
    print(f"IP Addresses: {results['ip_info'].get('ipv4_addresses', [])}")
    print(f"Open Ports: {list(results['ports'].keys())}")
    print(f"Technologies: {results['technologies']}")

if __name__ == "__main__":
    main() 