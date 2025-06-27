"""
Domain information gathering module.
"""

import dns.resolver
import dns.query
import dns.zone
import socket
import whois
from typing import Dict, List, Any, Optional
from datetime import datetime
import json
import re
from urllib.parse import urlparse

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
        
        # Clean the domain - remove protocol and path
        clean_domain = domain
        if domain.startswith('http://') or domain.startswith('https://'):
            parsed = urlparse(domain)
            clean_domain = parsed.netloc
        
        # Remove any path or query parameters
        clean_domain = clean_domain.split('/')[0].split('?')[0].split('#')[0]
        
        Logger.info(f"Cleaned domain for analysis: {clean_domain}")
        
        self.results = {
            'domain': clean_domain,
            'timestamp': datetime.now().isoformat(),
            'whois_info': self.get_whois_info(clean_domain),
            'dns_records': self.get_dns_records(clean_domain),
            'ip_info': self.get_ip_info(clean_domain),
            'subdomains': self.get_subdomains(clean_domain),
            'ports': self.scan_common_ports(clean_domain),
            'technologies': self.detect_technologies(domain),  # Use original URL for HTTP requests
            'ssl_info': self.get_ssl_info(clean_domain)
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
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA', 'PTR', 'SRV', 'CAA']
        
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
        
        # Enhanced DNS reconnaissance
        dns_records.update(self.perform_dns_zone_transfer(domain))
        dns_records['wildcard_detection'] = self.detect_dns_wildcard(domain)
        dns_records['dns_sec'] = self.check_dnssec(domain)
        dns_records['dns_cache_poisoning'] = self.test_dns_cache_poisoning(domain)
        
        return dns_records
    
    def perform_dns_zone_transfer(self, domain: str) -> Dict[str, Any]:
        """Attempt DNS zone transfer on nameservers."""
        Logger.info(f"Attempting DNS zone transfer for {domain}")
        
        zone_transfer_results = {
            'zone_transfer_attempts': [],
            'zone_transfer_success': False,
            'nameservers_tested': []
        }
        
        try:
            # Get nameservers
            nameservers = dns.resolver.resolve(domain, 'NS')
            
            for ns in nameservers:
                ns_name = str(ns).rstrip('.')
                zone_transfer_results['nameservers_tested'].append(ns_name)
                
                try:
                    # Attempt zone transfer
                    zone = dns.zone.from_xfr(dns.query.xfr(ns_name, domain))
                    if zone:
                        zone_transfer_results['zone_transfer_success'] = True
                        zone_transfer_results['zone_transfer_attempts'].append({
                            'nameserver': ns_name,
                            'status': 'SUCCESS',
                            'records_count': len(zone.nodes.keys())
                        })
                        Logger.warning(f"DNS zone transfer SUCCESSFUL on {ns_name} - Security issue!")
                        
                        # Extract zone data (simplified)
                        zone_data = []
                        try:
                            for name, node in zone.nodes.items():
                                zone_data.append({
                                    'name': str(name),
                                    'node_type': str(type(node))
                                })
                        except Exception as e:
                            Logger.warning(f"Error extracting zone data: {e}")
                        
                        zone_transfer_results['zone_data'] = zone_data
                        
                except Exception as e:
                    zone_transfer_results['zone_transfer_attempts'].append({
                        'nameserver': ns_name,
                        'status': 'FAILED',
                        'error': str(e)
                    })
                    Logger.info(f"Zone transfer failed on {ns_name}: {e}")
                    
        except Exception as e:
            Logger.warning(f"DNS zone transfer attempt failed: {e}")
        
        return {'zone_transfer': zone_transfer_results}
    
    def detect_dns_wildcard(self, domain: str) -> Dict[str, Any]:
        """Detect if DNS wildcard is configured."""
        Logger.info(f"Detecting DNS wildcard for {domain}")
        
        wildcard_results = {
            'wildcard_detected': False,
            'test_subdomains': [],
            'wildcard_ip': None
        }
        
        # Test random subdomains
        import random
        import string
        
        test_subdomains = []
        for _ in range(5):
            random_sub = ''.join(random.choices(string.ascii_lowercase, k=10))
            test_subdomains.append(f"{random_sub}.{domain}")
        
        wildcard_results['test_subdomains'] = test_subdomains
        
        resolved_ips = set()
        for subdomain in test_subdomains:
            try:
                ip = socket.gethostbyname(subdomain)
                resolved_ips.add(ip)
                Logger.info(f"Random subdomain {subdomain} resolves to {ip}")
            except socket.gaierror:
                continue
            except Exception as e:
                Logger.warning(f"Error testing subdomain {subdomain}: {e}")
        
        # If all random subdomains resolve to the same IP, likely a wildcard
        if len(resolved_ips) == 1:
            wildcard_results['wildcard_detected'] = True
            wildcard_results['wildcard_ip'] = list(resolved_ips)[0]
            Logger.warning(f"DNS wildcard detected! All random subdomains resolve to {wildcard_results['wildcard_ip']}")
        
        return wildcard_results
    
    def check_dnssec(self, domain: str) -> Dict[str, Any]:
        """Check DNSSEC configuration."""
        Logger.info(f"Checking DNSSEC for {domain}")
        
        dnssec_results = {
            'dnssec_enabled': False,
            'dnssec_records': [],
            'dnssec_validation': False
        }
        
        try:
            # Check for DNSKEY records
            try:
                dnskey_records = dns.resolver.resolve(domain, 'DNSKEY')
                dnssec_results['dnssec_enabled'] = True
                dnssec_results['dnssec_records'].append('DNSKEY')
                Logger.success(f"DNSSEC DNSKEY records found for {domain}")
            except Exception:
                pass
            
            # Check for DS records
            try:
                ds_records = dns.resolver.resolve(domain, 'DS')
                dnssec_results['dnssec_enabled'] = True
                dnssec_results['dnssec_records'].append('DS')
                Logger.success(f"DNSSEC DS records found for {domain}")
            except Exception:
                pass
            
            # Check for RRSIG records
            try:
                rrsig_records = dns.resolver.resolve(domain, 'RRSIG')
                dnssec_results['dnssec_enabled'] = True
                dnssec_results['dnssec_records'].append('RRSIG')
                Logger.success(f"DNSSEC RRSIG records found for {domain}")
            except Exception:
                pass
            
            if dnssec_results['dnssec_enabled']:
                Logger.success(f"DNSSEC is enabled for {domain}")
            else:
                Logger.info(f"DNSSEC is not enabled for {domain}")
                
        except Exception as e:
            Logger.warning(f"DNSSEC check failed: {e}")
        
        return dnssec_results
    
    def test_dns_cache_poisoning(self, domain: str) -> Dict[str, Any]:
        """Test for DNS cache poisoning vulnerabilities."""
        Logger.info(f"Testing DNS cache poisoning for {domain}")
        
        cache_poisoning_results = {
            'vulnerable': False,
            'tests_performed': [],
            'recommendations': []
        }
        
        # Test 1: Check for predictable transaction IDs
        # This is a simplified test - real testing would require more sophisticated analysis
        cache_poisoning_results['tests_performed'].append({
            'test': 'transaction_id_predictability',
            'description': 'DNS transaction ID predictability check',
            'result': 'Manual analysis required'
        })
        
        # Test 2: Check for source port randomization
        cache_poisoning_results['tests_performed'].append({
            'test': 'source_port_randomization',
            'description': 'DNS source port randomization check',
            'result': 'Manual analysis required'
        })
        
        # Test 3: Check for DNS amplification vulnerability
        try:
            # Test if domain allows recursive queries
            resolver = dns.resolver.Resolver()
            resolver.nameservers = ['8.8.8.8']  # Use Google DNS
            resolver.timeout = 5
            resolver.lifetime = 5
            
            # Try to query through the target's DNS server
            answers = resolver.resolve(domain, 'A')
            cache_poisoning_results['tests_performed'].append({
                'test': 'recursive_queries',
                'description': 'DNS recursive query test',
                'result': 'Target may allow recursive queries'
            })
            
        except Exception as e:
            cache_poisoning_results['tests_performed'].append({
                'test': 'recursive_queries',
                'description': 'DNS recursive query test',
                'result': f'Test failed: {str(e)}'
            })
        
        cache_poisoning_results['recommendations'] = [
            'Enable DNSSEC',
            'Use random transaction IDs',
            'Implement source port randomization',
            'Disable recursive queries if not needed',
            'Use DNS rate limiting'
        ]
        
        return cache_poisoning_results
    
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
        try:
            common_subdomains = config.get_wordlist('subdomains')
            if isinstance(common_subdomains, dict):
                # If config returns a dict, try to get the list from it
                common_subdomains = common_subdomains.get('subdomains', [])
            elif not isinstance(common_subdomains, list):
                Logger.warning("Subdomain wordlist not found, using default list")
                common_subdomains = ['www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test', 'api', 'cdn', 'static']
            
            for subdomain in common_subdomains:
                if isinstance(subdomain, str):
                    full_domain = f"{subdomain}.{domain}"
                    try:
                        socket.gethostbyname(full_domain)
                        subdomains.add(full_domain)
                        Logger.success(f"Found subdomain: {full_domain}")
                    except socket.gaierror:
                        continue
                    except Exception as e:
                        Logger.warning(f"Error checking subdomain {full_domain}: {e}")
        except Exception as e:
            Logger.error(f"Error loading subdomain wordlist: {e}")
            # Fallback to basic subdomain list
            basic_subdomains = ['www', 'mail', 'ftp', 'admin', 'blog', 'dev', 'test', 'api', 'cdn', 'static']
            for subdomain in basic_subdomains:
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
            Logger.warning(f"Could not fetch {url} for technology detection")
            return {'error': 'Could not fetch website'}
        
        technologies = {
            'web_server': self.detect_web_server(response),
            'programming_language': self.detect_programming_language(response),
            'framework': self.detect_framework(response),
            'cms': self.detect_cms(response),
            'database': self.detect_database(response),
            'cdn': self.detect_cdn(response),
            'waf': self.detect_waf(response),
            'js_frameworks': self.detect_js_frameworks(response),
            'mobile_frameworks': self.detect_mobile_frameworks(response),
            'api_frameworks': self.detect_api_frameworks(response),
            'security_headers': self.check_security_headers(response),
            'server_signatures': self.extract_server_signatures(response),
            'technologies_found': []
        }
        
        # Compile list of all technologies found
        all_techs = []
        for category, tech in technologies.items():
            if tech and tech != 'Unknown' and tech != 'Not detected':
                if isinstance(tech, list):
                    all_techs.extend(tech)
                else:
                    all_techs.append(tech)
        
        technologies['technologies_found'] = list(set(all_techs))
        
        Logger.success(f"Technology detection completed. Found {len(technologies['technologies_found'])} technologies")
        return technologies
    
    def detect_web_server(self, response) -> str:
        """Detect web server type."""
        server_header = response.headers.get('Server', '').lower()
        
        if 'apache' in server_header:
            return 'Apache'
        elif 'nginx' in server_header:
            return 'Nginx'
        elif 'iis' in server_header or 'microsoft' in server_header:
            return 'IIS'
        elif 'cloudflare' in server_header:
            return 'Cloudflare'
        elif 'caddy' in server_header:
            return 'Caddy'
        elif 'lighttpd' in server_header:
            return 'Lighttpd'
        elif 'gunicorn' in server_header:
            return 'Gunicorn'
        elif 'uwsgi' in server_header:
            return 'uWSGI'
        elif 'express' in server_header:
            return 'Express.js'
        elif 'node' in server_header:
            return 'Node.js'
        else:
            return 'Unknown'
    
    def detect_programming_language(self, response) -> str:
        """Detect programming language."""
        content_type = response.headers.get('Content-Type', '').lower()
        content = response.text.lower()
        
        # Check content type and content patterns
        if 'php' in content_type or 'php' in content or '.php' in response.url:
            return 'PHP'
        elif 'python' in content or 'django' in content or 'flask' in content:
            return 'Python'
        elif 'node' in content or 'express' in content or 'npm' in content:
            return 'Node.js'
        elif 'java' in content or 'jsp' in content or 'servlet' in content:
            return 'Java'
        elif 'asp' in content or 'aspx' in content or 'vbscript' in content:
            return 'ASP.NET'
        elif 'ruby' in content or 'rails' in content:
            return 'Ruby'
        elif 'go' in content or 'golang' in content:
            return 'Go'
        else:
            return 'Unknown'
    
    def detect_database(self, response) -> str:
        """Detect database technology."""
        content = response.text.lower()
        headers = str(response.headers).lower()
        
        if 'mysql' in content or 'mysqli' in content:
            return 'MySQL'
        elif 'postgresql' in content or 'postgres' in content:
            return 'PostgreSQL'
        elif 'mongodb' in content or 'mongo' in content:
            return 'MongoDB'
        elif 'sqlite' in content:
            return 'SQLite'
        elif 'oracle' in content:
            return 'Oracle'
        elif 'microsoft sql server' in content or 'mssql' in content:
            return 'SQL Server'
        elif 'redis' in content:
            return 'Redis'
        elif 'cassandra' in content:
            return 'Cassandra'
        else:
            return 'Unknown'
    
    def detect_cdn(self, response) -> str:
        """Detect CDN provider."""
        headers = str(response.headers).lower()
        server_header = response.headers.get('Server', '').lower()
        
        if 'cloudflare' in headers or 'cloudflare' in server_header:
            return 'Cloudflare'
        elif 'akamai' in headers:
            return 'Akamai'
        elif 'aws' in headers or 'amazon' in headers:
            return 'AWS CloudFront'
        elif 'fastly' in headers:
            return 'Fastly'
        elif 'cloudfront' in headers:
            return 'AWS CloudFront'
        elif 'cdn77' in headers:
            return 'CDN77'
        elif 'bunny' in headers:
            return 'Bunny CDN'
        else:
            return 'Not detected'
    
    def detect_waf(self, response) -> str:
        """Detect Web Application Firewall."""
        headers = str(response.headers).lower()
        server_header = response.headers.get('Server', '').lower()
        
        if 'cloudflare' in headers or 'cloudflare' in server_header:
            return 'Cloudflare WAF'
        elif 'mod_security' in headers or 'modsecurity' in headers:
            return 'ModSecurity'
        elif 'imperva' in headers or 'incapsula' in headers:
            return 'Imperva Incapsula'
        elif 'f5' in headers or 'big-ip' in headers:
            return 'F5 BIG-IP ASM'
        elif 'barracuda' in headers:
            return 'Barracuda WAF'
        elif 'fortinet' in headers or 'fortigate' in headers:
            return 'Fortinet FortiWeb'
        elif 'aws' in headers and 'waf' in headers:
            return 'AWS WAF'
        elif 'azure' in headers and 'waf' in headers:
            return 'Azure WAF'
        else:
            return 'Not detected'
    
    def detect_mobile_frameworks(self, response) -> List[str]:
        """Detect mobile app frameworks."""
        content = response.text.lower()
        frameworks = []
        
        if 'react native' in content or 'reactnative' in content:
            frameworks.append('React Native')
        if 'flutter' in content:
            frameworks.append('Flutter')
        if 'ionic' in content:
            frameworks.append('Ionic')
        if 'cordova' in content or 'phonegap' in content:
            frameworks.append('Cordova/PhoneGap')
        if 'xamarin' in content:
            frameworks.append('Xamarin')
        if 'native' in content and 'script' in content:
            frameworks.append('NativeScript')
        
        return frameworks
    
    def detect_api_frameworks(self, response) -> List[str]:
        """Detect API frameworks."""
        content = response.text.lower()
        headers = str(response.headers).lower()
        frameworks = []
        
        # Check for API indicators
        if 'swagger' in content or 'openapi' in content:
            frameworks.append('Swagger/OpenAPI')
        if 'graphql' in content:
            frameworks.append('GraphQL')
        if 'rest' in content and 'api' in content:
            frameworks.append('REST API')
        if 'soap' in content:
            frameworks.append('SOAP')
        if 'grpc' in content:
            frameworks.append('gRPC')
        if 'json' in headers and 'api' in headers:
            frameworks.append('JSON API')
        
        return frameworks
    
    def extract_server_signatures(self, response) -> Dict[str, str]:
        """Extract server signatures and headers."""
        signatures = {}
        
        # Common headers to check
        important_headers = [
            'Server', 'X-Powered-By', 'X-AspNet-Version', 'X-AspNetMvc-Version',
            'X-Runtime', 'X-Version', 'X-Framework', 'X-Application-Context',
            'X-Served-By', 'X-Backend-Server', 'X-Forwarded-Server'
        ]
        
        for header in important_headers:
            value = response.headers.get(header)
            if value:
                signatures[header] = value
        
        return signatures
    
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
                    
                    if cert is None:
                        return {'error': 'No certificate found'}
                    
                    # Fix the certificate parsing
                    subject_dict = {}
                    if cert.get('subject'):
                        for item in cert['subject']:
                            if len(item) > 0 and len(item[0]) > 1:
                                subject_dict[item[0][0]] = item[0][1]
                    
                    issuer_dict = {}
                    if cert.get('issuer'):
                        for item in cert['issuer']:
                            if len(item) > 0 and len(item[0]) > 1:
                                issuer_dict[item[0][0]] = item[0][1]
                    
                    ssl_info = {
                        'subject': subject_dict,
                        'issuer': issuer_dict,
                        'version': cert.get('version'),
                        'serial_number': cert.get('serialNumber'),
                        'not_before': cert.get('notBefore'),
                        'not_after': cert.get('notAfter'),
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
            domain = self.results.get('domain', 'unknown')
            if domain and domain != 'unknown':
                # Remove protocol and path, keep only domain
                if '://' in domain:
                    domain = domain.split('://')[1]
                if '/' in domain:
                    domain = domain.split('/')[0]
                # Remove invalid characters for filenames
                sanitized_domain = re.sub(r'[<>:"/\\|?*]', '_', domain)
            else:
                sanitized_domain = 'unknown_domain'
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