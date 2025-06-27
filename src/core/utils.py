"""
Utility functions for the penetration testing tool.
"""

import requests
import socket
import dns.resolver
import whois
import time
import random
from typing import Dict, List, Optional, Tuple, Any
from urllib.parse import urljoin, urlparse
import logging
from colorama import Fore, Style, init
import threading
from concurrent.futures import ThreadPoolExecutor, as_completed

# Initialize colorama for cross-platform colored output
init(autoreset=True)

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('pentest_tool.log'),
        logging.StreamHandler()
    ]
)

class HTTPClient:
    """HTTP client with custom headers and session management."""
    
    def __init__(self, timeout: int = 10, verify_ssl: bool = False):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        })
        self.timeout = timeout
        self.verify_ssl = verify_ssl
        
    def get(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make GET request with error handling."""
        try:
            response = self.session.get(
                url, 
                timeout=self.timeout, 
                verify=self.verify_ssl,
                allow_redirects=True,
                **kwargs
            )
            return response
        except requests.exceptions.RequestException as e:
            logging.warning(f"Request failed for {url}: {e}")
            return None
    
    def head(self, url: str, **kwargs) -> Optional[requests.Response]:
        """Make HEAD request with error handling."""
        try:
            response = self.session.head(
                url, 
                timeout=self.timeout, 
                verify=self.verify_ssl,
                allow_redirects=True,
                **kwargs
            )
            return response
        except requests.exceptions.RequestException as e:
            logging.warning(f"HEAD request failed for {url}: {e}")
            return None

class Logger:
    """Custom logger with colored output."""
    
    @staticmethod
    def info(message: str):
        """Log info message."""
        print(f"{Fore.BLUE}[INFO]{Style.RESET_ALL} {message}")
        logging.info(message)
    
    @staticmethod
    def success(message: str):
        """Log success message."""
        print(f"{Fore.GREEN}[SUCCESS]{Style.RESET_ALL} {message}")
        logging.info(f"SUCCESS: {message}")
    
    @staticmethod
    def warning(message: str):
        """Log warning message."""
        print(f"{Fore.YELLOW}[WARNING]{Style.RESET_ALL} {message}")
        logging.warning(message)
    
    @staticmethod
    def error(message: str):
        """Log error message."""
        print(f"{Fore.RED}[ERROR]{Style.RESET_ALL} {message}")
        logging.error(message)
    
    @staticmethod
    def critical(message: str):
        """Log critical message."""
        print(f"{Fore.RED}{Style.BRIGHT}[CRITICAL]{Style.RESET_ALL} {message}")
        logging.critical(message)

def get_domain_info(domain: str) -> Dict[str, Any]:
    """Get comprehensive domain information."""
    info = {
        'domain': domain,
        'whois': None,
        'dns_records': {},
        'ip_addresses': [],
        'nameservers': []
    }
    
    try:
        # WHOIS information
        w = whois.whois(domain)
        info['whois'] = {
            'registrar': w.registrar,
            'creation_date': w.creation_date,
            'expiration_date': w.expiration_date,
            'status': w.status
        }
    except Exception as e:
        Logger.warning(f"WHOIS lookup failed for {domain}: {e}")
    
    try:
        # DNS records
        record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'CNAME', 'SOA']
        for record_type in record_types:
            try:
                answers = dns.resolver.resolve(domain, record_type)
                info['dns_records'][record_type] = [str(answer) for answer in answers]
            except dns.resolver.NXDOMAIN:
                continue
            except Exception as e:
                Logger.warning(f"DNS {record_type} lookup failed: {e}")
        
        # Get IP addresses
        try:
            answers = dns.resolver.resolve(domain, 'A')
            info['ip_addresses'] = [str(answer) for answer in answers]
        except Exception as e:
            Logger.warning(f"IP resolution failed: {e}")
        
        # Get nameservers
        try:
            answers = dns.resolver.resolve(domain, 'NS')
            info['nameservers'] = [str(answer) for answer in answers]
        except Exception as e:
            Logger.warning(f"Nameserver lookup failed: {e}")
            
    except Exception as e:
        Logger.error(f"DNS resolution failed for {domain}: {e}")
    
    return info

def is_port_open(host: str, port: int, timeout: int = 3) -> bool:
    """Check if a port is open on the target host."""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return result == 0
    except Exception as e:
        Logger.warning(f"Port scan failed for {host}:{port}: {e}")
        return False

def scan_ports(host: str, ports: List[int], max_threads: int = 50) -> List[int]:
    """Scan multiple ports concurrently."""
    open_ports = []
    
    def scan_port(port):
        if is_port_open(host, port):
            return port
        return None
    
    with ThreadPoolExecutor(max_workers=max_threads) as executor:
        future_to_port = {executor.submit(scan_port, port): port for port in ports}
        
        for future in as_completed(future_to_port):
            port = future.result()
            if port:
                open_ports.append(port)
                Logger.success(f"Open port found: {host}:{port}")
    
    return sorted(open_ports)

def normalize_url(url: str) -> str:
    """Normalize URL by adding protocol if missing."""
    if not url.startswith(('http://', 'https://')):
        url = 'https://' + url
    return url

def extract_domain(url: str) -> str:
    """Extract domain from URL."""
    parsed = urlparse(normalize_url(url))
    return parsed.netloc

def get_common_ports() -> List[int]:
    """Get list of common ports to scan."""
    return [
        21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995,  # Standard services
        8080, 8443, 3000, 8000, 8888, 9000,  # Web services
        3306, 5432, 6379, 27017,  # Databases
        22, 23, 3389, 5900  # Remote access
    ]

def random_delay(min_delay: float = 0.1, max_delay: float = 0.5):
    """Add random delay to avoid rate limiting."""
    time.sleep(random.uniform(min_delay, max_delay))

def save_results(filename: str, data: Any, format: str = 'json'):
    """Save results to file."""
    import json
    import os
    
    os.makedirs('results', exist_ok=True)
    filepath = os.path.join('results', filename)
    
    if format == 'json':
        with open(filepath, 'w') as f:
            json.dump(data, f, indent=4, default=str)
    elif format == 'txt':
        with open(filepath, 'w') as f:
            if isinstance(data, dict):
                for key, value in data.items():
                    f.write(f"{key}: {value}\n")
            else:
                f.write(str(data))
    
    Logger.success(f"Results saved to {filepath}")

def load_wordlist(filepath: str) -> List[str]:
    """Load wordlist from file."""
    try:
        with open(filepath, 'r') as f:
            return [line.strip() for line in f if line.strip() and not line.startswith('#')]
    except FileNotFoundError:
        Logger.warning(f"Wordlist file not found: {filepath}")
        return []
    except Exception as e:
        Logger.error(f"Error loading wordlist {filepath}: {e}")
        return []

def is_valid_domain(domain: str) -> bool:
    """Validate domain format."""
    import re
    pattern = r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$'
    return bool(re.match(pattern, domain)) 