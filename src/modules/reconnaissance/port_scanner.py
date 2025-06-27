"""
Port scanning module for network reconnaissance.
"""

import socket
import threading
import time
from typing import Dict, List, Any, Optional
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

from src.core.utils import Logger
from src.core.config import config

class PortScanner:
    """Advanced port scanner for network reconnaissance."""
    
    def __init__(self):
        self.results = {}
        self.common_ports = {
            # Web Services
            80: 'HTTP', 443: 'HTTPS', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
            3000: 'Node.js', 8000: 'Django', 5000: 'Flask',
            
            # Database Services
            3306: 'MySQL', 5432: 'PostgreSQL', 27017: 'MongoDB',
            6379: 'Redis', 1521: 'Oracle', 1433: 'SQL Server',
            
            # Mail Services
            25: 'SMTP', 587: 'SMTP-Submission', 465: 'SMTPS',
            110: 'POP3', 995: 'POP3S', 143: 'IMAP', 993: 'IMAPS',
            
            # File Transfer
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 69: 'TFTP',
            
            # DNS & Network
            53: 'DNS', 67: 'DHCP', 123: 'NTP', 161: 'SNMP',
            
            # Remote Access
            3389: 'RDP', 5900: 'VNC', 5901: 'VNC-1', 5902: 'VNC-2',
            
            # Development & Debug
            9000: 'Jenkins', 8081: 'Development', 3001: 'Development',
            5001: 'Development', 8001: 'Development',
            
            # Cloud & Container
            2375: 'Docker', 2376: 'Docker-TLS', 5000: 'Docker-Registry',
            6443: 'Kubernetes', 10250: 'Kubernetes-Kubelet',
            
            # Monitoring & Management
            9090: 'Prometheus', 9100: 'Node-Exporter', 3000: 'Grafana',
            5601: 'Kibana', 9200: 'Elasticsearch', 9300: 'Elasticsearch-Cluster'
        }
    
    def scan_target(self, target: str, port_range: Optional[List[int]] = None, 
                   timeout: int = 3, max_workers: int = 50) -> Dict[str, Any]:
        """Scan a target for open ports."""
        Logger.info(f"Starting port scan for {target}")
        
        if not port_range:
            port_range = list(self.common_ports.keys())
        
        self.results = {
            'target': target,
            'timestamp': datetime.now().isoformat(),
            'scan_config': {
                'ports_scanned': len(port_range),
                'timeout': timeout,
                'max_workers': max_workers
            },
            'open_ports': {},
            'scan_summary': {}
        }
        
        # Resolve target to IP
        try:
            ip = socket.gethostbyname(target)
            Logger.info(f"Resolved {target} to {ip}")
        except socket.gaierror as e:
            Logger.error(f"Could not resolve {target}: {e}")
            return {'error': f'Could not resolve {target}'}
        
        # Perform port scan
        start_time = time.time()
        open_ports = self._scan_ports(ip, port_range, timeout, max_workers)
        scan_time = time.time() - start_time
        
        # Process results
        self.results['open_ports'] = open_ports
        self.results['scan_summary'] = {
            'total_ports_scanned': len(port_range),
            'open_ports_found': len(open_ports),
            'scan_duration': round(scan_time, 2),
            'ports_per_second': round(len(port_range) / scan_time, 2)
        }
        
        Logger.success(f"Port scan completed: {len(open_ports)} open ports found")
        return self.results
    
    def _scan_ports(self, ip: str, ports: List[int], timeout: int, 
                   max_workers: int) -> Dict[int, Dict[str, Any]]:
        """Scan ports using thread pool."""
        open_ports = {}
        
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            # Submit all port scan tasks
            future_to_port = {
                executor.submit(self._scan_single_port, ip, port, timeout): port 
                for port in ports
            }
            
            # Collect results as they complete
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    result = future.result()
                    if result:
                        open_ports[port] = result
                except Exception as e:
                    Logger.warning(f"Error scanning port {port}: {e}")
        
        return open_ports
    
    def _scan_single_port(self, ip: str, port: int, timeout: int) -> Optional[Dict[str, Any]]:
        """Scan a single port."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            sock.close()
            
            if result == 0:
                # Port is open, get service information
                service_info = self._get_service_info(ip, port, timeout)
                Logger.success(f"Open port {port} ({service_info['service']}) on {ip}")
                return service_info
            
        except Exception as e:
            Logger.debug(f"Error scanning port {port}: {e}")
        
        return None
    
    def _get_service_info(self, ip: str, port: int, timeout: int) -> Dict[str, Any]:
        """Get detailed service information for an open port."""
        service_info = {
            'port': port,
            'service': self.common_ports.get(port, 'Unknown'),
            'banner': None,
            'version': None,
            'protocol': 'TCP'
        }
        
        # Try to get banner
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((ip, port))
            
            # Send a basic probe
            probes = [
                b'\r\n',  # HTTP-like
                b'HELP\r\n',  # SMTP-like
                b'VERSION\r\n',  # Generic
                b'\x00',  # Null byte
            ]
            
            for probe in probes:
                try:
                    sock.send(probe)
                    response = sock.recv(1024)
                    if response:
                        service_info['banner'] = response.decode('utf-8', errors='ignore').strip()
                        break
                except:
                    continue
            
            sock.close()
            
        except Exception as e:
            Logger.debug(f"Could not get banner for port {port}: {e}")
        
        # Analyze banner for version information
        if service_info['banner']:
            service_info['version'] = self._extract_version(service_info['banner'])
        
        return service_info
    
    def _extract_version(self, banner: str) -> Optional[str]:
        """Extract version information from banner."""
        import re
        
        # Common version patterns
        version_patterns = [
            r'(\d+\.\d+\.\d+)',  # x.x.x
            r'(\d+\.\d+)',       # x.x
            r'version[:\s]+([^\s]+)',  # version: x.x.x
            r'v([\d\.]+)',       # vx.x.x
        ]
        
        for pattern in version_patterns:
            match = re.search(pattern, banner, re.IGNORECASE)
            if match:
                return match.group(1)
        
        return None
    
    def scan_port_range(self, target: str, start_port: int, end_port: int, 
                       timeout: int = 3, max_workers: int = 50) -> Dict[str, Any]:
        """Scan a range of ports."""
        port_range = list(range(start_port, end_port + 1))
        return self.scan_target(target, port_range, timeout, max_workers)
    
    def quick_scan(self, target: str) -> Dict[str, Any]:
        """Perform a quick scan of most common ports."""
        common_ports = [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 3306, 5432, 8080]
        return self.scan_target(target, common_ports, timeout=2, max_workers=20)
    
    def service_scan(self, target: str, service: str) -> Dict[str, Any]:
        """Scan for specific service ports."""
        service_ports = {
            'web': [80, 443, 8080, 8443, 3000, 8000, 5000],
            'database': [3306, 5432, 27017, 6379, 1521, 1433],
            'mail': [25, 587, 465, 110, 995, 143, 993],
            'ftp': [21, 22, 23, 69],
            'remote': [3389, 5900, 5901, 5902],
            'development': [9000, 8081, 3001, 5001, 8001]
        }
        
        if service.lower() in service_ports:
            return self.scan_target(target, service_ports[service.lower()])
        else:
            Logger.warning(f"Unknown service: {service}")
            return {'error': f'Unknown service: {service}'}
    
    def save_results(self, filename: str = None) -> str:
        """Save scan results to file."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            filename = f"port_scan_{self.results.get('target', 'unknown')}_{timestamp}.json"
        
        import json
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        
        Logger.success(f"Port scan results saved to {filename}")
        return filename

def main():
    """Main function for testing."""
    scanner = PortScanner()
    
    # Example usage
    target = "example.com"
    results = scanner.quick_scan(target)
    
    print(f"Scan results for {target}:")
    for port, info in results.get('open_ports', {}).items():
        print(f"  Port {port}: {info['service']} - {info.get('banner', 'No banner')}")
    
    # Save results
    scanner.save_results()

if __name__ == "__main__":
    main() 