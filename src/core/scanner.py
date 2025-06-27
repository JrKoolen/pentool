"""
Main scanning engine for the penetration testing tool.
"""

import os
import sys
import argparse
import json
from typing import Dict, List, Any, Optional
from datetime import datetime
import time
from urllib.parse import urlparse
import re

# Add the src directory to the Python path
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from src.core.utils import Logger, normalize_url, save_results
from src.core.config import config
from src.modules.reconnaissance.domain_info import DomainInfoGatherer
from src.modules.reconnaissance.port_scanner import PortScanner
from src.modules.reconnaissance.security_headers import SecurityHeadersAnalyzer
from src.modules.discovery.directories import DirectoryEnumerator
from src.modules.vulnerabilities.vulnerability_scanner import VulnerabilityScanner

class PenTestScanner:
    """Main penetration testing scanner class."""
    
    def __init__(self):
        self.results = {
            'scan_info': {},
            'domain_info': {},
            'port_scan': {},
            'security_headers': {},
            'directory_enum': {},
            'vulnerabilities': [],
            'summary': {}
        }
        self.start_time = None
        self.end_time = None
        self.domain_gatherer = DomainInfoGatherer()
        self.port_scanner = PortScanner()
        self.security_headers_analyzer = SecurityHeadersAnalyzer()
        self.directory_enumerator = DirectoryEnumerator()
        self.vulnerability_scanner = VulnerabilityScanner()
    
    def run_full_scan(self, target: str, modules: Optional[List[str]] = None) -> Dict[str, Any]:
        """Run a full penetration test scan."""
        Logger.info(f"Starting full penetration test scan for: {target}")
        
        self.start_time = datetime.now()
        target = normalize_url(target)
        
        # Default modules if none specified
        if not modules:
            modules = ['domain_info', 'port_scan', 'security_headers', 'directory_enum']
        
        # Initialize scan info
        self.results['scan_info'] = {
            'target': target,
            'start_time': self.start_time.isoformat(),
            'modules': modules,
            'scanner_version': '1.1.0'
        }
        
        try:
            # Module 1: Domain Information Gathering (Enhanced with DNS recon)
            if 'domain_info' in modules:
                Logger.info("=== Starting Enhanced Domain Information Gathering ===")
                try:
                    domain_gatherer = DomainInfoGatherer()
                    self.results['domain_info'] = domain_gatherer.gather_all(target)
                    domain_gatherer.save_results()
                except Exception as e:
                    Logger.error(f"Domain info gathering failed: {e}")
                    self.results['domain_info'] = {'error': str(e)}
            
            # Module 2: Port Scanning (NEW)
            if 'port_scan' in modules:
                Logger.info("=== Starting Port Scanning ===")
                try:
                    # Extract domain for port scanning - handle URLs properly
                    parsed_url = urlparse(target)
                    domain = parsed_url.netloc
                    if not domain:
                        # If netloc is empty, try to extract domain from the target
                        domain = target.replace('https://', '').replace('http://', '').split('/')[0]
                    
                    Logger.info(f"Port scanning domain: {domain}")
                    self.results['port_scan'] = self.port_scanner.quick_scan(domain)
                    self.port_scanner.save_results()
                except Exception as e:
                    Logger.error(f"Port scanning failed: {e}")
                    self.results['port_scan'] = {'error': str(e)}
            
            # Module 3: Security Headers Analysis (NEW)
            if 'security_headers' in modules:
                Logger.info("=== Starting Security Headers Analysis ===")
                try:
                    self.results['security_headers'] = self.security_headers_analyzer.analyze_target(target)
                    self.security_headers_analyzer.save_results()
                except Exception as e:
                    Logger.error(f"Security headers analysis failed: {e}")
                    self.results['security_headers'] = {'error': str(e)}
            
            # Module 4: Directory and File Enumeration
            if 'directory_enum' in modules:
                Logger.info("=== Starting Directory and File Enumeration ===")
                try:
                    dir_enumerator = DirectoryEnumerator()
                    self.results['directory_enum'] = dir_enumerator.enumerate_all(target)
                    dir_enumerator.save_results()
                except Exception as e:
                    Logger.error(f"Directory enumeration failed: {e}")
                    self.results['directory_enum'] = {'error': str(e)}
            
            # Module 5: Vulnerability Scanning
            if 'vulnerabilities' in modules:
                Logger.info("=== Starting Vulnerability Scanning ===")
                try:
                    vuln_results = self.vulnerability_scanner.scan_target(target)
                    self.results['vulnerabilities'] = vuln_results
                except Exception as e:
                    Logger.error(f"Vulnerability scanning failed: {e}")
                    self.results['vulnerabilities'] = {'error': str(e)}
            
            # Generate summary
            self.generate_summary()
            
        except KeyboardInterrupt:
            Logger.warning("Scan interrupted by user")
            self.results['scan_info']['status'] = 'interrupted'
        except Exception as e:
            Logger.error(f"Scan failed: {e}")
            self.results['scan_info']['status'] = 'failed'
            self.results['scan_info']['error'] = str(e)
        
        self.end_time = datetime.now()
        self.results['scan_info']['end_time'] = self.end_time.isoformat()
        self.results['scan_info']['duration'] = str(self.end_time - self.start_time)
        
        # Save final results
        self.save_final_results()
        
        Logger.success("Scan completed successfully!")
        return self.results
    
    def generate_summary(self):
        """Generate a summary of all findings."""
        Logger.info("Generating scan summary...")
        
        summary = {
            'total_findings': 0,
            'risk_level': 'low',
            'critical_findings': 0,
            'high_findings': 0,
            'medium_findings': 0,
            'low_findings': 0,
            'recommendations': []
        }
        
        # Count domain information findings (Enhanced DNS recon)
        if self.results['domain_info']:
            domain_info = self.results['domain_info']
            
            # Check for interesting findings
            if domain_info.get('subdomains'):
                summary['total_findings'] += len(domain_info['subdomains'])
                summary['medium_findings'] += len(domain_info['subdomains'])
            
            if domain_info.get('ports'):
                summary['total_findings'] += len(domain_info['ports'])
                summary['low_findings'] += len(domain_info['ports'])
            
            # Check SSL/TLS configuration
            ssl_info = domain_info.get('ssl_info', {})
            if 'error' in ssl_info:
                summary['high_findings'] += 1
                summary['recommendations'].append("SSL/TLS certificate issues detected")
            
            # Check DNS zone transfer vulnerabilities
            dns_records = domain_info.get('dns_records', {})
            zone_transfer = dns_records.get('zone_transfer', {})
            if zone_transfer.get('zone_transfer_success'):
                summary['critical_findings'] += 1
                summary['recommendations'].append("DNS zone transfer vulnerability - CRITICAL")
            
            # Check DNS wildcard
            wildcard = dns_records.get('wildcard_detection', {})
            if wildcard.get('wildcard_detected'):
                summary['medium_findings'] += 1
                summary['recommendations'].append("DNS wildcard detected - potential subdomain takeover risk")
            
            # Check DNSSEC
            dnssec = dns_records.get('dns_sec', {})
            if not dnssec.get('dnssec_enabled'):
                summary['medium_findings'] += 1
                summary['recommendations'].append("DNSSEC not enabled - consider enabling for DNS security")
        
        # Count port scanning findings (NEW)
        if self.results['port_scan']:
            port_scan = self.results['port_scan']
            open_ports = port_scan.get('open_ports', {})
            
            summary['total_findings'] += len(open_ports)
            summary['low_findings'] += len(open_ports)
            
            # Check for dangerous ports
            dangerous_ports = [21, 23, 3389, 5900, 5901, 5902]  # FTP, Telnet, RDP, VNC
            for port in open_ports:
                if port in dangerous_ports:
                    summary['high_findings'] += 1
                    summary['recommendations'].append(f"Potentially dangerous port {port} open - review necessity")
            
            # Check for development ports
            dev_ports = [3000, 8000, 5000, 8080, 9000]  # Common dev ports
            for port in open_ports:
                if port in dev_ports:
                    summary['medium_findings'] += 1
                    summary['recommendations'].append(f"Development port {port} open - ensure not exposed in production")
        
        # Count security headers findings (NEW)
        if self.results['security_headers']:
            sec_headers = self.results['security_headers']
            security_score = sec_headers.get('security_score', 0)
            
            if security_score < 50:
                summary['high_findings'] += 1
                summary['recommendations'].append("Security headers score very low - immediate attention required")
            elif security_score < 80:
                summary['medium_findings'] += 1
                summary['recommendations'].append("Security headers need improvement")
            
            # Count vulnerabilities from security headers
            vulnerabilities = sec_headers.get('vulnerabilities', [])
            for vuln in vulnerabilities:
                if vuln.get('severity') == 'High':
                    summary['high_findings'] += 1
                elif vuln.get('severity') == 'Medium':
                    summary['medium_findings'] += 1
                else:
                    summary['low_findings'] += 1
        
        # Count directory enumeration findings
        if self.results['directory_enum']:
            dir_enum = self.results['directory_enum']
            
            # Check for sensitive findings
            if dir_enum.get('backup_files'):
                summary['total_findings'] += len(dir_enum['backup_files'])
                summary['high_findings'] += len(dir_enum['backup_files'])
                summary['recommendations'].append("Backup files found - remove them immediately")
            
            if dir_enum.get('interesting_findings'):
                summary['total_findings'] += len(dir_enum['interesting_findings'])
                summary['medium_findings'] += len(dir_enum['interesting_findings'])
                summary['recommendations'].append("Hidden files/directories found - review for sensitive information")
            
            # Check for directory listing
            directories = dir_enum.get('directories', [])
            for directory in directories:
                if directory.get('directory_listing'):
                    summary['critical_findings'] += 1
                    summary['recommendations'].append("Directory listing enabled - disable immediately")
        
        # Count vulnerabilities
        if self.results['vulnerabilities']:
            vuln_summary = self.results['vulnerabilities']['summary']
            summary['total_findings'] += vuln_summary.get('total_vulnerabilities', 0)
            summary['critical_findings'] += vuln_summary.get('critical', 0)
            summary['high_findings'] += vuln_summary.get('high', 0)
            summary['medium_findings'] += vuln_summary.get('medium', 0)
            summary['low_findings'] += vuln_summary.get('low', 0)
        
        # Determine overall risk level
        if summary['critical_findings'] > 0:
            summary['risk_level'] = 'critical'
        elif summary['high_findings'] > 0:
            summary['risk_level'] = 'high'
        elif summary['medium_findings'] > 0:
            summary['risk_level'] = 'medium'
        else:
            summary['risk_level'] = 'low'
        
        self.results['summary'] = summary
        
        Logger.success(f"Scan summary generated - Risk Level: {summary['risk_level']}")
    
    def save_final_results(self):
        """Save the final scan results."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Properly extract and sanitize domain from target URL
        target_url = self.results['scan_info']['target']
        
        # Parse URL to get domain
        parsed_url = urlparse(target_url)
        target_domain = parsed_url.netloc
        
        # Remove invalid characters for filenames
        sanitized_domain = re.sub(r'[<>:"/\\|?*]', '_', target_domain)
        
        filename = f"pentest_scan_{sanitized_domain}_{timestamp}.json"
        
        save_results(filename, self.results, 'json')
    
    def print_summary(self):
        """Print a formatted summary of the scan results."""
        if not self.results['summary']:
            Logger.warning("No summary available")
            return
        
        summary = self.results['summary']
        
        print("\n" + "="*60)
        print("           PENETRATION TEST SCAN SUMMARY")
        print("="*60)
        print(f"Target: {self.results['scan_info']['target']}")
        print(f"Scan Duration: {self.results['scan_info']['duration']}")
        print(f"Overall Risk Level: {summary['risk_level'].upper()}")
        print("-"*60)
        print("FINDINGS BREAKDOWN:")
        print(f"  Critical: {summary['critical_findings']}")
        print(f"  High: {summary['high_findings']}")
        print(f"  Medium: {summary['medium_findings']}")
        print(f"  Low: {summary['low_findings']}")
        print(f"  Total: {summary['total_findings']}")
        print("-"*60)
        
        if summary['recommendations']:
            print("RECOMMENDATIONS:")
            for i, rec in enumerate(summary['recommendations'], 1):
                print(f"  {i}. {rec}")
        
        print("="*60)
    
    def export_report(self, format: str = 'json'):
        """Export scan results in various formats."""
        if format == 'json':
            return self.results
        elif format == 'txt':
            # Generate text report
            report = []
            report.append("PENETRATION TEST REPORT")
            report.append("=" * 50)
            report.append(f"Target: {self.results['scan_info']['target']}")
            report.append(f"Date: {self.results['scan_info']['start_time']}")
            report.append(f"Duration: {self.results['scan_info']['duration']}")
            report.append("")
            
            # Add findings
            if self.results['domain_info']:
                report.append("DOMAIN INFORMATION:")
                report.append("-" * 20)
                domain_info = self.results['domain_info']
                if domain_info.get('ip_info', {}).get('ipv4_addresses'):
                    report.append(f"IP Addresses: {', '.join(domain_info['ip_info']['ipv4_addresses'])}")
                if domain_info.get('ports'):
                    report.append(f"Open Ports: {list(domain_info['ports'].keys())}")
                report.append("")
            
            if self.results['directory_enum']:
                report.append("DIRECTORY ENUMERATION:")
                report.append("-" * 20)
                dir_enum = self.results['directory_enum']
                if dir_enum.get('directories'):
                    report.append(f"Directories Found: {len(dir_enum['directories'])}")
                if dir_enum.get('backup_files'):
                    report.append(f"Backup Files: {len(dir_enum['backup_files'])}")
                report.append("")
            
            return "\n".join(report)
        
        return None

def main():
    """Main function for command-line usage."""
    parser = argparse.ArgumentParser(description='Web Penetration Testing Tool')
    parser.add_argument('target', help='Target URL or domain')
    parser.add_argument('--modules', nargs='+', 
                       choices=['domain_info', 'port_scan', 'security_headers', 'directory_enum', 'vulnerabilities'],
                       default=['domain_info', 'port_scan', 'security_headers', 'directory_enum'],
                       help='Modules to run')
    parser.add_argument('--output', choices=['json', 'txt'], default='json',
                       help='Output format')
    parser.add_argument('--verbose', '-v', action='store_true',
                       help='Verbose output')
    
    args = parser.parse_args()
    
    # Configure logging level
    if args.verbose:
        import logging
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Run the scan
    scanner = PenTestScanner()
    results = scanner.run_full_scan(args.target, args.modules)
    
    # Print summary
    scanner.print_summary()
    
    # Export report if requested
    if args.output:
        report = scanner.export_report(args.output)
        if report:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            
            # Properly extract and sanitize domain from target URL
            parsed_url = urlparse(args.target)
            target_domain = parsed_url.netloc
            
            # Remove invalid characters for filenames
            sanitized_domain = re.sub(r'[<>:"/\\|?*]', '_', target_domain)
            
            filename = f"pentest_report_{sanitized_domain}_{timestamp}.{args.output}"
            save_results(filename, report, args.output)

if __name__ == "__main__":
    main() 