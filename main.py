#!/usr/bin/env python3
"""
Web Penetration Testing Tool - Main Entry Point

A comprehensive web application penetration testing tool with advanced
information gathering and vulnerability assessment capabilities.

Usage:
    python main.py <target> [options]
    python main.py --help

Example:
    python main.py example.com --modules reconnaissance discovery
    python main.py https://example.com --verbose --output json
"""

import sys
import os
import argparse
from datetime import datetime

# Add the src directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

from src.core.scanner import PenTestScanner
from src.core.utils import Logger

def print_banner():
    """Print the tool banner."""
    banner = """
    ╔══════════════════════════════════════════════════════════════╗
    ║                    WEB PENETRATION TESTING TOOL              ║
    ║                                                              ║
    ║  Advanced Information Gathering & Vulnerability Assessment   ║
    ║                                                              ║
    ║  Version: 1.0.0                                              ║
    ║  Author: Security Researcher                                 ║
    ╚══════════════════════════════════════════════════════════════╝
    """
    print(banner)

def validate_target(target: str) -> str:
    """Validate and normalize the target URL."""
    if not target:
        raise ValueError("Target cannot be empty")
    
    # Remove protocol if present and add https://
    if target.startswith(('http://', 'https://')):
        return target
    else:
        return f"https://{target}"

def main():
    """Main function."""
    print_banner()
    
    parser = argparse.ArgumentParser(
        description='Web Penetration Testing Tool - Advanced Information Gathering',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  %(prog)s example.com
  %(prog)s https://example.com --modules domain_info directory_enum
  %(prog)s example.com --verbose --output json
  %(prog)s example.com --modules domain_info --threads 20
        """
    )
    
    parser.add_argument(
        'target',
        help='Target URL or domain (e.g., example.com or https://example.com)'
    )
    
    parser.add_argument(
        '--modules', '-m',
        nargs='+',
        choices=['domain_info', 'directory_enum', 'vulnerabilities'],
        default=['domain_info', 'directory_enum'],
        help='Modules to run (default: domain_info directory_enum)'
    )
    
    parser.add_argument(
        '--output', '-o',
        choices=['json', 'txt'],
        default='json',
        help='Output format for reports (default: json)'
    )
    
    parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        help='Enable verbose output'
    )
    
    parser.add_argument(
        '--threads', '-t',
        type=int,
        default=10,
        help='Number of threads for concurrent scanning (default: 10)'
    )
    
    parser.add_argument(
        '--timeout',
        type=int,
        default=10,
        help='Request timeout in seconds (default: 10)'
    )
    
    parser.add_argument(
        '--no-delay',
        action='store_true',
        help='Disable random delays between requests (not recommended)'
    )
    
    args = parser.parse_args()
    
    try:
        # Validate target
        target = validate_target(args.target)
        Logger.info(f"Target validated: {target}")
        
        # Update configuration based on arguments
        from src.core.config import config
        config.set('scanning.max_threads', args.threads)
        config.set('scanning.timeout', args.timeout)
        
        if args.no_delay:
            Logger.warning("Random delays disabled - this may trigger rate limiting")
        
        # Configure logging
        if args.verbose:
            import logging
            logging.getLogger().setLevel(logging.DEBUG)
            Logger.info("Verbose mode enabled")
        
        # Display scan configuration
        Logger.info("Scan Configuration:")
        Logger.info(f"  Target: {target}")
        Logger.info(f"  Modules: {', '.join(args.modules)}")
        Logger.info(f"  Threads: {args.threads}")
        Logger.info(f"  Timeout: {args.timeout}s")
        Logger.info(f"  Output Format: {args.output}")
        
        # Confirm scan
        print(f"\nStarting scan at {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
        print("=" * 60)
        
        # Run the scan
        scanner = PenTestScanner()
        results = scanner.run_full_scan(target, args.modules)
        
        # Print summary
        scanner.print_summary()
        
        # Export report
        if args.output:
            report = scanner.export_report(args.output)
            if report:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                target_domain = target.replace('https://', '').replace('http://', '').replace('/', '')
                filename = f"pentest_report_{target_domain}_{timestamp}.{args.output}"
                
                from src.core.utils import save_results
                save_results(filename, report, args.output)
                
                Logger.success(f"Report exported to: {filename}")
        
        Logger.success("Scan completed successfully!")
        
    except KeyboardInterrupt:
        Logger.warning("\nScan interrupted by user (Ctrl+C)")
        sys.exit(1)
    except ValueError as e:
        Logger.error(f"Invalid target: {e}")
        sys.exit(1)
    except Exception as e:
        Logger.error(f"Scan failed: {e}")
        if args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)

if __name__ == "__main__":
    main() 