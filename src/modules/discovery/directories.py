"""
Directory and file enumeration module.
"""

import os
import time
from typing import Dict, List, Set, Tuple, Optional
from urllib.parse import urljoin, urlparse
from concurrent.futures import ThreadPoolExecutor, as_completed
import json
from datetime import datetime
import re

from src.core.utils import Logger, HTTPClient, normalize_url, random_delay
from src.core.config import config

class DirectoryEnumerator:
    """Directory and file enumeration class."""
    
    def __init__(self, max_threads: int = 10):
        self.http_client = HTTPClient()
        self.max_threads = max_threads
        self.results = {
            'directories': [],
            'files': [],
            'interesting_findings': [],
            'robots_txt': None,
            'sitemap': None,
            'backup_files': []
        }
        self.visited_urls = set()
        self.found_urls = set()
    
    def enumerate_all(self, base_url: str) -> Dict[str, List[str]]:
        """Perform comprehensive directory and file enumeration."""
        Logger.info(f"Starting directory enumeration for: {base_url}")
        
        base_url = normalize_url(base_url)
        
        # Phase 1: Check common files
        Logger.info("Phase 1: Checking common files")
        self.check_common_files(base_url)
        
        # Phase 2: Directory enumeration
        Logger.info("Phase 2: Directory enumeration")
        self.enumerate_directories(base_url)
        
        # Phase 3: Backup file detection
        Logger.info("Phase 3: Backup file detection")
        self.find_backup_files(base_url)
        
        # Phase 4: Hidden files and directories
        Logger.info("Phase 4: Hidden files and directories")
        self.find_hidden_items(base_url)
        
        Logger.success(f"Directory enumeration completed. Found {len(self.found_urls)} items")
        return self.results
    
    def check_common_files(self, base_url: str):
        """Check for common files like robots.txt, sitemap.xml, etc."""
        common_files = [
            'robots.txt',
            'sitemap.xml',
            'sitemap_index.xml',
            '.htaccess',
            'web.config',
            'crossdomain.xml',
            'clientaccesspolicy.xml',
            'favicon.ico',
            'security.txt',
            '.well-known/security.txt',
            'humans.txt',
            'ads.txt',
            'app-ads.txt'
        ]
        
        for file_path in common_files:
            url = urljoin(base_url, file_path)
            if url in self.visited_urls:
                continue
                
            self.visited_urls.add(url)
            response = self.http_client.head(url)
            
            if response and response.status_code == 200:
                self.found_urls.add(url)
                
                if file_path == 'robots.txt':
                    self.results['robots_txt'] = {
                        'url': url,
                        'content': self.http_client.get(url).text if self.http_client.get(url) else ''
                    }
                    Logger.success(f"Found robots.txt: {url}")
                    
                elif file_path == 'sitemap.xml':
                    self.results['sitemap'] = {
                        'url': url,
                        'content': self.http_client.get(url).text if self.http_client.get(url) else ''
                    }
                    Logger.success(f"Found sitemap: {url}")
                    
                else:
                    self.results['files'].append({
                        'url': url,
                        'status_code': response.status_code,
                        'content_length': response.headers.get('content-length', 'unknown')
                    })
                    Logger.success(f"Found file: {url}")
            
            random_delay(0.1, 0.3)
    
    def enumerate_directories(self, base_url: str):
        """Enumerate directories using wordlist."""
        directories = config.get_wordlist('directories')
        
        def check_directory(directory):
            url = urljoin(base_url, directory + '/')
            if url in self.visited_urls:
                return None
                
            self.visited_urls.add(url)
            response = self.http_client.head(url)
            
            if response and response.status_code in [200, 301, 302, 403]:
                self.found_urls.add(url)
                result = {
                    'url': url,
                    'status_code': response.status_code,
                    'content_length': response.headers.get('content-length', 'unknown'),
                    'server': response.headers.get('server', 'unknown')
                }
                
                # Check if directory listing is enabled
                if response.status_code == 200:
                    get_response = self.http_client.get(url)
                    if get_response and self.is_directory_listing(get_response.text):
                        result['directory_listing'] = True
                        Logger.warning(f"Directory listing enabled: {url}")
                
                return result
            
            return None
        
        # Use ThreadPoolExecutor for concurrent scanning
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_dir = {executor.submit(check_directory, directory): directory for directory in directories}
            
            for future in as_completed(future_to_dir):
                result = future.result()
                if result:
                    self.results['directories'].append(result)
                    Logger.success(f"Found directory: {result['url']}")
                
                random_delay(0.05, 0.15)
    
    def find_backup_files(self, base_url: str):
        """Find backup files and common backup extensions."""
        backup_extensions = [
            '.bak', '.backup', '.old', '.orig', '.save', '.swp', '.tmp',
            '.zip', '.tar.gz', '.rar', '.7z', '.sql', '.db', '.sqlite'
        ]
        
        # Get discovered directories and files
        discovered_items = []
        for directory in self.results['directories']:
            discovered_items.append(directory['url'].rstrip('/'))
        
        for file_item in self.results['files']:
            discovered_items.append(file_item['url'])
        
        # Add base URL
        discovered_items.append(base_url.rstrip('/'))
        
        def check_backup_file(item_url):
            backup_files = []
            for ext in backup_extensions:
                backup_url = item_url + ext
                if backup_url in self.visited_urls:
                    continue
                    
                self.visited_urls.add(backup_url)
                response = self.http_client.head(backup_url)
                
                if response and response.status_code == 200:
                    self.found_urls.add(backup_url)
                    backup_files.append({
                        'url': backup_url,
                        'extension': ext,
                        'content_length': response.headers.get('content-length', 'unknown')
                    })
                    Logger.warning(f"Found backup file: {backup_url}")
                
                random_delay(0.1, 0.2)
            
            return backup_files
        
        # Check backup files for discovered items
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_item = {executor.submit(check_backup_file, item): item for item in discovered_items}
            
            for future in as_completed(future_to_item):
                backup_files = future.result()
                self.results['backup_files'].extend(backup_files)
    
    def find_hidden_items(self, base_url: str):
        """Find hidden files and directories."""
        hidden_items = [
            '.git/', '.svn/', '.hg/', '.bzr/',
            '.env', '.htpasswd', '.htaccess', 'web.config',
            'config.php', 'config.js', 'config.json',
            '.DS_Store', 'Thumbs.db', 'desktop.ini',
            'wp-config.php', 'configuration.php', 'config.ini'
        ]
        
        def check_hidden_item(item):
            url = urljoin(base_url, item)
            if url in self.visited_urls:
                return None
                
            self.visited_urls.add(url)
            response = self.http_client.head(url)
            
            if response and response.status_code in [200, 403]:
                self.found_urls.add(url)
                result = {
                    'url': url,
                    'status_code': response.status_code,
                    'type': 'hidden_file' if '.' in item else 'hidden_directory',
                    'content_length': response.headers.get('content-length', 'unknown')
                }
                
                if response.status_code == 403:
                    Logger.warning(f"Access forbidden (potentially sensitive): {url}")
                
                return result
            
            return None
        
        with ThreadPoolExecutor(max_workers=self.max_threads) as executor:
            future_to_item = {executor.submit(check_hidden_item, item): item for item in hidden_items}
            
            for future in as_completed(future_to_item):
                result = future.result()
                if result:
                    self.results['interesting_findings'].append(result)
                    Logger.success(f"Found hidden item: {result['url']}")
                
                random_delay(0.1, 0.3)
    
    def is_directory_listing(self, content: str) -> bool:
        """Check if response contains directory listing."""
        directory_listing_indicators = [
            'Index of /',
            'Directory listing for',
            'Parent Directory',
            '[DIR]',
            'Last modified',
            'Size</a>',
            'Name</a>'
        ]
        
        content_lower = content.lower()
        return any(indicator.lower() in content_lower for indicator in directory_listing_indicators)
    
    def analyze_robots_txt(self) -> Dict[str, List[str]]:
        """Analyze robots.txt file for interesting paths."""
        if not self.results['robots_txt']:
            return {}
        
        content = self.results['robots_txt']['content']
        analysis = {
            'disallowed': [],
            'sitemaps': [],
            'user_agents': []
        }
        
        lines = content.split('\n')
        current_user_agent = None
        
        for line in lines:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            
            if ':' in line:
                key, value = line.split(':', 1)
                key = key.strip().lower()
                value = value.strip()
                
                if key == 'user-agent':
                    current_user_agent = value
                    analysis['user_agents'].append(value)
                elif key == 'disallow':
                    if current_user_agent:
                        analysis['disallowed'].append({
                            'user_agent': current_user_agent,
                            'path': value
                        })
                elif key == 'sitemap':
                    analysis['sitemaps'].append(value)
        
        return analysis
    
    def save_results(self, filename: str = None):
        """Save enumeration results to file."""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            # Get base domain and sanitize it
            if self.found_urls:
                base_domain = urlparse(list(self.found_urls)[0]).netloc
            else:
                base_domain = 'unknown'
            
            # Remove invalid characters for filenames
            sanitized_domain = re.sub(r'[<>:"/\\|?*]', '_', base_domain)
            filename = f"directory_enum_{sanitized_domain}_{timestamp}.json"
        
        os.makedirs('results', exist_ok=True)
        filepath = os.path.join('results', filename)
        
        # Add summary statistics
        summary = {
            'total_items_found': len(self.found_urls),
            'directories_found': len(self.results['directories']),
            'files_found': len(self.results['files']),
            'backup_files_found': len(self.results['backup_files']),
            'interesting_findings': len(self.results['interesting_findings']),
            'robots_txt_analysis': self.analyze_robots_txt()
        }
        
        output_data = {
            'summary': summary,
            'results': self.results,
            'timestamp': datetime.now().isoformat()
        }
        
        with open(filepath, 'w') as f:
            json.dump(output_data, f, indent=4, default=str)
        
        Logger.success(f"Directory enumeration results saved to {filepath}")
        return filepath

def main():
    """Main function for testing."""
    import sys
    
    if len(sys.argv) != 2:
        print("Usage: python directories.py <url>")
        sys.exit(1)
    
    url = sys.argv[1]
    enumerator = DirectoryEnumerator()
    results = enumerator.enumerate_all(url)
    enumerator.save_results()
    
    print("\n=== Directory Enumeration Summary ===")
    print(f"Total items found: {len(enumerator.found_urls)}")
    print(f"Directories: {len(results['directories'])}")
    print(f"Files: {len(results['files'])}")
    print(f"Backup files: {len(results['backup_files'])}")
    print(f"Interesting findings: {len(results['interesting_findings'])}")

if __name__ == "__main__":
    main() 