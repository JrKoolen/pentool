#!/usr/bin/env python3
"""
Website Downloader for Local Testing
Downloads a website and its resources for local penetration testing
"""

import os
import requests
from urllib.parse import urljoin, urlparse
from bs4 import BeautifulSoup
import re
import time

class WebsiteDownloader:
    def __init__(self, base_url, output_dir="local_test_site"):
        self.base_url = base_url.rstrip('/')
        self.domain = urlparse(base_url).netloc
        self.output_dir = output_dir
        self.downloaded_urls = set()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })
        
    def download_file(self, url, local_path):
        """Download a file to local path"""
        try:
            response = self.session.get(url, timeout=10, verify=False)
            response.raise_for_status()
            
            # Create directory if it doesn't exist
            os.makedirs(os.path.dirname(local_path), exist_ok=True)
            
            # Write file
            with open(local_path, 'wb') as f:
                f.write(response.content)
            
            print(f"Downloaded: {url} -> {local_path}")
            return True
        except Exception as e:
            print(f"Failed to download {url}: {e}")
            return False
    
    def get_local_path(self, url):
        """Convert URL to local file path"""
        parsed = urlparse(url)
        path = parsed.path
        
        if not path or path.endswith('/'):
            path += 'index.html'
        elif '.' not in os.path.basename(path):
            path += '.html'
            
        return os.path.join(self.output_dir, parsed.netloc, path.lstrip('/'))
    
    def extract_links(self, html_content, base_url):
        """Extract all links from HTML content"""
        soup = BeautifulSoup(html_content, 'html.parser')
        links = []
        
        # Find all links
        for tag in soup.find_all(['a', 'link', 'script', 'img']):
            href = tag.get('href') or tag.get('src')
            if href:
                absolute_url = urljoin(base_url, href)
                if absolute_url.startswith(self.base_url):
                    links.append(absolute_url)
        
        return links
    
    def download_site(self, max_depth=2):
        """Download the website recursively"""
        print(f"Starting download of {self.base_url}")
        print(f"Output directory: {self.output_dir}")
        
        urls_to_download = [(self.base_url, 0)]  # (url, depth)
        
        while urls_to_download:
            url, depth = urls_to_download.pop(0)
            
            if url in self.downloaded_urls or depth > max_depth:
                continue
                
            self.downloaded_urls.add(url)
            
            try:
                response = self.session.get(url, timeout=10, verify=False)
                response.raise_for_status()
                
                local_path = self.get_local_path(url)
                
                # Download the file
                if self.download_file(url, local_path):
                    # If it's HTML, extract links for further downloading
                    if response.headers.get('content-type', '').startswith('text/html'):
                        links = self.extract_links(response.text, url)
                        for link in links:
                            if link not in self.downloaded_urls:
                                urls_to_download.append((link, depth + 1))
                
                # Be nice to the server
                time.sleep(0.1)
                
            except Exception as e:
                print(f"Error processing {url}: {e}")
        
        print(f"\nDownload completed! Files saved to {self.output_dir}")
        print(f"Total files downloaded: {len(self.downloaded_urls)}")

def main():
    # Example usage
    url = "http://testphp.vulnweb.com"
    downloader = WebsiteDownloader(url)
    downloader.download_site(max_depth=2)

if __name__ == "__main__":
    main() 