"""
Configuration management for the penetration testing tool.
"""

import os
import json
from typing import Dict, Any, List

class Config:
    """Configuration class for managing tool settings."""
    
    def __init__(self, config_file: str = "config.json"):
        self.config_file = config_file
        self.config = self.load_config()
        
    def load_config(self) -> Dict[str, Any]:
        """Load configuration from file or create default."""
        default_config = {
            "scanning": {
                "timeout": 10,
                "max_threads": 10,
                "user_agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "follow_redirects": True,
                "verify_ssl": False
            },
            "reconnaissance": {
                "subdomain_wordlist": "data/wordlists/subdomains.txt",
                "directory_wordlist": "data/wordlists/directories.txt",
                "port_range": [80, 443, 8080, 8443, 3000, 8000, 8888],
                "common_ports": [21, 22, 23, 25, 53, 80, 110, 143, 443, 993, 995, 8080, 8443],
                "max_subdomains": 1000,
                "max_directories": 500
            },
            "reporting": {
                "output_dir": "reports",
                "format": ["html", "json"],
                "include_timestamps": True,
                "risk_levels": ["low", "medium", "high", "critical"]
            },
            "api_keys": {
                "shodan": "",
                "censys": "",
                "virustotal": ""
            },
            "wordlists": {
                "subdomains": [
                    "www", "mail", "ftp", "admin", "blog", "dev", "test", "stage",
                    "api", "cdn", "static", "img", "images", "assets", "media"
                ],
                "directories": [
                    "admin", "login", "wp-admin", "administrator", "backup",
                    "config", "db", "database", "files", "images", "includes",
                    "js", "css", "assets", "uploads", "downloads", "temp"
                ],
                "files": [
                    "robots.txt", "sitemap.xml", ".htaccess", "web.config",
                    "config.php", "config.js", "backup.zip", "backup.sql"
                ]
            }
        }
        
        if os.path.exists(self.config_file):
            try:
                with open(self.config_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, FileNotFoundError):
                return default_config
        else:
            self.save_config(default_config)
            return default_config
    
    def save_config(self, config: Dict[str, Any]) -> None:
        """Save configuration to file."""
        with open(self.config_file, 'w') as f:
            json.dump(config, f, indent=4)
    
    def get(self, key: str, default: Any = None) -> Any:
        """Get configuration value by key."""
        keys = key.split('.')
        value = self.config
        
        for k in keys:
            if isinstance(value, dict) and k in value:
                value = value[k]
            else:
                return default
        
        return value
    
    def set(self, key: str, value: Any) -> None:
        """Set configuration value by key."""
        keys = key.split('.')
        config = self.config
        
        for k in keys[:-1]:
            if k not in config:
                config[k] = {}
            config = config[k]
        
        config[keys[-1]] = value
        self.save_config(self.config)
    
    def get_wordlist(self, wordlist_type: str) -> List[str]:
        """Get wordlist by type."""
        return self.config.get("wordlists", {}).get(wordlist_type, [])
    
    def get_scanning_config(self) -> Dict[str, Any]:
        """Get scanning configuration."""
        return self.config.get("scanning", {})
    
    def get_reconnaissance_config(self) -> Dict[str, Any]:
        """Get reconnaissance configuration."""
        return self.config.get("reconnaissance", {})

# Global configuration instance
config = Config() 