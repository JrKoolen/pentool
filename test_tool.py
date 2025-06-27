#!/usr/bin/env python3
"""
Test script for the Web Penetration Testing Tool
"""

import sys
import os

# Add the src directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

def test_imports():
    """Test if all modules can be imported successfully."""
    print("Testing module imports...")
    
    try:
        from src.core.config import config
        print("✓ Configuration module imported successfully")
        
        from src.core.utils import Logger, HTTPClient
        print("✓ Utils module imported successfully")
        
        from src.modules.reconnaissance.domain_info import DomainInfoGatherer
        print("✓ Domain info module imported successfully")
        
        from src.modules.discovery.directories import DirectoryEnumerator
        print("✓ Directory enumeration module imported successfully")
        
        from src.core.scanner import PenTestScanner
        print("✓ Scanner module imported successfully")
        
        return True
        
    except ImportError as e:
        print(f"✗ Import error: {e}")
        return False
    except Exception as e:
        print(f"✗ Unexpected error: {e}")
        return False

def test_configuration():
    """Test configuration functionality."""
    print("\nTesting configuration...")
    
    try:
        from src.core.config import config
        
        # Test basic config operations
        test_value = config.get('scanning.timeout', 10)
        print(f"✓ Configuration get: {test_value}")
        
        config.set('test.key', 'test_value')
        retrieved = config.get('test.key')
        print(f"✓ Configuration set/get: {retrieved}")
        
        wordlist = config.get_wordlist('subdomains')
        print(f"✓ Wordlist retrieval: {len(wordlist)} items")
        
        return True
        
    except Exception as e:
        print(f"✗ Configuration test failed: {e}")
        return False

def test_utils():
    """Test utility functions."""
    print("\nTesting utility functions...")
    
    try:
        from src.core.utils import normalize_url, extract_domain, is_valid_domain
        
        # Test URL normalization
        test_url = "example.com"
        normalized = normalize_url(test_url)
        print(f"✓ URL normalization: {test_url} -> {normalized}")
        
        # Test domain extraction
        domain = extract_domain("https://www.example.com/path")
        print(f"✓ Domain extraction: {domain}")
        
        # Test domain validation
        is_valid = is_valid_domain("example.com")
        print(f"✓ Domain validation: {is_valid}")
        
        return True
        
    except Exception as e:
        print(f"✗ Utils test failed: {e}")
        return False

def test_scanner():
    """Test scanner initialization."""
    print("\nTesting scanner initialization...")
    
    try:
        from src.core.scanner import PenTestScanner
        
        scanner = PenTestScanner()
        print("✓ Scanner initialized successfully")
        
        # Test scanner structure
        if hasattr(scanner, 'results') and isinstance(scanner.results, dict):
            print("✓ Scanner results structure is correct")
        else:
            print("✗ Scanner results structure is incorrect")
            return False
        
        return True
        
    except Exception as e:
        print(f"✗ Scanner test failed: {e}")
        return False

def main():
    """Run all tests."""
    print("=" * 50)
    print("WEB PENETRATION TESTING TOOL - TEST SUITE")
    print("=" * 50)
    
    tests = [
        test_imports,
        test_configuration,
        test_utils,
        test_scanner
    ]
    
    passed = 0
    total = len(tests)
    
    for test in tests:
        if test():
            passed += 1
        print()
    
    print("=" * 50)
    print(f"TEST RESULTS: {passed}/{total} tests passed")
    
    if passed == total:
        print("✓ All tests passed! The tool is ready to use.")
        print("\nYou can now run the tool with:")
        print("  python main.py example.com")
        print("  python main.py --help")
    else:
        print("✗ Some tests failed. Please check the errors above.")
    
    print("=" * 50)

if __name__ == "__main__":
    main() 