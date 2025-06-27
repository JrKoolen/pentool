#!/usr/bin/env python3
"""
Web Penetration Testing Tool - GUI Entry Point

Launch the graphical user interface for the penetration testing tool.
"""

import sys
import os
import tkinter as tk
from tkinter import messagebox

# Add the src directory to the Python path
sys.path.append(os.path.join(os.path.dirname(__file__), 'src'))

def check_dependencies():
    """Check if all required dependencies are installed."""
    missing_deps = []
    
    try:
        import requests
    except ImportError:
        missing_deps.append("requests")
    
    try:
        import dns.resolver
    except ImportError:
        missing_deps.append("dnspython")
    
    try:
        import whois
    except ImportError:
        missing_deps.append("python-whois")
    
    try:
        from bs4 import BeautifulSoup
    except ImportError:
        missing_deps.append("beautifulsoup4")
    
    try:
        from colorama import init
    except ImportError:
        missing_deps.append("colorama")
    
    if missing_deps:
        error_msg = f"Missing required dependencies: {', '.join(missing_deps)}\n\n"
        error_msg += "Please install them using:\n"
        error_msg += "pip install -r requirements.txt"
        
        root = tk.Tk()
        root.withdraw()  # Hide the main window
        messagebox.showerror("Missing Dependencies", error_msg)
        root.destroy()
        return False
    
    return True

def main():
    """Main function to launch the GUI."""
    # Check dependencies first
    if not check_dependencies():
        sys.exit(1)
    
    try:
        # Import and launch the main window
        from src.gui.main_window import MainWindow
        
        # Create and run the application
        app = MainWindow()
        app.run()
        
    except ImportError as e:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Import Error", f"Failed to import required modules: {e}")
        root.destroy()
        sys.exit(1)
    except Exception as e:
        root = tk.Tk()
        root.withdraw()
        messagebox.showerror("Error", f"Failed to start GUI: {e}")
        root.destroy()
        sys.exit(1)

if __name__ == "__main__":
    main() 