"""
Advanced scan configuration window.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
from typing import Dict, List, Any, Callable
import queue

class ScanWindow:
    """Advanced scan configuration window."""
    
    def __init__(self, parent, on_scan_start: Callable):
        self.parent = parent
        self.on_scan_start = on_scan_start
        self.window = None
        
    def show(self):
        """Show the scan configuration window."""
        self.window = tk.Toplevel(self.parent)
        self.window.title("Advanced Scan Configuration")
        self.window.geometry("600x700")
        self.window.resizable(True, True)
        
        # Center the window
        self.window.transient(self.parent)
        self.window.grab_set()
        
        self.create_widgets()
        
    def create_widgets(self):
        """Create the window widgets."""
        # Main frame
        main_frame = ttk.Frame(self.window, padding="20")
        main_frame.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        
        # Configure grid weights
        self.window.columnconfigure(0, weight=1)
        self.window.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="Advanced Scan Configuration", 
                               font=("Arial", 16, "bold"))
        title_label.grid(row=0, column=0, columnspan=2, pady=(0, 20))
        
        # Target URL
        ttk.Label(main_frame, text="Target URL:").grid(row=1, column=0, sticky=tk.W, pady=5)
        self.url_entry = ttk.Entry(main_frame, width=50)
        self.url_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=5, padx=(10, 0))
        
        # Scan modules
        ttk.Label(main_frame, text="Scan Modules:").grid(row=2, column=0, sticky=tk.W, pady=(20, 5))
        
        modules_frame = ttk.Frame(main_frame)
        modules_frame.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=(20, 5), padx=(10, 0))
        
        # Module checkboxes
        self.module_vars = {}
        modules = [
            ("domain_info", "Domain Information Gathering", "WHOIS, DNS, subdomains, ports"),
            ("directory_enum", "Directory Enumeration", "Files, directories, backup files"),
            ("vulnerabilities", "Vulnerability Scanning", "SQL injection, XSS, CSRF, etc.")
        ]
        
        for i, (key, name, desc) in enumerate(modules):
            var = tk.BooleanVar(value=True)
            self.module_vars[key] = var
            
            cb = ttk.Checkbutton(modules_frame, text=name, variable=var)
            cb.grid(row=i, column=0, sticky=tk.W, pady=2)
            
            desc_label = ttk.Label(modules_frame, text=f"  ({desc})", 
                                  font=("Arial", 9), foreground="gray")
            desc_label.grid(row=i, column=1, sticky=tk.W, pady=2)
        
        # Scan options
        ttk.Label(main_frame, text="Scan Options:").grid(row=3, column=0, sticky=tk.W, pady=(20, 5))
        
        options_frame = ttk.Frame(main_frame)
        options_frame.grid(row=3, column=1, sticky=(tk.W, tk.E), pady=(20, 5), padx=(10, 0))
        
        # Threads
        ttk.Label(options_frame, text="Threads:").grid(row=0, column=0, sticky=tk.W, pady=2)
        self.threads_var = tk.StringVar(value="10")
        threads_spin = ttk.Spinbox(options_frame, from_=1, to=50, textvariable=self.threads_var, width=10)
        threads_spin.grid(row=0, column=1, sticky=tk.W, pady=2, padx=(10, 0))
        
        # Timeout
        ttk.Label(options_frame, text="Timeout (seconds):").grid(row=1, column=0, sticky=tk.W, pady=2)
        self.timeout_var = tk.StringVar(value="30")
        timeout_spin = ttk.Spinbox(options_frame, from_=5, to=300, textvariable=self.timeout_var, width=10)
        timeout_spin.grid(row=1, column=1, sticky=tk.W, pady=2, padx=(10, 0))
        
        # Delay
        ttk.Label(options_frame, text="Delay (seconds):").grid(row=2, column=0, sticky=tk.W, pady=2)
        self.delay_var = tk.StringVar(value="0.1")
        delay_spin = ttk.Spinbox(options_frame, from_=0, to=5, increment=0.1, textvariable=self.delay_var, width=10)
        delay_spin.grid(row=2, column=1, sticky=tk.W, pady=2, padx=(10, 0))
        
        # User agent
        ttk.Label(options_frame, text="User Agent:").grid(row=3, column=0, sticky=tk.W, pady=2)
        self.user_agent_var = tk.StringVar(value="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36")
        user_agent_entry = ttk.Entry(options_frame, textvariable=self.user_agent_var, width=40)
        user_agent_entry.grid(row=3, column=1, sticky=(tk.W, tk.E), pady=2, padx=(10, 0))
        
        # Vulnerability scanning options
        ttk.Label(main_frame, text="Vulnerability Options:").grid(row=4, column=0, sticky=tk.W, pady=(20, 5))
        
        vuln_frame = ttk.Frame(main_frame)
        vuln_frame.grid(row=4, column=1, sticky=(tk.W, tk.E), pady=(20, 5), padx=(10, 0))
        
        # Vulnerability types
        self.vuln_vars = {}
        vuln_types = [
            ("sql_injection", "SQL Injection"),
            ("xss", "Cross-Site Scripting (XSS)"),
            ("csrf", "Cross-Site Request Forgery (CSRF)"),
            ("lfi", "Local File Inclusion (LFI)"),
            ("open_redirect", "Open Redirect")
        ]
        
        for i, (key, name) in enumerate(vuln_types):
            var = tk.BooleanVar(value=True)
            self.vuln_vars[key] = var
            
            cb = ttk.Checkbutton(vuln_frame, text=name, variable=var)
            cb.grid(row=i, column=0, sticky=tk.W, pady=2)
        
        # Buttons
        button_frame = ttk.Frame(main_frame)
        button_frame.grid(row=5, column=0, columnspan=2, pady=(30, 0))
        
        ttk.Button(button_frame, text="Start Scan", command=self.start_scan).pack(side=tk.LEFT, padx=(0, 10))
        ttk.Button(button_frame, text="Cancel", command=self.window.destroy).pack(side=tk.LEFT)
        
    def start_scan(self):
        """Start the scan with current configuration."""
        url = self.url_entry.get().strip()
        
        if not url:
            messagebox.showerror("Error", "Please enter a target URL")
            return
        
        # Get selected modules
        modules = [key for key, var in self.module_vars.items() if var.get()]
        
        if not modules:
            messagebox.showerror("Error", "Please select at least one scan module")
            return
        
        # Get scan options
        options = {
            'threads': int(self.threads_var.get()),
            'timeout': int(self.timeout_var.get()),
            'delay': float(self.delay_var.get()),
            'user_agent': self.user_agent_var.get(),
            'vulnerability_types': [key for key, var in self.vuln_vars.items() if var.get()]
        }
        
        # Close window
        self.window.destroy()
        
        # Start scan in background
        def run_scan():
            try:
                self.on_scan_start(url, modules, options)
            except Exception as e:
                messagebox.showerror("Scan Error", f"Failed to start scan: {e}")
        
        thread = threading.Thread(target=run_scan, daemon=True)
        thread.start() 