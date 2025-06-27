"""
Settings configuration window.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import json
import os

class SettingsWindow:
    """Settings configuration window."""
    
    def __init__(self, parent):
        self.parent = parent
        
        # Create window
        self.window = tk.Toplevel(parent)
        self.window.title("Settings")
        self.window.geometry("600x500")
        self.window.minsize(500, 400)
        
        # Make window modal
        self.window.transient(parent)
        self.window.grab_set()
        
        # Center window
        self.center_window()
        
        # Load current settings
        self.load_current_settings()
        
        # Create widgets
        self.create_widgets()
        
        # Focus on window
        self.window.focus_set()
    
    def center_window(self):
        """Center the window on screen."""
        self.window.update_idletasks()
        width = self.window.winfo_width()
        height = self.window.winfo_height()
        x = (self.window.winfo_screenwidth() // 2) - (width // 2)
        y = (self.window.winfo_screenheight() // 2) - (height // 2)
        self.window.geometry(f"{width}x{height}+{x}+{y}")
    
    def load_current_settings(self):
        """Load current settings from config."""
        try:
            from src.core.config import config
            self.current_settings = {
                'timeout': config.get('scanning.timeout', 10),
                'max_threads': config.get('scanning.max_threads', 10),
                'user_agent': config.get('scanning.user_agent', ''),
                'verify_ssl': config.get('scanning.verify_ssl', False),
                'follow_redirects': config.get('scanning.follow_redirects', True),
                'output_dir': config.get('reporting.output_dir', 'reports'),
                'include_timestamps': config.get('reporting.include_timestamps', True),
                'shodan_key': config.get('api_keys.shodan', ''),
                'censys_key': config.get('api_keys.censys', ''),
                'virustotal_key': config.get('api_keys.virustotal', '')
            }
        except Exception as e:
            messagebox.showerror("Error", f"Failed to load settings: {e}")
            self.current_settings = {}
    
    def create_widgets(self):
        """Create the window widgets."""
        # Main container
        main_frame = ttk.Frame(self.window, padding="20")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Title
        title_label = ttk.Label(main_frame, text="Settings", style='Title.TLabel')
        title_label.pack(pady=(0, 20))
        
        # Create notebook for tabs
        self.notebook = ttk.Notebook(main_frame)
        self.notebook.pack(fill=tk.BOTH, expand=True, pady=(0, 20))
        
        # Scanning settings tab
        self.create_scanning_tab()
        
        # Reporting settings tab
        self.create_reporting_tab()
        
        # API keys tab
        self.create_api_keys_tab()
        
        # Buttons
        self.create_buttons(main_frame)
    
    def create_scanning_tab(self):
        """Create scanning settings tab."""
        scan_frame = ttk.Frame(self.notebook, padding="20")
        self.notebook.add(scan_frame, text="Scanning")
        
        # Timeout
        ttk.Label(scan_frame, text="Request Timeout (seconds):").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.timeout_var = tk.IntVar(value=self.current_settings.get('timeout', 10))
        timeout_spinbox = ttk.Spinbox(scan_frame, from_=5, to=60, textvariable=self.timeout_var, width=10)
        timeout_spinbox.grid(row=0, column=1, sticky=tk.W, pady=(0, 10))
        
        # Max threads
        ttk.Label(scan_frame, text="Maximum Threads:").grid(row=1, column=0, sticky=tk.W, padx=(0, 10))
        self.threads_var = tk.IntVar(value=self.current_settings.get('max_threads', 10))
        threads_spinbox = ttk.Spinbox(scan_frame, from_=1, to=50, textvariable=self.threads_var, width=10)
        threads_spinbox.grid(row=1, column=1, sticky=tk.W, pady=(0, 10))
        
        # User agent
        ttk.Label(scan_frame, text="User Agent:").grid(row=2, column=0, sticky=tk.W, padx=(0, 10))
        self.user_agent_var = tk.StringVar(value=self.current_settings.get('user_agent', ''))
        user_agent_entry = ttk.Entry(scan_frame, textvariable=self.user_agent_var, width=50)
        user_agent_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # SSL verification
        self.verify_ssl_var = tk.BooleanVar(value=self.current_settings.get('verify_ssl', False))
        ssl_checkbox = ttk.Checkbutton(scan_frame, text="Verify SSL Certificates", variable=self.verify_ssl_var)
        ssl_checkbox.grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=(0, 10))
        
        # Follow redirects
        self.follow_redirects_var = tk.BooleanVar(value=self.current_settings.get('follow_redirects', True))
        redirect_checkbox = ttk.Checkbutton(scan_frame, text="Follow Redirects", variable=self.follow_redirects_var)
        redirect_checkbox.grid(row=4, column=0, columnspan=2, sticky=tk.W, pady=(0, 10))
        
        # Configure grid
        scan_frame.columnconfigure(1, weight=1)
    
    def create_reporting_tab(self):
        """Create reporting settings tab."""
        report_frame = ttk.Frame(self.notebook, padding="20")
        self.notebook.add(report_frame, text="Reporting")
        
        # Output directory
        ttk.Label(report_frame, text="Output Directory:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.output_dir_var = tk.StringVar(value=self.current_settings.get('output_dir', 'reports'))
        output_dir_entry = ttk.Entry(report_frame, textvariable=self.output_dir_var, width=40)
        output_dir_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Browse button
        browse_button = ttk.Button(report_frame, text="Browse", command=self.browse_output_dir)
        browse_button.grid(row=0, column=2, padx=(10, 0), pady=(0, 10))
        
        # Include timestamps
        self.include_timestamps_var = tk.BooleanVar(value=self.current_settings.get('include_timestamps', True))
        timestamp_checkbox = ttk.Checkbutton(report_frame, text="Include Timestamps in Reports", variable=self.include_timestamps_var)
        timestamp_checkbox.grid(row=1, column=0, columnspan=3, sticky=tk.W, pady=(0, 10))
        
        # Configure grid
        report_frame.columnconfigure(1, weight=1)
    
    def create_api_keys_tab(self):
        """Create API keys settings tab."""
        api_frame = ttk.Frame(self.notebook, padding="20")
        self.notebook.add(api_frame, text="API Keys")
        
        # Shodan API key
        ttk.Label(api_frame, text="Shodan API Key:").grid(row=0, column=0, sticky=tk.W, padx=(0, 10))
        self.shodan_key_var = tk.StringVar(value=self.current_settings.get('shodan_key', ''))
        shodan_entry = ttk.Entry(api_frame, textvariable=self.shodan_key_var, width=50, show="*")
        shodan_entry.grid(row=0, column=1, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Censys API key
        ttk.Label(api_frame, text="Censys API Key:").grid(row=1, column=0, sticky=tk.W, padx=(0, 10))
        self.censys_key_var = tk.StringVar(value=self.current_settings.get('censys_key', ''))
        censys_entry = ttk.Entry(api_frame, textvariable=self.censys_key_var, width=50, show="*")
        censys_entry.grid(row=1, column=1, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # VirusTotal API key
        ttk.Label(api_frame, text="VirusTotal API Key:").grid(row=2, column=0, sticky=tk.W, padx=(0, 10))
        self.virustotal_key_var = tk.StringVar(value=self.current_settings.get('virustotal_key', ''))
        virustotal_entry = ttk.Entry(api_frame, textvariable=self.virustotal_key_var, width=50, show="*")
        virustotal_entry.grid(row=2, column=1, sticky=(tk.W, tk.E), pady=(0, 10))
        
        # Note about API keys
        note_label = ttk.Label(api_frame, text="Note: API keys are stored locally and used for enhanced reconnaissance capabilities.", 
                              style='Info.TLabel')
        note_label.grid(row=3, column=0, columnspan=2, sticky=tk.W, pady=(20, 0))
        
        # Configure grid
        api_frame.columnconfigure(1, weight=1)
    
    def create_buttons(self, parent):
        """Create action buttons."""
        button_frame = ttk.Frame(parent)
        button_frame.pack(fill=tk.X)
        
        # Save button
        save_button = ttk.Button(button_frame, text="Save Settings", command=self.save_settings, style='Action.TButton')
        save_button.pack(side=tk.RIGHT, padx=(10, 0))
        
        # Cancel button
        cancel_button = ttk.Button(button_frame, text="Cancel", command=self.window.destroy)
        cancel_button.pack(side=tk.RIGHT)
        
        # Reset to defaults button
        reset_button = ttk.Button(button_frame, text="Reset to Defaults", command=self.reset_to_defaults)
        reset_button.pack(side=tk.LEFT)
    
    def browse_output_dir(self):
        """Browse for output directory."""
        from tkinter import filedialog
        directory = filedialog.askdirectory(initialdir=self.output_dir_var.get())
        if directory:
            self.output_dir_var.set(directory)
    
    def save_settings(self):
        """Save current settings."""
        try:
            from src.core.config import config
            
            # Update scanning settings
            config.set('scanning.timeout', self.timeout_var.get())
            config.set('scanning.max_threads', self.threads_var.get())
            config.set('scanning.user_agent', self.user_agent_var.get())
            config.set('scanning.verify_ssl', self.verify_ssl_var.get())
            config.set('scanning.follow_redirects', self.follow_redirects_var.get())
            
            # Update reporting settings
            config.set('reporting.output_dir', self.output_dir_var.get())
            config.set('reporting.include_timestamps', self.include_timestamps_var.get())
            
            # Update API keys
            config.set('api_keys.shodan', self.shodan_key_var.get())
            config.set('api_keys.censys', self.censys_key_var.get())
            config.set('api_keys.virustotal', self.virustotal_key_var.get())
            
            messagebox.showinfo("Success", "Settings saved successfully!")
            self.window.destroy()
            
        except Exception as e:
            messagebox.showerror("Error", f"Failed to save settings: {e}")
    
    def reset_to_defaults(self):
        """Reset all settings to defaults."""
        if messagebox.askyesno("Confirm", "Are you sure you want to reset all settings to defaults?"):
            # Reset scanning settings
            self.timeout_var.set(10)
            self.threads_var.set(10)
            self.user_agent_var.set('Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
            self.verify_ssl_var.set(False)
            self.follow_redirects_var.set(True)
            
            # Reset reporting settings
            self.output_dir_var.set('reports')
            self.include_timestamps_var.set(True)
            
            # Reset API keys
            self.shodan_key_var.set('')
            self.censys_key_var.set('')
            self.virustotal_key_var.set('')
            
            messagebox.showinfo("Reset", "Settings have been reset to defaults.") 