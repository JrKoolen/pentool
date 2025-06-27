"""
Main GUI window for the Web Penetration Testing Tool.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog, scrolledtext
import threading
import json
import os
from datetime import datetime
from typing import Dict, List, Any
import queue

# Add the src directory to the Python path
import sys
sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from src.core.scanner import PenTestScanner
from src.core.utils import Logger, normalize_url
from src.gui.scan_window import ScanWindow
from src.gui.results_window import ResultsWindow
from src.gui.settings_window import SettingsWindow

class MainWindow:
    """Main application window for the penetration testing tool."""
    
    def __init__(self):
        self.root = tk.Tk()
        self.root.title("Web Penetration Testing Tool v1.0")
        self.root.geometry("1000x700")
        self.root.minsize(800, 600)
        
        # Configure style
        self.setup_styles()
        
        # Initialize variables
        self.scan_queue = queue.Queue()
        self.scan_results = {}
        self.current_scans = {}
        
        # Create GUI components
        self.create_widgets()
        self.create_menu()
        self.create_status_bar()
        
        # Set Logger callback for GUI log output
        Logger.set_gui_callback(self.append_log)
        
        # Load saved data
        self.load_saved_data()
        
        # Start background thread for scan processing
        self.scan_thread = threading.Thread(target=self.process_scan_queue, daemon=True)
        self.scan_thread.start()
    
    def setup_styles(self):
        """Configure ttk styles for a modern look."""
        style = ttk.Style()
        
        # Configure theme
        try:
            style.theme_use('clam')
        except:
            pass
        
        # Configure colors
        style.configure('Title.TLabel', font=('Arial', 16, 'bold'))
        style.configure('Heading.TLabel', font=('Arial', 12, 'bold'))
        style.configure('Success.TLabel', foreground='green')
        style.configure('Warning.TLabel', foreground='orange')
        style.configure('Error.TLabel', foreground='red')
        
        # Configure buttons
        style.configure('Action.TButton', font=('Arial', 10, 'bold'))
        style.configure('Scan.TButton', background='#4CAF50', foreground='white')
    
    def create_widgets(self):
        """Create the main GUI widgets."""
        # Main container
        main_frame = ttk.Frame(self.root, padding="10")
        main_frame.grid(row=0, column=0, sticky='nsew')
        
        # Configure grid weights
        self.root.columnconfigure(0, weight=1)
        self.root.rowconfigure(0, weight=1)
        main_frame.columnconfigure(1, weight=1)
        main_frame.rowconfigure(2, weight=1)
        
        # Title
        title_label = ttk.Label(main_frame, text="Web Penetration Testing Tool", style='Title.TLabel')
        title_label.grid(row=0, column=0, columnspan=3, pady=(0, 20))
        
        # Quick Scan Section
        self.create_quick_scan_section(main_frame)
        
        # Scan Management Section
        self.create_scan_management_section(main_frame)
        
        # Results Section
        self.create_results_section(main_frame)
        
        # Log output area at the bottom
        self.log_text = scrolledtext.ScrolledText(self.root, height=8, state='disabled', font=('Consolas', 10))
        self.log_text.grid(row=2, column=0, sticky='wes', padx=10, pady=(0, 5))
        self.root.rowconfigure(2, weight=0)
    
    def create_quick_scan_section(self, parent):
        """Create the quick scan section."""
        # Quick scan frame
        quick_frame = ttk.LabelFrame(parent, text="Quick Scan", padding="10")
        quick_frame.grid(row=1, column=0, columnspan=3, sticky='we', pady=(0, 10))
        quick_frame.columnconfigure(1, weight=1)
        
        # Target input
        ttk.Label(quick_frame, text="Target URL:").grid(row=0, column=0, sticky='w', padx=(0, 10))
        self.target_var = tk.StringVar()
        self.target_entry = ttk.Entry(quick_frame, textvariable=self.target_var, width=50)
        self.target_entry.grid(row=0, column=1, sticky='we', padx=(0, 10))
        
        # Scan button
        self.scan_button = ttk.Button(quick_frame, text="Start Scan", command=self.start_quick_scan, style='Action.TButton')
        self.scan_button.grid(row=0, column=2, padx=(0, 10))
        
        # Advanced scan button
        self.advanced_button = ttk.Button(quick_frame, text="Advanced Scan", command=self.open_advanced_scan)
        self.advanced_button.grid(row=0, column=3)
        
        # Progress bar
        self.progress_var = tk.DoubleVar()
        self.progress_bar = ttk.Progressbar(quick_frame, variable=self.progress_var, mode='indeterminate')
        self.progress_bar.grid(row=1, column=0, columnspan=4, sticky='we', pady=(10, 0))
    
    def create_scan_management_section(self, parent):
        """Create the scan management section."""
        # Scan management frame
        scan_frame = ttk.LabelFrame(parent, text="Scan Management", padding="10")
        scan_frame.grid(row=2, column=0, sticky='wens', padx=(0, 5))
        scan_frame.columnconfigure(0, weight=1)
        scan_frame.rowconfigure(1, weight=1)
        
        # Buttons
        button_frame = ttk.Frame(scan_frame)
        button_frame.grid(row=0, column=0, sticky='we', pady=(0, 10))
        
        ttk.Button(button_frame, text="Refresh", command=self.refresh_scans).pack(side='left', padx=(0, 5))
        ttk.Button(button_frame, text="Clear Completed", command=self.clear_completed_scans).pack(side='left', padx=(0, 5))
        ttk.Button(button_frame, text="Export All", command=self.export_all_results).pack(side='left')
        
        # Scan list
        list_frame = ttk.Frame(scan_frame)
        list_frame.grid(row=1, column=0, sticky='wens')
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        
        # Create Treeview for scans
        columns = ('Target', 'Status', 'Start Time', 'Duration', 'Risk Level')
        self.scan_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=10)
        
        # Configure columns
        for col in columns:
            self.scan_tree.heading(col, text=col)
            self.scan_tree.column(col, width=120)
        
        # Scrollbar
        scan_scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.scan_tree.yview)
        self.scan_tree.configure(yscrollcommand=scan_scrollbar.set)
        
        self.scan_tree.grid(row=0, column=0, sticky='wens')
        scan_scrollbar.grid(row=0, column=1, sticky='ns')
        
        # Bind double-click event
        self.scan_tree.bind('<Double-1>', self.on_scan_double_click)
        
        # Context menu
        self.create_scan_context_menu()
    
    def create_results_section(self, parent):
        """Create the results section."""
        # Results frame
        results_frame = ttk.LabelFrame(parent, text="Recent Results", padding="10")
        results_frame.grid(row=2, column=1, sticky='wens', padx=(5, 0))
        results_frame.columnconfigure(0, weight=1)
        results_frame.rowconfigure(1, weight=1)
        
        # Buttons
        button_frame = ttk.Frame(results_frame)
        button_frame.grid(row=0, column=0, sticky='we', pady=(0, 10))
        
        ttk.Button(button_frame, text="View Details", command=self.view_selected_result).pack(side='left', padx=(0, 5))
        ttk.Button(button_frame, text="Export", command=self.export_selected_result).pack(side='left', padx=(0, 5))
        ttk.Button(button_frame, text="Delete", command=self.delete_selected_result).pack(side='left')
        
        # Results list
        list_frame = ttk.Frame(results_frame)
        list_frame.grid(row=1, column=0, sticky='wens')
        list_frame.columnconfigure(0, weight=1)
        list_frame.rowconfigure(0, weight=1)
        
        # Create Treeview for results
        columns = ('Target', 'Scan Date', 'Risk Level', 'Findings')
        self.results_tree = ttk.Treeview(list_frame, columns=columns, show='headings', height=10)
        
        # Configure columns
        for col in columns:
            self.results_tree.heading(col, text=col)
            self.results_tree.column(col, width=120)
        
        # Scrollbar
        results_scrollbar = ttk.Scrollbar(list_frame, orient=tk.VERTICAL, command=self.results_tree.yview)
        self.results_tree.configure(yscrollcommand=results_scrollbar.set)
        
        self.results_tree.grid(row=0, column=0, sticky='wens')
        results_scrollbar.grid(row=0, column=1, sticky='ns')
        
        # Bind double-click event
        self.results_tree.bind('<Double-1>', self.on_result_double_click)
    
    def create_scan_context_menu(self):
        """Create context menu for scan list."""
        self.scan_context_menu = tk.Menu(self.root, tearoff=0)
        self.scan_context_menu.add_command(label="View Details", command=self.view_selected_scan)
        self.scan_context_menu.add_command(label="Stop Scan", command=self.stop_selected_scan)
        self.scan_context_menu.add_separator()
        self.scan_context_menu.add_command(label="Delete", command=self.delete_selected_scan)
        
        self.scan_tree.bind('<Button-3>', self.show_scan_context_menu)
    
    def show_scan_context_menu(self, event):
        """Show context menu for scan list."""
        try:
            self.scan_context_menu.tk_popup(event.x_root, event.y_root)
        finally:
            self.scan_context_menu.grab_release()
    
    def create_menu(self):
        """Create the main menu bar."""
        menubar = tk.Menu(self.root)
        self.root.config(menu=menubar)
        
        # File menu
        file_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="File", menu=file_menu)
        file_menu.add_command(label="Import Results", command=self.import_results)
        file_menu.add_command(label="Export All Results", command=self.export_all_results)
        file_menu.add_separator()
        file_menu.add_command(label="Exit", command=self.root.quit)
        
        # Scan menu
        scan_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Scan", menu=scan_menu)
        scan_menu.add_command(label="New Scan", command=self.open_advanced_scan)
        scan_menu.add_command(label="Batch Scan", command=self.open_batch_scan)
        scan_menu.add_separator()
        scan_menu.add_command(label="Stop All Scans", command=self.stop_all_scans)
        
        # Tools menu
        tools_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Tools", menu=tools_menu)
        tools_menu.add_command(label="Settings", command=self.open_settings)
        tools_menu.add_command(label="Wordlist Manager", command=self.open_wordlist_manager)
        
        # Help menu
        help_menu = tk.Menu(menubar, tearoff=0)
        menubar.add_cascade(label="Help", menu=help_menu)
        help_menu.add_command(label="User Guide", command=self.show_user_guide)
        help_menu.add_command(label="About", command=self.show_about)
    
    def create_status_bar(self):
        """Create the status bar."""
        self.status_var = tk.StringVar()
        self.status_var.set("Ready")
        
        status_bar = ttk.Label(self.root, textvariable=self.status_var, relief=tk.SUNKEN, anchor='w')
        status_bar.grid(row=1, column=0, sticky='we')
    
    def start_quick_scan(self):
        """Start a quick scan with default settings."""
        target = self.target_var.get().strip()
        
        if not target:
            messagebox.showerror("Error", "Please enter a target URL")
            return
        
        # Validate target
        try:
            target = normalize_url(target)
        except Exception as e:
            messagebox.showerror("Error", f"Invalid target URL: {e}")
            return
        
        # Add to scan queue
        scan_id = f"scan_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
        scan_info = {
            'id': scan_id,
            'target': target,
            'modules': ['domain_info', 'directory_enum'],
            'threads': 10,
            'timeout': 10
        }
        
        self.scan_queue.put(scan_info)
        self.update_status(f"Queued scan for {target}")
        
        # Clear target entry
        self.target_var.set("")
    
    def open_advanced_scan(self):
        """Open the advanced scan window."""
        ScanWindow(self.root, self.scan_queue)
    
    def open_batch_scan(self):
        """Open batch scan window (placeholder)."""
        messagebox.showinfo("Info", "Batch scan feature coming soon!")
    
    def open_settings(self):
        """Open settings window."""
        SettingsWindow(self.root)
    
    def open_wordlist_manager(self):
        """Open wordlist manager (placeholder)."""
        messagebox.showinfo("Info", "Wordlist manager feature coming soon!")
    
    def process_scan_queue(self):
        """Background thread to process scan queue."""
        while True:
            try:
                scan_info = self.scan_queue.get(timeout=1)
                self.run_scan(scan_info)
            except queue.Empty:
                continue
            except Exception as e:
                Logger.error(f"Error processing scan: {e}")
    
    def run_scan(self, scan_info):
        """Run a scan in background thread."""
        scan_id = scan_info['id']
        target = scan_info['target']
        
        # Update UI
        self.root.after(0, lambda: self.add_scan_to_list(scan_id, target, "Running"))
        self.root.after(0, lambda: self.progress_bar.start())
        
        try:
            # Run the scan
            scanner = PenTestScanner()
            results = scanner.run_full_scan(target, scan_info['modules'])
            
            # Store results
            self.scan_results[scan_id] = results
            
            # Update UI
            self.root.after(0, lambda: self.update_scan_status(scan_id, "Completed", results))
            self.root.after(0, lambda: self.add_result_to_list(scan_id, results))
            self.root.after(0, lambda: self.progress_bar.stop())
            self.root.after(0, lambda: self.update_status(f"Scan completed for {target}"))
            
        except Exception as e:
            # Update UI with error
            self.root.after(0, lambda: self.update_scan_status(scan_id, "Failed", None))
            self.root.after(0, lambda: self.progress_bar.stop())
            self.root.after(0, lambda: self.update_status(f"Scan failed for {target}: {e}"))
            Logger.error(f"Scan failed: {e}")
    
    def add_scan_to_list(self, scan_id, target, status):
        """Add a scan to the scan list."""
        start_time = datetime.now().strftime("%H:%M:%S")
        self.scan_tree.insert('', 'end', scan_id, values=(target, status, start_time, "", ""))
    
    def update_scan_status(self, scan_id, status, results):
        """Update scan status in the list."""
        item = self.scan_tree.item(scan_id)
        values = list(item['values'])
        values[1] = status
        
        if results and 'summary' in results:
            values[4] = results['summary'].get('risk_level', 'Unknown').upper()
        
        self.scan_tree.item(scan_id, values=values)
    
    def add_result_to_list(self, scan_id, results):
        """Add a result to the results list."""
        target = results['scan_info']['target']
        scan_date = datetime.now().strftime("%Y-%m-%d %H:%M")
        risk_level = results['summary'].get('risk_level', 'Unknown').upper()
        findings = results['summary'].get('total_findings', 0)
        
        self.results_tree.insert('', 0, scan_id, values=(target, scan_date, risk_level, findings))
    
    def refresh_scans(self):
        """Refresh the scan list."""
        # This would reload from saved data
        pass
    
    def clear_completed_scans(self):
        """Clear completed scans from the list."""
        items_to_remove = []
        for item in self.scan_tree.get_children():
            values = self.scan_tree.item(item)['values']
            if values[1] in ['Completed', 'Failed']:
                items_to_remove.append(item)
        
        for item in items_to_remove:
            self.scan_tree.delete(item)
    
    def export_all_results(self):
        """Export all results to a file."""
        if not self.scan_results:
            messagebox.showinfo("Info", "No results to export")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    json.dump(self.scan_results, f, indent=4, default=str)
                messagebox.showinfo("Success", f"Results exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export results: {e}")
    
    def import_results(self):
        """Import results from a file."""
        filename = filedialog.askopenfilename(
            filetypes=[("JSON files", "*.json"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                with open(filename, 'r') as f:
                    imported_results = json.load(f)
                
                # Merge with existing results
                self.scan_results.update(imported_results)
                self.refresh_results_list()
                messagebox.showinfo("Success", f"Results imported from {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to import results: {e}")
    
    def refresh_results_list(self):
        """Refresh the results list."""
        # Clear existing items
        for item in self.results_tree.get_children():
            self.results_tree.delete(item)
        
        # Add all results
        for scan_id, results in self.scan_results.items():
            self.add_result_to_list(scan_id, results)
    
    def on_scan_double_click(self, event):
        """Handle double-click on scan item."""
        self.view_selected_scan()
    
    def on_result_double_click(self, event):
        """Handle double-click on result item."""
        self.view_selected_result()
    
    def view_selected_scan(self):
        """View details of selected scan."""
        selection = self.scan_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "Please select a scan to view")
            return
        
        scan_id = selection[0]
        if scan_id in self.scan_results:
            ResultsWindow(self.root, self.scan_results[scan_id])
        else:
            messagebox.showinfo("Info", "Scan results not available yet")
    
    def view_selected_result(self):
        """View details of selected result."""
        selection = self.results_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "Please select a result to view")
            return
        
        scan_id = selection[0]
        if scan_id in self.scan_results:
            ResultsWindow(self.root, self.scan_results[scan_id])
        else:
            messagebox.showinfo("Info", "Result not found")
    
    def export_selected_result(self):
        """Export selected result."""
        selection = self.results_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "Please select a result to export")
            return
        
        scan_id = selection[0]
        if scan_id not in self.scan_results:
            messagebox.showinfo("Info", "Result not found")
            return
        
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("JSON files", "*.json"), ("Text files", "*.txt"), ("All files", "*.*")]
        )
        
        if filename:
            try:
                results = self.scan_results[scan_id]
                if filename.endswith('.json'):
                    with open(filename, 'w') as f:
                        json.dump(results, f, indent=4, default=str)
                else:
                    # Export as text
                    with open(filename, 'w') as f:
                        f.write(self.format_results_as_text(results))
                
                messagebox.showinfo("Success", f"Result exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export result: {e}")
    
    def delete_selected_result(self):
        """Delete selected result."""
        selection = self.results_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "Please select a result to delete")
            return
        
        scan_id = selection[0]
        if messagebox.askyesno("Confirm", "Are you sure you want to delete this result?"):
            self.results_tree.delete(scan_id)
            if scan_id in self.scan_results:
                del self.scan_results[scan_id]
    
    def stop_selected_scan(self):
        """Stop selected scan (placeholder)."""
        messagebox.showinfo("Info", "Stop scan feature coming soon!")
    
    def delete_selected_scan(self):
        """Delete selected scan."""
        selection = self.scan_tree.selection()
        if not selection:
            messagebox.showinfo("Info", "Please select a scan to delete")
            return
        
        scan_id = selection[0]
        if messagebox.askyesno("Confirm", "Are you sure you want to delete this scan?"):
            self.scan_tree.delete(scan_id)
    
    def stop_all_scans(self):
        """Stop all running scans."""
        if messagebox.askyesno("Confirm", "Are you sure you want to stop all scans?"):
            # Clear scan queue
            while not self.scan_queue.empty():
                try:
                    self.scan_queue.get_nowait()
                except queue.Empty:
                    break
            
            # Update all running scans to stopped
            for item in self.scan_tree.get_children():
                values = self.scan_tree.item(item)['values']
                if values[1] == "Running":
                    self.scan_tree.item(item, values=(values[0], "Stopped", values[2], values[3], values[4]))
            
            self.progress_bar.stop()
            self.update_status("All scans stopped")
    
    def show_user_guide(self):
        """Show user guide (placeholder)."""
        messagebox.showinfo("User Guide", "User guide feature coming soon!")
    
    def show_about(self):
        """Show about dialog."""
        about_text = """Web Penetration Testing Tool v1.0

A comprehensive web application penetration testing tool with advanced information gathering and vulnerability assessment capabilities.

Features:
• Domain information gathering
• Directory and file enumeration
• Technology fingerprinting
• Security configuration analysis
• Risk assessment and reporting

For authorized security testing only.
Always ensure you have proper permission before testing any website."""
        
        messagebox.showinfo("About", about_text)
    
    def format_results_as_text(self, results):
        """Format results as text for export."""
        text = []
        text.append("PENETRATION TEST REPORT")
        text.append("=" * 50)
        text.append(f"Target: {results['scan_info']['target']}")
        text.append(f"Date: {results['scan_info']['start_time']}")
        text.append(f"Duration: {results['scan_info']['duration']}")
        text.append("")
        
        if 'summary' in results:
            summary = results['summary']
            text.append("SUMMARY:")
            text.append("-" * 20)
            text.append(f"Risk Level: {summary.get('risk_level', 'Unknown')}")
            text.append(f"Total Findings: {summary.get('total_findings', 0)}")
            text.append(f"Critical: {summary.get('critical_findings', 0)}")
            text.append(f"High: {summary.get('high_findings', 0)}")
            text.append(f"Medium: {summary.get('medium_findings', 0)}")
            text.append(f"Low: {summary.get('low_findings', 0)}")
            text.append("")
        
        return "\n".join(text)
    
    def update_status(self, message):
        """Update status bar message."""
        self.status_var.set(message)
    
    def load_saved_data(self):
        """Load saved scan data."""
        # This would load from a saved file
        pass
    
    def save_data(self):
        """Save scan data."""
        # This would save to a file
        pass
    
    def append_log(self, message):
        """Append a log message to the log output area."""
        def do_append():
            self.log_text.configure(state='normal')
            self.log_text.insert(tk.END, message + '\n')
            self.log_text.see(tk.END)
            self.log_text.configure(state='disabled')
        self.root.after(0, do_append)
    
    def run(self):
        """Start the GUI application."""
        self.root.mainloop()

def main():
    """Main function to start the GUI."""
    app = MainWindow()
    app.run()

if __name__ == "__main__":
    main() 