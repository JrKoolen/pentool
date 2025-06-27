"""
Results viewer window for displaying scan results.
"""

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import json
from typing import Dict, Any
from datetime import datetime

class ResultsWindow:
    """Results viewer window."""
    
    def __init__(self, parent, results):
        self.parent = parent
        self.results = results
        
        # Create window
        self.window = tk.Toplevel(parent)
        self.window.title(f"Scan Results - {results['scan_info']['target']}")
        self.window.geometry("900x700")
        self.window.minsize(800, 600)
        
        # Make window modal
        self.window.transient(parent)
        self.window.grab_set()
        
        # Center window
        self.center_window()
        
        # Create widgets
        self.create_widgets()
        
        # Load results
        self.load_results()
        
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
    
    def create_widgets(self):
        """Create the window widgets."""
        # Main container
        main_frame = ttk.Frame(self.window, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Configure grid
        main_frame.columnconfigure(0, weight=1)
        main_frame.rowconfigure(1, weight=1)
        
        # Header
        self.create_header(main_frame)
        
        # Content area
        self.create_content_area(main_frame)
        
        # Footer
        self.create_footer(main_frame)
    
    def create_header(self, parent):
        """Create the header section."""
        header_frame = ttk.Frame(parent)
        header_frame.grid(row=0, column=0, sticky=(tk.W, tk.E), pady=(0, 10))
        header_frame.columnconfigure(1, weight=1)
        
        # Title
        title_label = ttk.Label(header_frame, text="Scan Results", style='Title.TLabel')
        title_label.grid(row=0, column=0, columnspan=2, sticky=tk.W, pady=(0, 10))
        
        # Target info
        target = self.results['scan_info']['target']
        target_label = ttk.Label(header_frame, text=f"Target: {target}", style='Heading.TLabel')
        target_label.grid(row=1, column=0, sticky=tk.W)
        
        # Risk level
        if 'summary' in self.results:
            risk_level = self.results['summary'].get('risk_level', 'Unknown').upper()
            risk_label = ttk.Label(header_frame, text=f"Risk Level: {risk_level}", style='Heading.TLabel')
            risk_label.grid(row=1, column=1, sticky=tk.E)
        
        # Scan info
        scan_date = self.results['scan_info'].get('start_time', 'Unknown')
        duration = self.results['scan_info'].get('duration', 'Unknown')
        info_label = ttk.Label(header_frame, text=f"Date: {scan_date} | Duration: {duration}")
        info_label.grid(row=2, column=0, columnspan=2, sticky=tk.W, pady=(5, 0))
    
    def create_content_area(self, parent):
        """Create the main content area."""
        # Notebook for tabs
        self.notebook = ttk.Notebook(parent)
        self.notebook.grid(row=1, column=0, sticky=(tk.W, tk.E, tk.N, tk.S), pady=(0, 10))
        
        # Summary tab
        self.create_summary_tab()
        
        # Domain Info tab
        self.create_domain_info_tab()
        
        # Port Scan tab (NEW)
        self.create_port_scan_tab()
        
        # Security Headers tab (NEW)
        self.create_security_headers_tab()
        
        # Directory Enum tab
        self.create_directory_enum_tab()
        
        # Vulnerabilities tab
        self.create_vulnerabilities_tab()
        
        # Raw Data tab
        self.create_raw_data_tab()
    
    def create_summary_tab(self):
        """Create the summary tab."""
        summary_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(summary_frame, text="Summary")
        
        # Summary content
        if 'summary' in self.results:
            summary = self.results['summary']
            
            # Findings breakdown
            findings_frame = ttk.LabelFrame(summary_frame, text="Findings Breakdown", padding="10")
            findings_frame.pack(fill=tk.X, pady=(0, 10))
            
            findings_text = f"""
Risk Level: {summary.get('risk_level', 'Unknown').upper()}
Total Findings: {summary.get('total_findings', 0)}
Critical: {summary.get('critical_findings', 0)}
High: {summary.get('high_findings', 0)}
Medium: {summary.get('medium_findings', 0)}
Low: {summary.get('low_findings', 0)}
            """
            
            findings_label = ttk.Label(findings_frame, text=findings_text, justify=tk.LEFT)
            findings_label.pack(anchor=tk.W)
            
            # Recommendations
            if summary.get('recommendations'):
                rec_frame = ttk.LabelFrame(summary_frame, text="Recommendations", padding="10")
                rec_frame.pack(fill=tk.BOTH, expand=True)
                
                rec_text = "\n".join([f"{i+1}. {rec}" for i, rec in enumerate(summary['recommendations'])])
                rec_text_widget = tk.Text(rec_frame, wrap=tk.WORD, height=10)
                rec_text_widget.insert(tk.END, rec_text)
                rec_text_widget.config(state=tk.DISABLED)
                
                rec_scrollbar = ttk.Scrollbar(rec_frame, orient=tk.VERTICAL, command=rec_text_widget.yview)
                rec_text_widget.configure(yscrollcommand=rec_scrollbar.set)
                
                rec_text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
                rec_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_domain_info_tab(self):
        """Create the domain information tab."""
        domain_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(domain_frame, text="Domain Info")
        
        if 'domain_info' not in self.results:
            ttk.Label(domain_frame, text="No domain information available").pack()
            return
        
        domain_info = self.results['domain_info']
        
        # Create scrollable frame
        canvas = tk.Canvas(domain_frame)
        scrollbar = ttk.Scrollbar(domain_frame, orient=tk.VERTICAL, command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # WHOIS Information
        if domain_info.get('whois_info'):
            whois_frame = ttk.LabelFrame(scrollable_frame, text="WHOIS Information", padding="10")
            whois_frame.pack(fill=tk.X, pady=(0, 10))
            
            whois_text = self.format_dict(domain_info['whois_info'])
            whois_text_widget = tk.Text(whois_frame, wrap=tk.WORD, height=8)
            whois_text_widget.insert(tk.END, whois_text)
            whois_text_widget.config(state=tk.DISABLED)
            whois_text_widget.pack(fill=tk.X)
        
        # DNS Records
        if domain_info.get('dns_records'):
            dns_frame = ttk.LabelFrame(scrollable_frame, text="DNS Records", padding="10")
            dns_frame.pack(fill=tk.X, pady=(0, 10))
            
            dns_text = self.format_dict(domain_info['dns_records'])
            dns_text_widget = tk.Text(dns_frame, wrap=tk.WORD, height=8)
            dns_text_widget.insert(tk.END, dns_text)
            dns_text_widget.config(state=tk.DISABLED)
            dns_text_widget.pack(fill=tk.X)
        
        # IP Information
        if domain_info.get('ip_info'):
            ip_frame = ttk.LabelFrame(scrollable_frame, text="IP Information", padding="10")
            ip_frame.pack(fill=tk.X, pady=(0, 10))
            
            ip_text = self.format_dict(domain_info['ip_info'])
            ip_text_widget = tk.Text(ip_frame, wrap=tk.WORD, height=6)
            ip_text_widget.insert(tk.END, ip_text)
            ip_text_widget.config(state=tk.DISABLED)
            ip_text_widget.pack(fill=tk.X)
        
        # Open Ports
        if domain_info.get('ports'):
            ports_frame = ttk.LabelFrame(scrollable_frame, text="Open Ports", padding="10")
            ports_frame.pack(fill=tk.X, pady=(0, 10))
            
            ports_text = self.format_dict(domain_info['ports'])
            ports_text_widget = tk.Text(ports_frame, wrap=tk.WORD, height=4)
            ports_text_widget.insert(tk.END, ports_text)
            ports_text_widget.config(state=tk.DISABLED)
            ports_text_widget.pack(fill=tk.X)
        
        # Technologies
        if domain_info.get('technologies'):
            tech_frame = ttk.LabelFrame(scrollable_frame, text="Technologies", padding="10")
            tech_frame.pack(fill=tk.X, pady=(0, 10))
            
            tech_text = self.format_dict(domain_info['technologies'])
            tech_text_widget = tk.Text(tech_frame, wrap=tk.WORD, height=6)
            tech_text_widget.insert(tk.END, tech_text)
            tech_text_widget.config(state=tk.DISABLED)
            tech_text_widget.pack(fill=tk.X)
        
        # Pack canvas and scrollbar
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_port_scan_tab(self):
        """Create the port scanning tab."""
        port_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(port_frame, text="Port Scan")
        
        if 'port_scan' not in self.results:
            ttk.Label(port_frame, text="No port scan results available").pack()
            return
        
        port_scan = self.results['port_scan']
        
        # Scan summary
        if 'scan_summary' in port_scan:
            summary_frame = ttk.LabelFrame(port_frame, text="Scan Summary", padding="10")
            summary_frame.pack(fill=tk.X, pady=(0, 10))
            
            summary = port_scan['scan_summary']
            summary_text = f"""
Target: {port_scan.get('target', 'Unknown')}
Total Ports Scanned: {summary.get('total_ports_scanned', 0)}
Open Ports Found: {summary.get('open_ports_found', 0)}
Scan Duration: {summary.get('scan_duration', 0)} seconds
Ports per Second: {summary.get('ports_per_second', 0)}
            """
            
            summary_label = ttk.Label(summary_frame, text=summary_text, justify=tk.LEFT)
            summary_label.pack(anchor=tk.W)
        
        # Open ports
        if 'open_ports' in port_scan and port_scan['open_ports']:
            ports_frame = ttk.LabelFrame(port_frame, text="Open Ports", padding="10")
            ports_frame.pack(fill=tk.BOTH, expand=True)
            
            # Create treeview for ports
            columns = ('Port', 'Service', 'Banner', 'Protocol')
            ports_tree = ttk.Treeview(ports_frame, columns=columns, show='headings', height=15)
            
            # Configure columns
            for col in columns:
                ports_tree.heading(col, text=col)
                ports_tree.column(col, width=150)
            
            # Add data
            for port, info in port_scan['open_ports'].items():
                ports_tree.insert('', tk.END, values=(
                    port,
                    info.get('service', 'Unknown'),
                    info.get('banner', 'No banner')[:50] + '...' if info.get('banner') and len(info.get('banner', '')) > 50 else info.get('banner', 'No banner'),
                    info.get('protocol', 'TCP')
                ))
            
            # Scrollbar
            ports_scrollbar = ttk.Scrollbar(ports_frame, orient=tk.VERTICAL, command=ports_tree.yview)
            ports_tree.configure(yscrollcommand=ports_scrollbar.set)
            
            ports_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            ports_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        else:
            ttk.Label(port_frame, text="No open ports found").pack()
    
    def create_security_headers_tab(self):
        """Create the security headers analysis tab."""
        headers_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(headers_frame, text="Security Headers")
        
        if 'security_headers' not in self.results:
            ttk.Label(headers_frame, text="No security headers analysis available").pack()
            return
        
        sec_headers = self.results['security_headers']
        
        # Security score
        if 'security_score' in sec_headers:
            score_frame = ttk.LabelFrame(headers_frame, text="Security Score", padding="10")
            score_frame.pack(fill=tk.X, pady=(0, 10))
            
            score = sec_headers['security_score']
            score_text = f"Overall Security Score: {score}%"
            
            # Color code the score
            if score >= 80:
                score_label = ttk.Label(score_frame, text=score_text, foreground='green', font=('Arial', 12, 'bold'))
            elif score >= 60:
                score_label = ttk.Label(score_frame, text=score_text, foreground='orange', font=('Arial', 12, 'bold'))
            else:
                score_label = ttk.Label(score_frame, text=score_text, foreground='red', font=('Arial', 12, 'bold'))
            
            score_label.pack(anchor=tk.W)
        
        # Headers analysis
        if 'headers_analysis' in sec_headers:
            headers_analysis_frame = ttk.LabelFrame(headers_frame, text="Headers Analysis", padding="10")
            headers_analysis_frame.pack(fill=tk.BOTH, expand=True)
            
            # Create treeview for headers
            columns = ('Header', 'Status', 'Score', 'Value', 'Severity')
            headers_tree = ttk.Treeview(headers_analysis_frame, columns=columns, show='headings', height=12)
            
            # Configure columns
            for col in columns:
                headers_tree.heading(col, text=col)
                headers_tree.column(col, width=120)
            
            # Add data
            for header_name, analysis in sec_headers['headers_analysis'].items():
                status = "✓ Present" if analysis.get('present') else "✗ Missing"
                score = f"{analysis.get('score', 0)}%"
                value = analysis.get('value', 'Not present')[:30] + '...' if analysis.get('value') and len(analysis.get('value', '')) > 30 else analysis.get('value', 'Not present')
                severity = analysis.get('severity', 'Unknown')
                
                headers_tree.insert('', tk.END, values=(
                    header_name,
                    status,
                    score,
                    value,
                    severity
                ))
            
            # Scrollbar
            headers_scrollbar = ttk.Scrollbar(headers_analysis_frame, orient=tk.VERTICAL, command=headers_tree.yview)
            headers_tree.configure(yscrollcommand=headers_scrollbar.set)
            
            headers_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            headers_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        
        # Recommendations
        if 'recommendations' in sec_headers and sec_headers['recommendations']:
            rec_frame = ttk.LabelFrame(headers_frame, text="Recommendations", padding="10")
            rec_frame.pack(fill=tk.X, pady=(10, 0))
            
            rec_text = "\n".join([f"• {rec}" for rec in sec_headers['recommendations']])
            rec_text_widget = tk.Text(rec_frame, wrap=tk.WORD, height=6)
            rec_text_widget.insert(tk.END, rec_text)
            rec_text_widget.config(state=tk.DISABLED)
            
            rec_scrollbar = ttk.Scrollbar(rec_frame, orient=tk.VERTICAL, command=rec_text_widget.yview)
            rec_text_widget.configure(yscrollcommand=rec_scrollbar.set)
            
            rec_text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            rec_scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_directory_enum_tab(self):
        """Create the directory enumeration tab."""
        enum_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(enum_frame, text="Directory Enum")
        
        if 'directory_enum' not in self.results:
            ttk.Label(enum_frame, text="No directory enumeration results available").pack()
            return
        
        dir_enum = self.results['directory_enum']
        
        # Create scrollable frame
        canvas = tk.Canvas(enum_frame)
        scrollbar = ttk.Scrollbar(enum_frame, orient=tk.VERTICAL, command=canvas.yview)
        scrollable_frame = ttk.Frame(canvas)
        
        scrollable_frame.bind(
            "<Configure>",
            lambda e: canvas.configure(scrollregion=canvas.bbox("all"))
        )
        
        canvas.create_window((0, 0), window=scrollable_frame, anchor="nw")
        canvas.configure(yscrollcommand=scrollbar.set)
        
        # Directories found
        if dir_enum.get('directories'):
            dirs_frame = ttk.LabelFrame(scrollable_frame, text="Directories Found", padding="10")
            dirs_frame.pack(fill=tk.X, pady=(0, 10))
            
            # Create treeview for directories
            columns = ('URL', 'Status', 'Size', 'Server')
            dir_tree = ttk.Treeview(dirs_frame, columns=columns, show='headings', height=8)
            
            for col in columns:
                dir_tree.heading(col, text=col)
                dir_tree.column(col, width=150)
            
            for directory in dir_enum['directories']:
                dir_tree.insert('', 'end', values=(
                    directory.get('url', ''),
                    directory.get('status_code', ''),
                    directory.get('content_length', ''),
                    directory.get('server', '')
                ))
            
            dir_tree.pack(fill=tk.X)
        
        # Files found
        if dir_enum.get('files'):
            files_frame = ttk.LabelFrame(scrollable_frame, text="Files Found", padding="10")
            files_frame.pack(fill=tk.X, pady=(0, 10))
            
            # Create treeview for files
            columns = ('URL', 'Status', 'Size')
            file_tree = ttk.Treeview(files_frame, columns=columns, show='headings', height=6)
            
            for col in columns:
                file_tree.heading(col, text=col)
                file_tree.column(col, width=200)
            
            for file_item in dir_enum['files']:
                file_tree.insert('', 'end', values=(
                    file_item.get('url', ''),
                    file_item.get('status_code', ''),
                    file_item.get('content_length', '')
                ))
            
            file_tree.pack(fill=tk.X)
        
        # Backup files
        if dir_enum.get('backup_files'):
            backup_frame = ttk.LabelFrame(scrollable_frame, text="Backup Files (High Risk)", padding="10")
            backup_frame.pack(fill=tk.X, pady=(0, 10))
            
            backup_text = ""
            for backup in dir_enum['backup_files']:
                backup_text += f"URL: {backup.get('url', '')}\n"
                backup_text += f"Extension: {backup.get('extension', '')}\n"
                backup_text += f"Size: {backup.get('content_length', '')}\n"
                backup_text += "-" * 50 + "\n"
            
            backup_text_widget = tk.Text(backup_frame, wrap=tk.WORD, height=6)
            backup_text_widget.insert(tk.END, backup_text)
            backup_text_widget.config(state=tk.DISABLED)
            backup_text_widget.pack(fill=tk.X)
        
        # Interesting findings
        if dir_enum.get('interesting_findings'):
            interesting_frame = ttk.LabelFrame(scrollable_frame, text="Interesting Findings", padding="10")
            interesting_frame.pack(fill=tk.X, pady=(0, 10))
            
            interesting_text = ""
            for finding in dir_enum['interesting_findings']:
                interesting_text += f"URL: {finding.get('url', '')}\n"
                interesting_text += f"Type: {finding.get('type', '')}\n"
                interesting_text += f"Status: {finding.get('status_code', '')}\n"
                interesting_text += "-" * 50 + "\n"
            
            interesting_text_widget = tk.Text(interesting_frame, wrap=tk.WORD, height=6)
            interesting_text_widget.insert(tk.END, interesting_text)
            interesting_text_widget.config(state=tk.DISABLED)
            interesting_text_widget.pack(fill=tk.X)
        
        # Pack canvas and scrollbar
        canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
    
    def create_vulnerabilities_tab(self):
        """Create the vulnerabilities tab."""
        vulnerabilities_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(vulnerabilities_frame, text="Vulnerabilities")
        
        # Create search frame
        search_frame = ttk.Frame(vulnerabilities_frame)
        search_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Search label
        ttk.Label(search_frame, text="Search:").pack(side=tk.LEFT, padx=(0, 5))
        
        # Search entry
        self.vuln_search_var = tk.StringVar()
        self.vuln_search_entry = ttk.Entry(search_frame, textvariable=self.vuln_search_var, width=30)
        self.vuln_search_entry.pack(side=tk.LEFT, padx=(0, 5))
        
        # Search button
        ttk.Button(search_frame, text="Search", command=self.search_vulnerabilities).pack(side=tk.LEFT, padx=(0, 5))
        
        # Clear button
        ttk.Button(search_frame, text="Clear", command=self.clear_vulnerability_search).pack(side=tk.LEFT, padx=(0, 5))
        
        # Filter by severity
        ttk.Label(search_frame, text="Severity:").pack(side=tk.LEFT, padx=(20, 5))
        self.severity_filter_var = tk.StringVar(value="All")
        severity_combo = ttk.Combobox(search_frame, textvariable=self.severity_filter_var, 
                                    values=["All", "Critical", "High", "Medium", "Low"], 
                                    state="readonly", width=10)
        severity_combo.pack(side=tk.LEFT, padx=(0, 5))
        severity_combo.bind('<<ComboboxSelected>>', self.filter_vulnerabilities_by_severity)
        
        # Results count label
        self.vuln_count_label = ttk.Label(search_frame, text="")
        self.vuln_count_label.pack(side=tk.RIGHT)
        
        # Create treeview
        columns = ('Type', 'Parameter', 'Severity', 'Evidence')
        tree = ttk.Treeview(vulnerabilities_frame, columns=columns, show='headings')
        
        # Configure columns
        for col in columns:
            tree.heading(col, text=col)
            tree.column(col, width=150)
        
        tree.pack(fill=tk.BOTH, expand=True, padx=10, pady=10)
        
        # Add scrollbar
        scrollbar = ttk.Scrollbar(vulnerabilities_frame, orient=tk.VERTICAL, command=tree.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        tree.configure(yscrollcommand=scrollbar.set)
        
        # Add double-click handler for detailed view
        tree.bind('<Double-1>', self.show_vulnerability_details)
        
        # Store tree reference for the handler
        self.vuln_tree = tree
        
        # Store all vulnerabilities for filtering
        self.all_vulnerabilities = []
        
        # Populate data
        self.populate_vulnerabilities()
        
        # Update count
        self.update_vulnerability_count()
        
        # Bind Enter key to search
        self.vuln_search_entry.bind('<Return>', lambda e: self.search_vulnerabilities())
    
    def create_raw_data_tab(self):
        """Create the raw data tab."""
        raw_frame = ttk.Frame(self.notebook, padding="10")
        self.notebook.add(raw_frame, text="Raw Data")
        
        # Raw JSON data
        raw_text = json.dumps(self.results, indent=2, default=str)
        
        text_widget = tk.Text(raw_frame, wrap=tk.NONE)
        text_widget.insert(tk.END, raw_text)
        text_widget.config(state=tk.DISABLED)
        
        # Scrollbars
        y_scrollbar = ttk.Scrollbar(raw_frame, orient=tk.VERTICAL, command=text_widget.yview)
        x_scrollbar = ttk.Scrollbar(raw_frame, orient=tk.HORIZONTAL, command=text_widget.xview)
        text_widget.configure(yscrollcommand=y_scrollbar.set, xscrollcommand=x_scrollbar.set)
        
        # Grid layout
        text_widget.grid(row=0, column=0, sticky=(tk.W, tk.E, tk.N, tk.S))
        y_scrollbar.grid(row=0, column=1, sticky=(tk.N, tk.S))
        x_scrollbar.grid(row=1, column=0, sticky=(tk.W, tk.E))
        
        raw_frame.columnconfigure(0, weight=1)
        raw_frame.rowconfigure(0, weight=1)
    
    def create_footer(self, parent):
        """Create the footer section."""
        footer_frame = ttk.Frame(parent)
        footer_frame.grid(row=2, column=0, sticky=(tk.W, tk.E))
        
        # Export button
        export_button = ttk.Button(footer_frame, text="Export Results", command=self.export_results)
        export_button.pack(side=tk.RIGHT, padx=(10, 0))
        
        # Close button
        close_button = ttk.Button(footer_frame, text="Close", command=self.window.destroy)
        close_button.pack(side=tk.RIGHT)
    
    def load_results(self):
        """Load and display the results."""
        # Results are already loaded in self.results
        pass
    
    def format_dict(self, data):
        """Format dictionary data for display."""
        if not isinstance(data, dict):
            return str(data)
        
        formatted = ""
        for key, value in data.items():
            if isinstance(value, list):
                formatted += f"{key}:\n"
                for item in value:
                    formatted += f"  - {item}\n"
            elif isinstance(value, dict):
                formatted += f"{key}:\n"
                formatted += self.format_dict(value)
            else:
                formatted += f"{key}: {value}\n"
        
        return formatted
    
    def export_results(self):
        """Export results to file."""
        filename = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[
                ("JSON files", "*.json"),
                ("Text files", "*.txt"),
                ("All files", "*.*")
            ]
        )
        
        if filename:
            try:
                if filename.endswith('.json'):
                    with open(filename, 'w') as f:
                        json.dump(self.results, f, indent=2, default=str)
                else:
                    # Export as formatted text
                    with open(filename, 'w') as f:
                        f.write(self.format_results_as_text())
                
                messagebox.showinfo("Success", f"Results exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export results: {e}")
    
    def format_results_as_text(self):
        """Format results as text for export."""
        text = []
        text.append("PENETRATION TEST REPORT")
        text.append("=" * 50)
        text.append(f"Target: {self.results['scan_info']['target']}")
        text.append(f"Date: {self.results['scan_info']['start_time']}")
        text.append(f"Duration: {self.results['scan_info']['duration']}")
        text.append("")
        
        if 'summary' in self.results:
            summary = self.results['summary']
            text.append("SUMMARY:")
            text.append("-" * 20)
            text.append(f"Risk Level: {summary.get('risk_level', 'Unknown')}")
            text.append(f"Total Findings: {summary.get('total_findings', 0)}")
            text.append(f"Critical: {summary.get('critical_findings', 0)}")
            text.append(f"High: {summary.get('high_findings', 0)}")
            text.append(f"Medium: {summary.get('medium_findings', 0)}")
            text.append(f"Low: {summary.get('low_findings', 0)}")
            text.append("")
            
            if summary.get('recommendations'):
                text.append("RECOMMENDATIONS:")
                text.append("-" * 20)
                for i, rec in enumerate(summary['recommendations'], 1):
                    text.append(f"{i}. {rec}")
                text.append("")
        
        return "\n".join(text)
    
    def show_vulnerability_details(self, event):
        """Show detailed information about a vulnerability."""
        selected_items = self.vuln_tree.selection()
        if not selected_items:
            return
        
        # Get selected vulnerability (take first selected item)
        selected_item = selected_items[0]
        selected_values = self.vuln_tree.item(selected_item)['values']
        
        if len(selected_values) >= 4:
            vulnerability_type, parameter, severity, evidence = selected_values
            
            # Skip summary rows
            if vulnerability_type.startswith('SUMMARY:'):
                return
            
            # Store details for export
            self.vulnerability_type = vulnerability_type
            self.parameter = parameter
            self.severity = severity
            self.evidence = evidence
            
            # Create a new window for detailed information
            detail_window = tk.Toplevel(self.window)
            detail_window.title(f"Vulnerability Details - {vulnerability_type}")
            detail_window.geometry("600x400")
            detail_window.minsize(500, 300)
            
            # Create widgets
            self.create_vulnerability_details_widgets(detail_window, vulnerability_type, parameter, severity, evidence)
    
    def create_vulnerability_details_widgets(self, parent, vulnerability_type, parameter, severity, evidence):
        """Create widgets for displaying vulnerability details."""
        # Main container
        main_frame = ttk.Frame(parent, padding="10")
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Header
        self.create_vulnerability_header(main_frame, vulnerability_type)
        
        # Content area
        self.create_vulnerability_content_area(main_frame, vulnerability_type, parameter, severity, evidence)
        
        # Footer
        self.create_vulnerability_footer(main_frame, parent)
    
    def create_vulnerability_header(self, parent, vulnerability_type):
        """Create the header section."""
        header_frame = ttk.Frame(parent)
        header_frame.pack(fill=tk.X, pady=(0, 10))
        
        # Title
        title_label = ttk.Label(header_frame, text=f"Vulnerability Details - {vulnerability_type}", font=("Arial", 12, "bold"))
        title_label.pack(anchor=tk.W)
    
    def create_vulnerability_content_area(self, parent, vulnerability_type, parameter, severity, evidence):
        """Create the main content area."""
        # Create scrollable text area
        text_frame = ttk.Frame(parent)
        text_frame.pack(fill=tk.BOTH, expand=True, pady=(0, 10))
        
        # Text widget for details
        text_widget = tk.Text(text_frame, wrap=tk.WORD, height=15)
        text_widget.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        
        # Scrollbar
        scrollbar = ttk.Scrollbar(text_frame, orient=tk.VERTICAL, command=text_widget.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        text_widget.configure(yscrollcommand=scrollbar.set)
        
        # Populate with vulnerability details
        details_text = f"""
VULNERABILITY DETAILS
{'='*50}

Type: {vulnerability_type}
Parameter: {parameter}
Severity: {severity}
Evidence: {evidence}

{'='*50}

DETAILED ANALYSIS:
"""
        
        # Add specific details based on vulnerability type
        if vulnerability_type == "SSL/TLS Certificate":
            details_text += f"""
SSL/TLS Certificate Issue Detected

This vulnerability indicates problems with the SSL/TLS configuration:

• Certificate Error: {evidence}
• Affected Parameter: {parameter}
• Risk Level: {severity}

IMPACT:
• Potential man-in-the-middle attacks
• Data interception
• Browser security warnings
• Loss of user trust

RECOMMENDATIONS:
• Fix SSL certificate configuration
• Ensure certificate is valid and not expired
• Use strong cipher suites
• Implement proper certificate validation
"""
        
        elif vulnerability_type == "Directory Listing":
            details_text += f"""
Directory Listing Vulnerability

This critical vulnerability exposes sensitive files and directories:

• Affected URL: {parameter}
• Risk Level: {severity}
• Evidence: {evidence}

IMPACT:
• Exposure of sensitive files
• Information disclosure
• Potential data breach
• Server enumeration

RECOMMENDATIONS:
• Disable directory listing immediately
• Configure proper access controls
• Remove or protect sensitive files
• Implement proper file permissions
"""
        
        elif vulnerability_type == "Backup File":
            details_text += f"""
Backup File Found

A backup file was discovered that may contain sensitive information:

• File URL: {parameter}
• Risk Level: {severity}
• Evidence: {evidence}

IMPACT:
• Source code exposure
• Configuration disclosure
• Database credentials exposure
• Application logic revelation

RECOMMENDATIONS:
• Remove all backup files immediately
• Implement proper backup procedures
• Use version control instead of backup files
• Secure file upload restrictions
"""
        
        elif vulnerability_type == "SQL Injection":
            details_text += f"""
SQL Injection Vulnerability

A SQL injection vulnerability was detected:

• Parameter: {parameter}
• Risk Level: {severity}
• Evidence: {evidence}

IMPACT:
• Unauthorized database access
• Data theft or manipulation
• Authentication bypass
• Complete system compromise

RECOMMENDATIONS:
• Use parameterized queries
• Implement input validation
• Apply principle of least privilege
• Use ORM frameworks
• Regular security testing
"""
        
        else:
            details_text += f"""
General Security Issue

A security vulnerability was detected:

• Type: {vulnerability_type}
• Parameter: {parameter}
• Risk Level: {severity}
• Evidence: {evidence}

IMPACT:
• Potential security breach
• Information disclosure
• System compromise

RECOMMENDATIONS:
• Investigate and fix the issue
• Implement proper security controls
• Regular security assessments
• Follow security best practices
"""
        
        # Insert the text
        text_widget.insert(tk.END, details_text)
        text_widget.config(state=tk.DISABLED)
    
    def create_vulnerability_footer(self, parent, detail_window):
        """Create the footer section."""
        footer_frame = ttk.Frame(parent)
        footer_frame.pack(fill=tk.X)
        
        # Close button
        close_button = ttk.Button(footer_frame, text="Close", command=detail_window.destroy)
        close_button.pack(side=tk.RIGHT, padx=(10, 0))
        
        # Export button
        export_button = ttk.Button(footer_frame, text="Export Details", command=self.export_vulnerability_details)
        export_button.pack(side=tk.RIGHT)
    
    def export_vulnerability_details(self):
        """Export vulnerability details to file."""
        filename = filedialog.asksaveasfilename(
            defaultextension=".txt",
            filetypes=[
                ("Text files", "*.txt"),
                ("All files", "*.*")
            ]
        )
        
        if filename:
            try:
                with open(filename, 'w') as f:
                    f.write(self.format_vulnerability_details())
                
                messagebox.showinfo("Success", f"Vulnerability details exported to {filename}")
            except Exception as e:
                messagebox.showerror("Error", f"Failed to export vulnerability details: {e}")
    
    def format_vulnerability_details(self):
        """Format vulnerability details for export."""
        text = []
        text.append("VULNERABILITY DETAILS")
        text.append("=" * 50)
        text.append(f"Type: {self.vulnerability_type}")
        text.append(f"Parameter: {self.parameter}")
        text.append(f"Severity: {self.severity}")
        text.append(f"Evidence: {self.evidence}")
        text.append("")
        
        return "\n".join(text)

    def populate_vulnerabilities(self):
        """Populate the vulnerabilities treeview with data."""
        self.all_vulnerabilities = []
        total_vulns = 0
        
        # 1. SSL/TLS Issues from Domain Info
        if 'domain_info' in self.results:
            domain_info = self.results['domain_info']
            ssl_info = domain_info.get('ssl_info', {})
            
            if 'error' in ssl_info:
                vuln_data = ('SSL/TLS Certificate', 'HTTPS Connection', 'High', f"SSL Error: {ssl_info['error']}")
                self.all_vulnerabilities.append(vuln_data)
                self.vuln_tree.insert('', tk.END, values=vuln_data)
                total_vulns += 1
            
            # Check for other SSL/TLS issues
            if ssl_info.get('certificate_expired'):
                vuln_data = ('SSL/TLS Certificate', 'Certificate Validity', 'High', 'Certificate has expired')
                self.all_vulnerabilities.append(vuln_data)
                self.vuln_tree.insert('', tk.END, values=vuln_data)
                total_vulns += 1
            
            if ssl_info.get('weak_ciphers'):
                vuln_data = ('SSL/TLS Configuration', 'Cipher Suites', 'Medium', 'Weak cipher suites detected')
                self.all_vulnerabilities.append(vuln_data)
                self.vuln_tree.insert('', tk.END, values=vuln_data)
                total_vulns += 1
        
        # 2. Directory Enumeration Issues
        if 'directory_enum' in self.results:
            dir_enum = self.results['directory_enum']
            
            # Directory listing vulnerabilities
            directories = dir_enum.get('directories', [])
            for directory in directories:
                if directory.get('directory_listing'):
                    vuln_data = ('Directory Listing', directory.get('url', ''), 'Critical', 'Directory listing enabled - sensitive files exposed')
                    self.all_vulnerabilities.append(vuln_data)
                    self.vuln_tree.insert('', tk.END, values=vuln_data)
                    total_vulns += 1
            
            # Backup files
            backup_files = dir_enum.get('backup_files', [])
            for backup_file in backup_files:
                vuln_data = ('Backup File', backup_file.get('url', ''), 'High', 'Backup file found - may contain sensitive information')
                self.all_vulnerabilities.append(vuln_data)
                self.vuln_tree.insert('', tk.END, values=vuln_data)
                total_vulns += 1
            
            # Interesting findings
            interesting_findings = dir_enum.get('interesting_findings', [])
            for finding in interesting_findings:
                vuln_data = ('Sensitive File', finding.get('url', ''), 'Medium', finding.get('description', 'Potentially sensitive file found'))
                self.all_vulnerabilities.append(vuln_data)
                self.vuln_tree.insert('', tk.END, values=vuln_data)
                total_vulns += 1
        
        # 3. Traditional Vulnerabilities (SQL Injection, XSS, etc.)
        vulnerabilities = self.results.get('vulnerabilities', {})
        
        # Handle vulnerability scanner structure
        if isinstance(vulnerabilities, dict):
            # SQL Injection vulnerabilities
            sql_injection = vulnerabilities.get('sql_injection', {})
            if isinstance(sql_injection, dict) and 'vulnerabilities' in sql_injection:
                sql_vulns = sql_injection['vulnerabilities']
                total_vulns += len(sql_vulns)
                
                for vuln in sql_vulns:
                    vuln_data = (
                        'SQL Injection',
                        vuln.get('parameter', ''),
                        vuln.get('severity', ''),
                        vuln.get('evidence', '')[:50] + '...' if len(vuln.get('evidence', '')) > 50 else vuln.get('evidence', '')
                    )
                    self.all_vulnerabilities.append(vuln_data)
                    self.vuln_tree.insert('', tk.END, values=vuln_data)
            
            # XSS vulnerabilities (when implemented)
            xss = vulnerabilities.get('xss', {})
            if isinstance(xss, dict) and 'vulnerabilities' in xss:
                xss_vulns = xss['vulnerabilities']
                total_vulns += len(xss_vulns)
                
                for vuln in xss_vulns:
                    vuln_data = (
                        'XSS',
                        vuln.get('parameter', ''),
                        vuln.get('severity', ''),
                        vuln.get('evidence', '')[:50] + '...' if len(vuln.get('evidence', '')) > 50 else vuln.get('evidence', '')
                    )
                    self.all_vulnerabilities.append(vuln_data)
                    self.vuln_tree.insert('', tk.END, values=vuln_data)
            
            # CSRF vulnerabilities (when implemented)
            csrf = vulnerabilities.get('csrf', {})
            if isinstance(csrf, dict) and 'vulnerabilities' in csrf:
                csrf_vulns = csrf['vulnerabilities']
                total_vulns += len(csrf_vulns)
                
                for vuln in csrf_vulns:
                    vuln_data = (
                        'CSRF',
                        vuln.get('parameter', ''),
                        vuln.get('severity', ''),
                        vuln.get('evidence', '')[:50] + '...' if len(vuln.get('evidence', '')) > 50 else vuln.get('evidence', '')
                    )
                    self.all_vulnerabilities.append(vuln_data)
                    self.vuln_tree.insert('', tk.END, values=vuln_data)
            
            # LFI vulnerabilities (when implemented)
            lfi = vulnerabilities.get('lfi', {})
            if isinstance(lfi, dict) and 'vulnerabilities' in lfi:
                lfi_vulns = lfi['vulnerabilities']
                total_vulns += len(lfi_vulns)
                
                for vuln in lfi_vulns:
                    vuln_data = (
                        'LFI',
                        vuln.get('parameter', ''),
                        vuln.get('severity', ''),
                        vuln.get('evidence', '')[:50] + '...' if len(vuln.get('evidence', '')) > 50 else vuln.get('evidence', '')
                    )
                    self.all_vulnerabilities.append(vuln_data)
                    self.vuln_tree.insert('', tk.END, values=vuln_data)
            
            # Open Redirect vulnerabilities (when implemented)
            open_redirect = vulnerabilities.get('open_redirect', {})
            if isinstance(open_redirect, dict) and 'vulnerabilities' in open_redirect:
                redirect_vulns = open_redirect['vulnerabilities']
                total_vulns += len(redirect_vulns)
                
                for vuln in redirect_vulns:
                    vuln_data = (
                        'Open Redirect',
                        vuln.get('parameter', ''),
                        vuln.get('severity', ''),
                        vuln.get('evidence', '')[:50] + '...' if len(vuln.get('evidence', '')) > 50 else vuln.get('evidence', '')
                    )
                    self.all_vulnerabilities.append(vuln_data)
                    self.vuln_tree.insert('', tk.END, values=vuln_data)
        
        # 4. Information Disclosure Issues
        if 'domain_info' in self.results:
            domain_info = self.results['domain_info']
            
            # Subdomain enumeration
            subdomains = domain_info.get('subdomains', [])
            if subdomains:
                vuln_data = ('Information Disclosure', 'Subdomains', 'Medium', f"{len(subdomains)} subdomains discovered")
                self.all_vulnerabilities.append(vuln_data)
                self.vuln_tree.insert('', tk.END, values=vuln_data)
                total_vulns += 1
            
            # Technology detection
            tech_info = domain_info.get('technology_info', {})
            if tech_info:
                vuln_data = ('Information Disclosure', 'Technologies', 'Low', 'Technology stack information exposed')
                self.all_vulnerabilities.append(vuln_data)
                self.vuln_tree.insert('', tk.END, values=vuln_data)
                total_vulns += 1
        
        # Show summary
        if total_vulns == 0:
            self.vuln_tree.insert('', tk.END, values=('No vulnerabilities found', '', '', ''))
        else:
            # Add summary row
            summary = self.results.get('summary', {})
            summary_data = (
                f"SUMMARY: {total_vulns} security issues found",
                f"Critical: {summary.get('critical_findings', 0)}",
                f"High: {summary.get('high_findings', 0)}",
                f"Medium: {summary.get('medium_findings', 0)}"
            )
            self.all_vulnerabilities.append(summary_data)
            self.vuln_tree.insert('', tk.END, values=summary_data)

    def update_vulnerability_count(self):
        """Update the vulnerability count label."""
        visible_count = len(self.vuln_tree.get_children())
        total_count = len(self.all_vulnerabilities)
        
        if visible_count == total_count:
            self.vuln_count_label.config(text=f"Showing {visible_count} vulnerabilities")
        else:
            self.vuln_count_label.config(text=f"Showing {visible_count} of {total_count} vulnerabilities")

    def search_vulnerabilities(self):
        """Search for vulnerabilities based on the search term."""
        search_term = self.vuln_search_var.get().lower()
        severity_filter = self.severity_filter_var.get()
        
        # Clear current display
        for item in self.vuln_tree.get_children():
            self.vuln_tree.delete(item)
        
        # Filter vulnerabilities
        filtered_vulns = []
        for vuln in self.all_vulnerabilities:
            vuln_type, parameter, severity, evidence = vuln
            
            # Skip summary rows
            if vuln_type.startswith('SUMMARY:'):
                continue
            
            # Apply severity filter
            if severity_filter != "All" and severity != severity_filter:
                continue
            
            # Apply search filter
            if search_term:
                if (search_term in vuln_type.lower() or 
                    search_term in parameter.lower() or 
                    search_term in severity.lower() or 
                    search_term in evidence.lower()):
                    filtered_vulns.append(vuln)
            else:
                filtered_vulns.append(vuln)
        
        # Display filtered results
        for vuln in filtered_vulns:
            self.vuln_tree.insert('', tk.END, values=vuln)
        
        # Update count
        self.update_vulnerability_count()

    def clear_vulnerability_search(self):
        """Clear the vulnerability search term."""
        self.vuln_search_var.set("")
        self.severity_filter_var.set("All")
        self.search_vulnerabilities()

    def filter_vulnerabilities_by_severity(self, event):
        """Filter vulnerabilities based on the selected severity."""
        self.search_vulnerabilities() 