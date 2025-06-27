# Web Penetration Testing Tool - GUI Version

A modern, user-friendly graphical interface for the Web Penetration Testing Tool with advanced information gathering and vulnerability assessment capabilities.

## 🚀 Quick Start

### Installation

1. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

2. **Launch the GUI**
   ```bash
   python gui_main.py
   ```

### First Run

1. **Enter a target URL** in the quick scan section
2. **Click "Start Scan"** to begin reconnaissance
3. **View results** in the scan management section
4. **Export reports** as needed

## 🖥️ GUI Features

### Main Dashboard

The main window provides a comprehensive overview with:

- **Quick Scan Section**: Fast scanning with default settings
- **Scan Management**: Monitor and control active scans
- **Results Viewer**: Review and export scan findings
- **Status Bar**: Real-time feedback and progress

### Quick Scan

The quick scan section allows you to:
- Enter a target URL (domain or full URL)
- Start scanning immediately with default settings
- View real-time progress
- Access advanced scan configuration

### Advanced Scan Configuration

Click "Advanced Scan" to access detailed settings:

#### Target Configuration
- **Target URL**: Enter the website to scan
- **Real-time validation**: URL format checking
- **Protocol detection**: Automatic HTTP/HTTPS handling

#### Scan Modules
- **Information Gathering**: Domain info, DNS, subdomains, ports
- **Directory & File Discovery**: Directory enumeration, backup files
- **Vulnerability Scanning**: SQL injection, XSS, CSRF (Coming Soon)

#### Scan Options
- **Threads**: Number of concurrent requests (1-50)
- **Timeout**: Request timeout in seconds (5-60)
- **Verbose Output**: Detailed logging
- **Rate Limiting**: Respectful scanning (recommended)

### Scan Management

The scan management section provides:

#### Active Scans
- **Real-time status**: Running, Completed, Failed
- **Progress tracking**: Start time, duration
- **Risk assessment**: Automatic risk level calculation
- **Context menu**: Right-click for additional options

#### Scan Controls
- **Refresh**: Update scan list
- **Clear Completed**: Remove finished scans
- **Export All**: Save all results
- **Stop All**: Cancel running scans

### Results Viewer

Double-click any scan or result to view detailed findings:

#### Summary Tab
- **Risk Level**: Overall security assessment
- **Findings Breakdown**: Critical, High, Medium, Low
- **Recommendations**: Remediation suggestions

#### Domain Info Tab
- **WHOIS Information**: Domain registration details
- **DNS Records**: A, AAAA, MX, NS, TXT records
- **IP Information**: IPv4/IPv6 addresses
- **Open Ports**: Discovered services
- **Technologies**: Web servers, frameworks, CMS

#### Directory Enum Tab
- **Directories Found**: Discovered directories
- **Files Found**: Common files (robots.txt, etc.)
- **Backup Files**: High-risk backup files
- **Interesting Findings**: Hidden files and configurations

#### Raw Data Tab
- **JSON Export**: Complete scan data
- **Searchable**: Find specific information
- **Exportable**: Save in various formats

### Settings Configuration

Access settings via Tools → Settings:

#### Scanning Settings
- **Request Timeout**: Connection timeout
- **Maximum Threads**: Concurrent connections
- **User Agent**: Custom browser identification
- **SSL Verification**: Certificate validation
- **Follow Redirects**: Handle HTTP redirects

#### Reporting Settings
- **Output Directory**: Where to save reports
- **Include Timestamps**: Add timestamps to reports
- **Report Formats**: JSON, TXT, HTML (Coming Soon)

#### API Keys
- **Shodan**: Enhanced reconnaissance
- **Censys**: Internet-wide scanning
- **VirusTotal**: Threat intelligence

## 📊 Understanding Results

### Risk Levels

- **Critical**: Immediate action required (e.g., directory listing)
- **High**: Significant security issues (e.g., backup files)
- **Medium**: Moderate concerns (e.g., subdomains)
- **Low**: Minor findings (e.g., open ports)

### Common Findings

#### Information Disclosure
- **Directory Listing**: Exposed file listings
- **Backup Files**: Configuration backups
- **Hidden Files**: Configuration files
- **Error Messages**: Detailed error information

#### Configuration Issues
- **Missing Security Headers**: X-Frame-Options, CSP
- **SSL/TLS Issues**: Certificate problems
- **Server Information**: Version disclosure

#### Technology Stack
- **Web Servers**: Apache, Nginx, IIS
- **Frameworks**: WordPress, Django, Laravel
- **Programming Languages**: PHP, Python, Node.js

## 🔧 Advanced Features

### Batch Scanning

Coming soon - scan multiple targets simultaneously:

1. **Import target list** from file
2. **Configure scan settings** for all targets
3. **Monitor progress** across all scans
4. **Export consolidated results**

### Custom Wordlists

Coming soon - customize enumeration wordlists:

1. **Edit subdomain wordlists**
2. **Modify directory wordlists**
3. **Add custom file extensions**
4. **Import/export wordlists**

### Integration

Coming soon - integrate with other tools:

1. **Burp Suite**: Import/export results
2. **OWASP ZAP**: Share findings
3. **Metasploit**: Vulnerability exploitation
4. **Custom APIs**: External integrations

## 🛡️ Security Best Practices

### Legal Considerations

- **Always obtain permission** before testing any website
- **Respect rate limits** to avoid being blocked
- **Follow responsible disclosure** if you find vulnerabilities
- **Comply with local laws** and regulations

### Safe Testing

- **Use test environments** when possible
- **Start with low thread counts** to avoid overwhelming servers
- **Monitor target responses** for rate limiting
- **Document all testing activities**

### Rate Limiting

The GUI includes built-in protection:

- **Random delays** between requests
- **Configurable thread limits**
- **Respect for robots.txt** files
- **Automatic backoff** on errors

## 🐛 Troubleshooting

### Common Issues

#### GUI Won't Start
```bash
# Check Python version
python --version  # Should be 3.8+

# Install dependencies
pip install -r requirements.txt

# Check for missing modules
python test_tool.py
```

#### Import Errors
```bash
# Make sure you're in the project directory
cd /path/to/bored

# Reinstall dependencies
pip install --force-reinstall -r requirements.txt
```

#### Scan Failures
- **Check internet connection**
- **Verify target is accessible**
- **Try with different target**
- **Check firewall settings**

#### Slow Performance
- **Reduce thread count** in settings
- **Increase timeout** values
- **Use specific modules** only
- **Check system resources**

### Getting Help

1. **Check the logs**: Look for error messages
2. **Run command-line version**: `python main.py --help`
3. **Test individual modules**: Use the test script
4. **Review documentation**: Read the full README

## 📈 Usage Examples

### Basic Reconnaissance

1. **Launch GUI**: `python gui_main.py`
2. **Enter target**: `example.com`
3. **Click "Start Scan"**
4. **Review results** in the scan list
5. **Double-click** to view details

### Advanced Scanning

1. **Click "Advanced Scan"**
2. **Enter target URL**
3. **Select modules**: Information Gathering + Directory Discovery
4. **Configure options**: 20 threads, 30-second timeout
5. **Start scan** and monitor progress

### Results Analysis

1. **View summary** for risk assessment
2. **Check domain info** for technology stack
3. **Review directory enum** for sensitive files
4. **Export results** for reporting
5. **Follow recommendations** for remediation

## 🎯 Workflow Examples

### Security Assessment

1. **Initial Scan**: Quick reconnaissance
2. **Deep Analysis**: Advanced scan with all modules
3. **Vulnerability Testing**: Focus on specific findings
4. **Report Generation**: Export detailed results
5. **Remediation Planning**: Follow recommendations

### Continuous Monitoring

1. **Baseline Scan**: Establish initial security posture
2. **Regular Scans**: Monitor for changes
3. **Alert System**: Notify on new findings
4. **Trend Analysis**: Track security improvements
5. **Compliance Reporting**: Generate audit reports

## 🔮 Future Features

### Planned Enhancements

- **Web-based Dashboard**: Browser-based interface
- **Real-time Monitoring**: Live security monitoring
- **Automated Remediation**: Fix common issues
- **AI-powered Analysis**: Intelligent vulnerability detection
- **Compliance Frameworks**: PCI DSS, GDPR, SOC 2

### Integration Roadmap

- **CI/CD Pipelines**: Automated security testing
- **Cloud Platforms**: AWS, Azure, GCP integration
- **Security Tools**: SIEM, EDR, WAF integration
- **APIs**: RESTful API for automation
- **Mobile App**: iOS/Android companion app

---

**Remember**: This tool is for authorized security testing only. Always ensure you have proper permission before testing any website or application.

For more information, see the main README.md file. 