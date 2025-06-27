# Quick Start Guide - Web Penetration Testing Tool

## 🚀 Getting Started

### Prerequisites
- Python 3.8 or higher
- pip (Python package installer)
- Internet connection for downloading dependencies

### Installation

1. **Clone or download the project**
   ```bash
   # If you have git
   git clone <repository-url>
   cd bored
   
   # Or download and extract the ZIP file
   ```

2. **Install dependencies**
   ```bash
   pip install -r requirements.txt
   ```

3. **Test the installation**
   ```bash
   python test_tool.py
   ```

### Basic Usage

#### 1. Simple Scan
```bash
python main.py example.com
```
This runs a full scan with default settings.

#### 2. Specific Modules
```bash
python main.py example.com --modules reconnaissance
```
Only run the reconnaissance module.

#### 3. Verbose Output
```bash
python main.py example.com --verbose
```
Get detailed output during scanning.

#### 4. Custom Configuration
```bash
python main.py example.com --threads 20 --timeout 30
```
Use 20 threads and 30-second timeout.

## 📋 What the Tool Does

### Information Gathering (Reconnaissance)
- **Domain Information**: WHOIS, DNS records, IP addresses
- **Subdomain Discovery**: Find subdomains using wordlists
- **Port Scanning**: Check for open ports and services
- **Technology Detection**: Identify web servers, frameworks, CMS
- **SSL/TLS Analysis**: Certificate information and security

### Directory & File Discovery
- **Common Files**: robots.txt, sitemap.xml, security.txt
- **Directory Enumeration**: Find hidden directories
- **Backup Files**: Detect backup and temporary files
- **Hidden Items**: Configuration files, version control
- **Directory Listing**: Check for enabled directory browsing

### Risk Assessment
- **Security Headers**: Analyze security configurations
- **Information Disclosure**: Find sensitive information
- **Risk Scoring**: Categorize findings by severity
- **Recommendations**: Provide remediation advice

## 📊 Understanding Output

### Console Output
The tool provides real-time feedback with colored output:
- 🔵 **Blue**: Information messages
- 🟢 **Green**: Success messages
- 🟡 **Yellow**: Warnings
- 🔴 **Red**: Errors

### Report Files
Results are saved in the `results/` directory:
- `domain_info_*.json`: Domain reconnaissance results
- `directory_enum_*.json`: Directory enumeration results
- `pentest_scan_*.json`: Complete scan results

### Summary Report
After each scan, you'll see a summary like:
```
============================================================
           PENETRATION TEST SCAN SUMMARY
============================================================
Target: https://example.com
Scan Duration: 0:02:15
Overall Risk Level: MEDIUM
------------------------------------------------------------
FINDINGS BREAKDOWN:
  Critical: 0
  High: 2
  Medium: 5
  Low: 12
  Total: 19
------------------------------------------------------------
RECOMMENDATIONS:
  1. Backup files found - remove them immediately
  2. Hidden files/directories found - review for sensitive information
============================================================
```

## ⚙️ Configuration

### Basic Configuration
Edit `config.json` to customize settings:
```json
{
  "scanning": {
    "timeout": 10,
    "max_threads": 10,
    "user_agent": "Mozilla/5.0..."
  },
  "reconnaissance": {
    "common_ports": [80, 443, 8080, 8443],
    "max_subdomains": 1000
  }
}
```

### Wordlists
Customize wordlists in the configuration:
- **Subdomains**: Common subdomain names
- **Directories**: Common directory names
- **Files**: Common file names

## 🔧 Advanced Usage

### Command Line Options
```bash
python main.py --help
```

Available options:
- `--modules`: Choose which modules to run
- `--threads`: Number of concurrent threads
- `--timeout`: Request timeout in seconds
- `--output`: Report format (json/txt)
- `--verbose`: Detailed output
- `--no-delay`: Disable rate limiting (not recommended)

### Examples

#### Quick Reconnaissance
```bash
python main.py example.com --modules reconnaissance --threads 5
```

#### Comprehensive Scan
```bash
python main.py example.com --verbose --threads 20 --timeout 30
```

#### Generate Text Report
```bash
python main.py example.com --output txt
```

## 🛡️ Security Best Practices

### Legal Considerations
- **Always get permission** before testing any website
- **Respect rate limits** to avoid being blocked
- **Follow responsible disclosure** if you find vulnerabilities
- **Comply with local laws** and regulations

### Safe Testing
- Use test environments when possible
- Start with low-thread counts
- Monitor target server responses
- Document your testing activities

### Rate Limiting
The tool includes built-in rate limiting:
- Random delays between requests
- Configurable thread limits
- Respect for robots.txt files

## 🐛 Troubleshooting

### Common Issues

#### Import Errors
```bash
# Make sure you're in the project directory
cd /path/to/bored

# Install dependencies
pip install -r requirements.txt

# Run test script
python test_tool.py
```

#### Permission Errors
```bash
# On Linux/Mac, make the script executable
chmod +x main.py

# Or run with python explicitly
python main.py example.com
```

#### Network Issues
- Check your internet connection
- Verify the target domain is accessible
- Try with a different target for testing

#### Slow Performance
- Reduce thread count: `--threads 5`
- Increase timeout: `--timeout 30`
- Use specific modules only

### Getting Help

1. **Check the logs**: Look for error messages in the console
2. **Run tests**: `python test_tool.py`
3. **Try verbose mode**: `python main.py example.com --verbose`
4. **Check documentation**: Read the full README.md

## 📈 Next Steps

### For Beginners
1. Start with simple scans on test domains
2. Learn to interpret the results
3. Practice with different modules
4. Read about web security concepts

### For Advanced Users
1. Customize wordlists and configurations
2. Integrate with other security tools
3. Develop custom modules
4. Contribute to the project

### Learning Resources
- OWASP Top 10
- Web Application Security Testing
- Network Security Fundamentals
- Python Security Programming

## 🎯 Example Workflow

### 1. Initial Assessment
```bash
python main.py target.com --modules reconnaissance
```

### 2. Deep Discovery
```bash
python main.py target.com --modules discovery --verbose
```

### 3. Analysis
- Review the generated reports
- Check for high-risk findings
- Document your findings
- Plan remediation steps

### 4. Reporting
- Generate executive summary
- Create technical report
- Provide remediation recommendations
- Follow up on critical issues

---

**Remember**: This tool is for authorized security testing only. Always ensure you have proper permission before testing any website or application. 

# Custom configuration
python main.py example.com --threads 20 --timeout 30

# Generate text report
python main.py example.com --output txt

# Only reconnaissance
python main.py example.com --modules reconnaissance 