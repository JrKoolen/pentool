# Web Penetration Testing Tool

A comprehensive web penetration testing tool with information gathering, directory enumeration, and vulnerability scanning capabilities.

## Features

- **Information Gathering**: WHOIS, DNS records, subdomain enumeration, port scanning
- **Directory Enumeration**: File and directory discovery, backup file detection
- **Vulnerability Scanning**: SQL injection, XSS, CSRF detection
- **GUI Interface**: User-friendly tkinter-based interface
- **Report Generation**: JSON and text report formats
- **Real-time Monitoring**: Live scan progress and results

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd bored
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### GUI Mode
```bash
python gui_main.py
```

### Command Line Mode
```bash
# Full scan
python main.py http://example.com

# Specific modules
python main.py http://example.com --modules domain_info directory_enum

# Vulnerability scan only
python main.py http://example.com --modules vulnerabilities
```

## Project Structure

```
bored/
├── src/
│   ├── core/           # Core scanning engine
│   ├── gui/            # GUI components
│   └── modules/        # Scanning modules
├── results/            # Scan results
├── config.json         # Configuration file
├── requirements.txt    # Python dependencies
└── README.md          # This file
```

## Configuration

Edit `config.json` to customize:
- Scanning timeouts
- Thread limits
- Wordlists
- API keys

## Security Notice

⚠️ **This tool is for authorized penetration testing only.**
- Only test systems you own or have explicit permission to test
- Respect rate limits and terms of service
- Follow responsible disclosure practices

## License

This project is for educational purposes. Use responsibly.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request

## Disclaimer

This tool is provided as-is for educational and authorized testing purposes. The authors are not responsible for any misuse or damage caused by this software. 