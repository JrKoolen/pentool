# Local Testing Guide

This guide explains how to download websites and test them locally using your penetration testing tool.

## Quick Start

### Option 1: Use the Launcher Script (Recommended)
```bash
# Windows Batch File
start_testing.bat

# PowerShell Script
.\start_testing.ps1
```

This will:
1. Download testphp.vulnweb.com if not already downloaded
2. Start a local web server on port 8080
3. Launch the GUI application
4. You can then test against `http://localhost:8080`

### Option 2: Manual Steps

#### Step 1: Download a Website
```bash
python download_site.py
```

This downloads testphp.vulnweb.com by default. To download a different site, edit the `url` variable in `download_site.py`.

#### Step 2: Start Local Server
```bash
python serve_local.py
```

The server will run on `http://localhost:8080`

#### Step 3: Launch GUI
```bash
python gui_main.py
```

## Available Test Sites

### Built-in Test Sites
- **testphp.vulnweb.com** - Acunetix vulnerable test site
- **demo.testfire.net** - IBM vulnerable test site

### Downloading Custom Sites

Edit `download_site.py` and change the URL:
```python
def main():
    url = "http://your-target-site.com"  # Change this
    downloader = WebsiteDownloader(url)
    downloader.download_site(max_depth=2)
```

## Testing Workflow

1. **Download a site** using `download_site.py`
2. **Start the local server** using `serve_local.py`
3. **Launch the GUI** using `gui_main.py`
4. **Enter the local URL** in the GUI: `http://localhost:8080`
5. **Run your scans** - directory enumeration, SQL injection, etc.

## File Structure

```
local_test_site/
├── testphp.vulnweb.com/
│   ├── index.html
│   ├── login.php
│   ├── artists.php
│   ├── images/
│   └── ...
└── your-site.com/
    └── ...
```

## Security Benefits

### Legal Testing
- **No legal issues** - you own the local copy
- **No network impact** - everything runs locally
- **Safe experimentation** - can't damage real systems

### Development Benefits
- **Faster testing** - no network delays
- **Offline work** - no internet required
- **Version control** - can modify files safely

## Troubleshooting

### Port 8080 Already in Use
Change the port in `serve_local.py`:
```python
PORT = 8081  # Change to any available port
```

### Download Fails
- Check internet connection
- Verify the target site is accessible
- Try a different site

### GUI Won't Start
- Ensure all dependencies are installed: `pip install -r requirements.txt`
- Check Python version (3.7+ required)

## Advanced Usage

### Custom Download Scripts
Create your own downloader for specific sites:
```python
from download_site import WebsiteDownloader

# Download multiple sites
sites = [
    "http://testphp.vulnweb.com",
    "http://demo.testfire.net"
]

for site in sites:
    downloader = WebsiteDownloader(site, f"local_test_site/{site.split('//')[1]}")
    downloader.download_site(max_depth=3)
```

### Modifying Downloaded Sites
You can edit the downloaded files to create custom test scenarios:
- Add new vulnerabilities
- Modify existing forms
- Create test data

## Best Practices

1. **Always test locally first** before testing live sites
2. **Keep downloaded sites updated** for realistic testing
3. **Document your findings** in the GUI results
4. **Use different test sites** to practice various vulnerabilities
5. **Never test production sites** without permission 