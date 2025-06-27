# PHP Installation Guide for Windows

## Quick Installation (Recommended)

### Option 1: Download and Install Manually

1. **Download PHP:**
   - Go to: https://www.php.net/downloads
   - Click on "Windows downloads"
   - Download "VS16 x64 Thread Safe" version (ZIP file)

2. **Extract to your project:**
   - Create a folder called `php` in your project directory
   - Extract the ZIP contents into the `php` folder
   - You should have `php.exe` in the `php` folder

3. **Configure PHP:**
   - Copy `php.ini-development` to `php.ini`
   - Edit `php.ini` and uncomment these lines:
     ```ini
     extension=curl
     extension=mbstring
     extension=openssl
     ```

### Option 2: Use XAMPP (All-in-one)

1. **Download XAMPP:**
   - Go to: https://www.apachefriends.org/
   - Download and install XAMPP

2. **Use XAMPP's PHP:**
   - Copy `php.exe` from `C:\xampp\php\` to your project's `php\` folder
   - Or add `C:\xampp\php\` to your system PATH

### Option 3: Use Chocolatey (if installed)

```cmd
choco install php
```

## Test Installation

After installation, run:
```cmd
php --version
```

If successful, you should see PHP version information.

## Start Testing

Once PHP is installed, run:
```cmd
start_testing.bat
```

This will:
1. Start the PHP server on http://localhost:8080
2. Launch the penetration testing GUI
3. Allow you to test PHP applications properly

## Troubleshooting

### "php is not recognized"
- Make sure `php.exe` is in the `php` folder
- Or add the PHP folder to your system PATH

### "Port 8080 already in use"
- Stop any existing servers
- Or change the port in `serve_php_local.py`

### Forms still download as files
- Make sure you're using the PHP server, not the Python server
- Run `python serve_php_local.py` instead of `python serve_local.py` 