# Web Penetration Testing Tool Launcher (PowerShell)
Write-Host "Starting Local Testing Environment..." -ForegroundColor Green
Write-Host ""

# Check if PHP is installed
try {
    $phpVersion = php --version 2>$null
    if ($LASTEXITCODE -ne 0) {
        throw "PHP not found"
    }
    Write-Host "PHP found: $($phpVersion[0])" -ForegroundColor Green
} catch {
    Write-Host "ERROR: PHP is not installed or not in PATH" -ForegroundColor Red
    Write-Host "Please install PHP from https://www.php.net/downloads" -ForegroundColor Yellow
    Write-Host ""
    Read-Host "Press Enter to exit"
    exit 1
}

# Start the PHP server in background
Write-Host "Starting PHP server..." -ForegroundColor Yellow
$phpJob = Start-Job -ScriptBlock {
    Set-Location $using:PWD
    python serve_php_local.py
}

# Wait a moment for server to start
Start-Sleep -Seconds 3

# Start the GUI
Write-Host "Starting GUI..." -ForegroundColor Yellow
python gui_main.py

# Clean up
if ($phpJob) {
    Stop-Job $phpJob
    Remove-Job $phpJob
}

Write-Host ""
Write-Host "Testing environment started!" -ForegroundColor Green
Write-Host "Server: http://localhost:8080" -ForegroundColor Cyan
Write-Host "GUI: Running" -ForegroundColor Cyan
Write-Host ""
Read-Host "Press Enter to exit" 