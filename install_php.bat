@echo off
echo ========================================
echo   PHP Installation Script for Windows
echo ========================================
echo.

REM Check if PHP is already installed
php --version >nul 2>&1
if not errorlevel 1 (
    echo PHP is already installed!
    php --version
    echo.
    pause
    exit /b 0
)

echo Downloading PHP for Windows...
echo.

REM Create php directory in current folder
if not exist "php" mkdir php
cd php

REM Download PHP (using PowerShell to download)
echo Downloading PHP 8.3 Thread Safe...
powershell -Command "& {Invoke-WebRequest -Uri 'https://windows.php.net/downloads/releases/php-8.3.12-Win32-vs16-x64.zip' -OutFile 'php.zip'}"

if errorlevel 1 (
    echo Failed to download PHP!
    echo Trying alternative download method...
    powershell -Command "& {[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12; Invoke-WebRequest -Uri 'https://windows.php.net/downloads/releases/php-8.3.12-Win32-vs16-x64.zip' -OutFile 'php.zip'}"
    
    if errorlevel 1 (
        echo Still failed to download PHP!
        echo Please download manually from: https://www.php.net/downloads
        echo Look for "VS16 x64 Thread Safe" version
        pause
        exit /b 1
    )
)

echo Extracting PHP...
powershell -Command "& {Expand-Archive -Path 'php.zip' -DestinationPath '.' -Force}"

REM Clean up zip file
del php.zip

REM Copy php.ini-development to php.ini
if exist "php.ini-development" (
    copy "php.ini-development" "php.ini"
    echo Created php.ini from development template
)

echo.
echo PHP installation completed!
echo PHP is now available in the 'php' folder
echo.

REM Add current directory to PATH for this session
set PATH=%CD%;%PATH%

echo Testing PHP installation...
php --version

if errorlevel 1 (
    echo.
    echo To use PHP, you need to:
    echo 1. Add %CD% to your system PATH, OR
    echo 2. Run: set PATH=%CD%;%%PATH%%
    echo 3. Or use the full path: %CD%\php.exe
    echo.
) else (
    echo.
    echo PHP is working! You can now run start_testing.bat
    echo.
)

cd ..
pause 