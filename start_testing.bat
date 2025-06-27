@echo off
setlocal enabledelayedexpansion
echo Starting Local Testing Environment...
echo.

REM Check if PHP is installed (local or system)
php --version >nul 2>&1
if errorlevel 1 (
    REM Check for local PHP installation
    if exist "php\php.exe" (
        echo Found local PHP installation
        set "PATH=%CD%\php;%PATH%"
    ) else (
        echo PHP not found. Installing PHP locally...
        call install_php.bat
        if errorlevel 1 (
            echo Failed to install PHP!
            echo Using Python server instead...
            goto :use_python_server
        )
        REM Add local PHP to PATH
        set "PATH=%CD%\php;%PATH%"
    )
)

REM Start the PHP server in the background
echo Starting PHP server...
start "PHP Server" cmd /c "python serve_php_local.py"
goto :start_gui

:use_python_server
echo Starting Python server (PHP not available)...
start "Python Server" cmd /c "python serve_local.py"

:start_gui
REM Wait a moment for server to start
timeout /t 2 /nobreak >nul

REM Start the GUI
echo Starting GUI...
python gui_main.py

echo.
echo Testing environment started!
echo Server: http://localhost:8080
echo GUI: Running
echo.
pause 