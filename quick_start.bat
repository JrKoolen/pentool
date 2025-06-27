@echo off
echo Starting Quick Testing Environment...
echo.

REM Start the Python server in the background
echo Starting Python server...
start "Python Server" cmd /c "python serve_local.py"

REM Wait a moment for server to start
timeout /t 2 /nobreak >nul

REM Start the GUI
echo Starting GUI...
python gui_main.py

echo.
echo Quick testing environment started!
echo Server: http://localhost:8080
echo GUI: Running
echo Note: PHP files will be served as static files
echo.
pause 