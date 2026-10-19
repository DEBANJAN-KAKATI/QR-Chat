@echo off
title CipherDrop // Private QR Chat Server
color 0B
cd /d "%~dp0"

echo =================================================================
echo   [+] CipherDrop - anonymous, self-destructing QR chat
echo   [+] E2EE - RAM only - Wi-Fi / Hotspot / Bluetooth PAN
echo =================================================================
echo.

python -m pip install -r requirements.txt --quiet --disable-pip-version-check
if %ERRORLEVEL% NEQ 0 (
    echo [!] pip reported a problem, trying to start anyway...
)

echo [*] Starting server... (first time: allow Python through Windows Firewall on Private networks)
python app.py
pause
