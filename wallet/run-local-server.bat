@echo off
:: Windows startup script to run the Sovereign Wallet locally over HTTP to bypass file:// browser restrictions.

echo 🚀 Starting local HTTP server on port 8080...
start http://localhost:8080

:: Try python3 first, then fallback to python, running our cache-disabled server
python3 server.py
if %errorlevel% neq 0 (
    echo Python3 not found, trying python...
    python server.py
)

if %errorlevel% neq 0 (
    echo ⚠️  Failed to start Python HTTP server. If you have Node installed, try running: npx serve
    pause
)
