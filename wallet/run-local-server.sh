#!/bin/bash
# Startup script to run the Sovereign Wallet locally over HTTP.
# Runs in the foreground so Ctrl+C cleans up the socket instantly.

PORT=8080
echo "🚀 Starting local HTTP server on port $PORT..."

# Open default browser shortly after server starts
(sleep 1.5 && (xdg-open "http://localhost:$PORT" || open "http://localhost:$PORT" || echo "Please open http://localhost:$PORT")) &

# Run in the foreground using our cache-disabled python server
python3 server.py
