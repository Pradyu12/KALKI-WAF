#!/bin/bash
# Build KALKI for local deployment
# Produces two standalone executables: KALKI-Server + KALKI-Desktop
# Usage: bash build-local.sh

set -e
cd "$(dirname "$0")"

echo "==> Installing build dependencies..."
pip3 install pyinstaller pillow requests sseclient-py --quiet

# ── 1. Build the backend server ──
echo ""
echo "==> Building KALKI-Server..."
mkdir -p /tmp/kalki_build

pyinstaller --onefile \
  --name "KALKI-Server" \
  --add-data "$(pwd)/dashboard:dashboard" \
  --add-data "$(pwd)/api/waf:waf" \
  --hidden-import uvicorn \
  --hidden-import uvicorn.logging \
  --hidden-import uvicorn.loops.auto \
  --hidden-import uvicorn.protocols.http.auto \
  --hidden-import fastapi \
  --hidden-import pydantic \
  --hidden-import httpx \
  --hidden-import psutil \
  --hidden-import prometheus_client \
  --hidden-import websockets \
  --hidden-import python_multipart \
  --hidden-import cryptography \
  --hidden-import jwt \
  --hidden-import aiofiles \
  --collect-all waf \
  --distpath dist \
  --workpath /tmp/kalki_build \
  --specpath /tmp/kalki_build \
  --noconfirm \
  api/main.py 2>&1 | tail -5

# Verify build
if [ ! -f "dist/KALKI-Server" ]; then
    echo "[!] Server binary not built — use kalki.py start instead"
fi

# ── 2. Build the desktop app ──
echo ""
echo "==> Building KALKI-Desktop..."
pyinstaller --onefile --windowed \
  --name "KALKI-Desktop" \
  --add-data "$(pwd)/dashboard/kalki_waf_logo.png:." \
  --hidden-import PIL \
  --collect-all PIL \
  --distpath dist \
  --workpath /tmp/kalki_build \
  --specpath /tmp/kalki_build \
  --noconfirm \
  kalki-desktop.py 2>&1 | tail -5

# ── Done ──
echo ""
echo "==> Build complete!"
ls -lh dist/KALKI-Desktop dist/KALKI-Server 2>/dev/null || ls -lh dist/KALKI-Desktop
echo ""
echo "Quick start:  python3 kalki.py"
echo "Server only:  dist/KALKI-Server &"
echo "Desktop only: dist/KALKI-Desktop --server http://127.0.0.1:8080"
echo "Full stack:   python3 kalki.py start"
